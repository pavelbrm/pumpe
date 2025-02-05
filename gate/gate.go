package gate

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/pavelbrm/pumpe/model"
)

const (
	ErrKindUnknown            model.Error = "gate: unknown kind"
	ErrKindNotSupported       model.Error = "gate: unsupported kind"
	ErrNotImplemented         model.Error = "gate: not implemented"
	ErrSetIsShutting          model.Error = "gate: set is shutting"
	ErrSetIsWarmingUp         model.Error = "gate: set is warming up"
	ErrNoRandomGate           model.Error = "gate: no random gate"
	ErrGateNotFound           model.Error = "gate: gate not found"
	ErrTorMaxReached          model.Error = "gate: reached maximum number of tor gates"
	ErrWarmupBadResponse      model.Error = "gate: warmup finished with bad response"
	ErrGateNotReady           model.Error = "gate: gate not ready"
	ErrGateIsRefreshing       model.Error = "gate: gate is refreshing"
	ErrInvalidWGConfig        model.Error = "gate: invalid wireguard config"
	ErrInvalidWGKey           model.Error = "gate: invalid wireguard key"
	ErrInvalidWGIfacePvtKey   model.Error = "gate: invalid wireguard iface private key"
	ErrInvalidWGIfaceAddr     model.Error = "gate: invalid wireguard iface address"
	ErrInvalidWGPeerPubKey    model.Error = "gate: invalid wireguard peer public key"
	ErrInvalidWGPeerEndpoint  model.Error = "gate: invalid wireguard peer endpoint"
	ErrInvalidWGPeerAllowedIP model.Error = "gate: invalid wireguard peer allowed_ip"
)

const (
	KindUnknown   Kind = "unknown"
	KindDirect    Kind = "direct"
	KindTor       Kind = "tor"
	KindWireGuard Kind = "wireguard"
)

type Kind string

func (x Kind) String() string {
	return string(x)
}

func (x *Kind) UnmarshalJSON(raw []byte) error {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return err
	}

	val, err := ParseKind(s)
	if err != nil {
		return err
	}

	*x = val

	return nil
}

func (x Kind) MarshalJSON() ([]byte, error) {
	var s string

	switch x {
	case KindUnknown, KindDirect, KindTor, KindWireGuard:
		s = string(x)
	default:
		return nil, ErrKindUnknown
	}

	return json.Marshal(s)
}

func ParseKind(raw string) (Kind, error) {
	switch Kind(raw) {
	case KindDirect:
		return KindDirect, nil
	case KindTor:
		return KindTor, nil
	case KindWireGuard:
		return KindWireGuard, nil

	default:
		return KindUnknown, ErrKindUnknown
	}
}

type ExitGate interface {
	ID() uuid.UUID
	Kind() Kind

	AddReq()
	DidReq()

	netDialDoer
}

type exitGateExt interface {
	ExitGate

	stateTracker

	refresh() error
	close() error
}

type netDialDoer interface {
	netDialer
	httpDoer
}

type netDialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

type httpDoer interface {
	Do(r *http.Request) (*http.Response, error)
}

type stateTracker interface {
	getState() state
	toState(st state)
	isReady() bool
	noReqs() bool
	resetReqs()
}

type torFactory interface {
	new(ctx context.Context, dtout, cltout time.Duration) (*Tor, error)
}

type wgFactory interface {
	new(lg *slog.Logger, cfg *WGConfig, dnsAddr netip.Addr, tout time.Duration) (*WireGuard, error)
}

type Set struct {
	cfg *SetConfig

	onceShut *sync.Once
	shutting chan struct{}
	warming  *struct{ value uint32 }

	drt *Direct
	tgs *model.Set[uuid.UUID, *Tor]
	wgs *model.Set[uuid.UUID, *WireGuard]

	tf torFactory
}

func NewSet(cfg *SetConfig, dct *Direct, tgs []*Tor, wgs []*WireGuard) *Set {
	result := &Set{
		cfg: cfg,

		onceShut: &sync.Once{},
		shutting: make(chan struct{}),
		warming:  &struct{ value uint32 }{},

		drt: dct,
		tgs: model.NewSetSize[uuid.UUID, *Tor](len(tgs)),
		wgs: model.NewSetSize[uuid.UUID, *WireGuard](len(wgs)),

		tf: &torCreator{},
	}

	for i := range tgs {
		result.tgs.Set(tgs[i].id, tgs[i])
	}

	for i := range wgs {
		result.wgs.Set(wgs[i].id, wgs[i])
	}

	return result
}

// ByID returns the gate identified by id if ready.
func (s *Set) ByID(id uuid.UUID) (ExitGate, error) {
	result, err := s.byID(id)
	if err != nil {
		return nil, err
	}

	if !result.isReady() {
		return nil, ErrGateNotReady
	}

	return result, nil
}

func (s *Set) ByKind(ctx context.Context, kind Kind) (ExitGate, error) {
	if kind == KindDirect {
		return s.drt, nil
	}

	return s.byKindReady(ctx, kind)
}

func (s *Set) Random(ctx context.Context) (ExitGate, error) {
	return s.ByKind(ctx, s.kindOrDefault())
}

func (s *Set) New(ctx context.Context, kind Kind) (uuid.UUID, error) {
	if kind != KindTor {
		return uuid.Nil, ErrKindNotSupported
	}

	// Check if s is shutting.
	// Starting a new tor instance takes time,
	// and there is little sense in doing it during shutdown.
	if s.isShutting() {
		return uuid.Nil, ErrSetIsShutting
	}

	if n := s.tgs.Len(); n >= s.cfg.TorMax {
		return uuid.Nil, ErrTorMaxReached
	}

	gt, err := s.tf.new(s.cfg.BaseCtx(), s.cfg.TorStartupTout, s.cfg.HTTPTimeout)
	if err != nil {
		return uuid.Nil, err
	}

	s.tgs.Set(gt.id, gt)

	return gt.id, nil
}

func (s *Set) GateIDs(kind Kind) ([]uuid.UUID, error) {
	switch kind {
	case KindDirect:
		return []uuid.UUID{s.drt.id}, nil

	case KindTor:
		return s.tgs.Keys(), nil

	case KindWireGuard:
		return s.wgs.Keys(), nil

	default:
		return nil, ErrKindUnknown
	}
}

func (s *Set) RefreshOne(ctx context.Context, id uuid.UUID) error {
	if id == s.drt.id {
		return ErrKindNotSupported
	}

	gt, err := s.byID(id)
	if err != nil {
		return err
	}

	if gt.Kind() != KindTor {
		return ErrKindNotSupported
	}

	if err := s.forState(ctx, gt, stateMaintenance); err != nil {
		return err
	}

	if err := refreshOne(ctx, gt); err != nil {
		return err
	}

	return s.toState(gt, stateReady)
}

func (s *Set) CloseOne(ctx context.Context, id uuid.UUID) error {
	if id == s.drt.id {
		return ErrKindNotSupported
	}

	gt, err := s.byID(id)
	if err != nil {
		return err
	}

	if err := s.forState(ctx, gt, stateClosed); err != nil {
		return err
	}

	return shutdownOne(ctx, gt)
}

func (s *Set) Shutdown(ctx context.Context) error {
	var errs []error

	s.onceShut.Do(func() {
		closeOrSkip(s.shutting)

		errc := make(chan error, 2)
		wg := &sync.WaitGroup{}

		if s.tgs.Len() > 0 {
			wg.Add(1)

			go func(tgs []*Tor) {
				defer wg.Done()

				errc <- ShutdownList(ctx, tgs)
			}(s.tgs.Values())
		}

		if s.wgs.Len() > 0 {
			wg.Add(1)

			go func(wgs []*WireGuard) {
				defer wg.Done()

				errc <- ShutdownList(ctx, wgs)
			}(s.wgs.Values())
		}

		go func() { wg.Wait(); close(errc) }()

		errs = collectErrs(errc)
	})

	return errors.Join(errs...)
}

func (s *Set) Warmup(ctx context.Context) error {
	if s.isShutting() {
		return errors.Join(ErrSetIsShutting)
	}

	if ok := atomic.CompareAndSwapUint32(&s.warming.value, 0, 1); !ok {
		return errors.Join(ErrSetIsWarmingUp)
	}

	defer func() { atomic.StoreUint32(&s.warming.value, 0) }()

	errc := make(chan error, 2)
	wg := &sync.WaitGroup{}

	if s.tgs.Len() > 0 {
		wg.Add(1)

		go func(tgs []*Tor) {
			defer wg.Done()

			_, err := WarmupList(ctx, tgs)

			errc <- err
		}(s.tgs.Values())
	}

	if s.wgs.Len() > 0 {
		wg.Add(1)

		go func(wgs []*WireGuard) {
			defer wg.Done()

			_, err := WarmupList(ctx, wgs)

			errc <- err
		}(s.wgs.Values())
	}

	go func() { wg.Wait(); close(errc) }()

	return errors.Join(collectErrs(errc)...)
}

func (s *Set) kindOrDefault() Kind {
	return s.kindOrDefaultN(rand.Int())
}

func (s *Set) kindOrDefaultN(n int) Kind {
	if !s.cfg.RandomiseKinds {
		return s.cfg.Default
	}

	return pickRandomKind(n)
}

func (s *Set) byID(id uuid.UUID) (exitGateExt, error) {
	if id == s.drt.ID() {
		return s.drt, nil
	}

	result, ok := s.tgs.Get(id)
	if !ok {
		result, ok := s.wgs.Get(id)
		if !ok {
			return nil, ErrGateNotFound
		}

		return result, nil
	}

	return result, nil
}

func (s *Set) byKindReady(ctx context.Context, kind Kind) (exitGateExt, error) {
	rctx, cancel := context.WithTimeout(ctx, s.cfg.RandomLoopTout)
	defer cancel()

	tc := time.NewTicker(s.cfg.RandomLoopDelay)
	defer tc.Stop()

	for {
		if s.isShutting() {
			return nil, ErrSetIsShutting
		}

		result, err := s.byKind(kind)
		if err != nil {
			return nil, err
		}

		if result.isReady() {
			return result, nil
		}

		select {
		case <-rctx.Done():
			return nil, rctx.Err()
		case <-tc.C:
		}
	}
}

func (s *Set) byKind(kind Kind) (exitGateExt, error) {
	switch kind {
	case KindDirect:
		return s.drt, nil

	case KindTor:
		result, ok := s.tgs.Random()
		if !ok {
			return nil, ErrNoRandomGate
		}

		return result, nil

	case KindWireGuard:
		result, ok := s.wgs.Random()
		if !ok {
			return nil, ErrNoRandomGate
		}

		return result, nil

	default:
		return nil, ErrKindUnknown
	}
}

func (s *Set) forState(ctx context.Context, gt exitGateExt, st state) error {
	// Consider what to do in a case of failure below.
	//
	// The gate has been moved to st (Maintenance or Closed), and removed from the set.
	// There are a couple of situations when the gate would have to be put back:
	// - if the incoming request's context is done, i.e. the client times out or abandons;
	// - if the loop times out, i.e. the gate is busy serving connections.
	//
	// Possible options are:
	// - do nothing, but the gate would be left in an unknown state;
	// - recover the gate's state and put it back;
	// - stop it.
	//
	// It's the caller who knows what needs to be done to the gate.
	// Ideally, operations should be idempotent, so that the caller could retry.
	// Therefore, option 2 is a reasonable choice.
	origst := gt.getState()
	gt.toState(st)

	id := gt.ID()

	switch gt.Kind() {
	case KindTor:
		s.tgs.Remove(id)
	case KindWireGuard:
		s.wgs.Remove(id)
	}

	rctx, cancel := context.WithTimeout(ctx, s.cfg.StateLoopTout)
	defer cancel()

	tc := time.NewTicker(s.cfg.StateLoopDelay)
	defer tc.Stop()

	for {
		if s.isShutting() {
			return ErrSetIsShutting
		}

		if gt.noReqs() {
			return nil
		}

		select {
		case <-rctx.Done():
			_ = s.toState(gt, origst)

			return rctx.Err()
		case <-tc.C:
		}
	}
}

func (s *Set) toState(gt exitGateExt, st state) error {
	gt.resetReqs()
	gt.toState(st)

	switch gtx := gt.(type) {
	case *Direct:
		return nil
	case *Tor:
		s.tgs.Set(gtx.id, gtx)

		return nil

	case *WireGuard:
		s.wgs.Set(gtx.id, gtx)

		return nil

	default:
		// Unreachable.
		return ErrKindUnknown
	}
}

func (s *Set) isShutting() bool {
	select {
	case <-s.shutting:
		return true
	default:
		return false
	}
}

type SetConfig struct {
	Default         Kind
	HTTPTimeout     time.Duration
	RandomLoopTout  time.Duration
	RandomLoopDelay time.Duration
	StateLoopTout   time.Duration
	StateLoopDelay  time.Duration
	TorStartupTout  time.Duration
	TorMax          int
	FnBaseCtx       func() context.Context
	RandomiseKinds  bool
}

func (c *SetConfig) BaseCtx() context.Context {
	if c.FnBaseCtx == nil {
		return context.Background()
	}

	return c.FnBaseCtx()
}

type Direct struct {
	*baseGate
	netd netDialer
	doer httpDoer
}

func NewDirect(tout time.Duration) *Direct {
	id := uuid.MustParse("facade00-0000-4000-a000-000000000000")

	netd := &net.Dialer{Timeout: tout}
	doer := &http.Client{
		Timeout: tout,
		Transport: &http.Transport{
			DialContext: netd.DialContext,
		},
	}

	return newDirect(id, netd, doer)
}

func newDirect(id uuid.UUID, netd netDialer, doer httpDoer) *Direct {
	result := &Direct{
		baseGate: newBaseGateID(KindDirect, id),
		netd:     netd,
		doer:     doer,
	}

	return result
}

func (g *Direct) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return g.netd.DialContext(ctx, network, addr)
}

func (g *Direct) Do(r *http.Request) (*http.Response, error) {
	return g.doer.Do(r)
}

func (g *Direct) warmup(ctx context.Context) (time.Duration, error) {
	return warmupDoer(ctx, g.doer)
}

func (g *Direct) refresh() error {
	return ErrNotImplemented
}

func (g *Direct) close() error {
	return nil
}

func ShutdownList[T interface{ close() error }](pctx context.Context, l []T) error {
	n := len(l)
	if n == 0 {
		return nil
	}

	errc := make(chan error, n)
	wg := &sync.WaitGroup{}

	ctx, cancel := context.WithCancel(pctx)
	defer cancel()

	wg.Add(n)
	for i := range l {
		go func(cl T) {
			defer wg.Done()

			errc <- shutdownOne(ctx, cl)
		}(l[i])
	}

	go func() {
		wg.Wait()
		close(errc)
	}()

	return errors.Join(collectErrs(errc)...)
}

func WarmupList[T interface {
	warmup(context.Context) (time.Duration, error)
}](pctx context.Context, l []T) ([]time.Duration, error) {
	n := len(l)
	if n == 0 {
		return nil, nil
	}

	out := make(chan *warmupResponseWithErr, len(l))
	wg := &sync.WaitGroup{}

	ctx, cancel := context.WithCancel(pctx)
	defer cancel()

	wg.Add(n)
	for i := range l {
		go func(wu T) {
			defer wg.Done()

			out <- warmupOne(ctx, wu)
		}(l[i])
	}

	go func() {
		wg.Wait()
		close(out)
	}()

	var (
		result []time.Duration
		errs   []error
	)

	for part := range out {
		if part.err != nil {
			errs = append(errs, part.err)
		} else {
			result = append(result, part.latency)
		}
	}

	if len(errs) > 0 {
		return result, errors.Join(errs...)
	}

	return result, nil
}

func refreshOne[T interface{ refresh() error }](ctx context.Context, rr T) error {
	errc := make(chan error, 1)
	go func() {
		defer close(errc)

		if err := rr.refresh(); err != nil {
			errc <- err
			return
		}
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errc:
		return err
	}
}

func shutdownOne[T interface{ close() error }](ctx context.Context, clr T) error {
	errc := make(chan error, 1)
	go func() {
		defer close(errc)

		if err := clr.close(); err != nil {
			errc <- err
			return
		}
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errc:
		return err
	}
}

type warmupResponseWithErr struct {
	latency time.Duration
	err     error
}

func warmupOne[T interface {
	warmup(context.Context) (time.Duration, error)
}](ctx context.Context, wmr T) *warmupResponseWithErr {
	out := make(chan *warmupResponseWithErr, 1)
	go func() {
		defer close(out)

		result, err := wmr.warmup(ctx)
		out <- &warmupResponseWithErr{latency: result, err: err}
	}()

	select {
	case <-ctx.Done():
		return &warmupResponseWithErr{err: ctx.Err()}
	case resp := <-out:
		return resp
	}
}

func warmupDoer(ctx context.Context, doer httpDoer) (time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://httpbin.org/status/200", nil)
	if err != nil {
		return 0, err
	}

	now := time.Now()
	resp, err := doer.Do(req)
	if err != nil {
		return 0, err
	}

	if resp != nil && resp.Body != nil {
		defer func() { _ = resp.Body.Close() }()
	}

	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		return 0, ErrWarmupBadResponse
	}

	return time.Since(now), nil
}

type baseGate struct {
	kind  Kind
	id    uuid.UUID
	state *gateState
}

func newBaseGateID(kind Kind, id uuid.UUID) *baseGate {
	return &baseGate{kind: kind, id: id, state: newGateState()}
}

func (g *baseGate) Kind() Kind {
	return g.kind
}

func (g *baseGate) ID() uuid.UUID {
	return g.id
}

func (g *baseGate) AddReq() {
	g.state.addReq()
}

func (g *baseGate) DidReq() {
	g.state.didReq()
}

func (g *baseGate) noReqs() bool {
	return g.state.noReqs()
}

func (g *baseGate) resetReqs() {
	g.state.resetReqs()
}

func (g *baseGate) getState() state {
	return g.state.getState()
}

func (g *baseGate) isReady() bool {
	return g.state.getState() == stateReady
}

func (g *baseGate) toState(st state) {
	switch st {
	case stateReady:
		g.state.toReady()
	case stateMaintenance:
		g.state.toMaint()
	case stateClosed:
		g.state.toClosed()
	}
}

const (
	stateReady state = iota
	stateMaintenance
	stateClosed
)

type state uint32

type gateState struct {
	state *struct{ value uint32 }
	mu    *sync.Mutex
	nreq  uint64
}

func newGateState() *gateState {
	result := &gateState{
		state: &struct{ value uint32 }{},
		mu:    &sync.Mutex{},
	}

	return result
}

func (s *gateState) toReady() {
	// StateReady can only be transitioned to from:
	// - initial state;
	// - StateMaintenance.
	_ = atomic.CompareAndSwapUint32(&s.state.value, uint32(stateMaintenance), uint32(stateReady))
}

func (s *gateState) toMaint() {
	// StateMaintenance can only be transitioned to from StateReady.
	_ = atomic.CompareAndSwapUint32(&s.state.value, uint32(stateReady), uint32(stateMaintenance))
}

func (s *gateState) toClosed() {
	// StateClosed can be transitioned to from:
	// - StateReady;
	// - StateMaintenance.
	if ok := atomic.CompareAndSwapUint32(&s.state.value, uint32(stateReady), uint32(stateClosed)); ok {
		return
	}

	_ = atomic.CompareAndSwapUint32(&s.state.value, uint32(stateMaintenance), uint32(stateClosed))
}

func (s *gateState) getState() state {
	return state(atomic.LoadUint32(&s.state.value))
}

func (s *gateState) addReq() {
	s.mu.Lock()
	s.nreq += 1
	s.mu.Unlock()
}

func (s *gateState) didReq() {
	s.mu.Lock()
	if s.nreq > 0 {
		s.nreq -= 1
	}
	s.mu.Unlock()
}

func (s *gateState) reqNum() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.nreq
}

func (s *gateState) noReqs() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.nreq == 0
}

func (s *gateState) resetReqs() {
	s.mu.Lock()
	s.nreq = 0
	s.mu.Unlock()
}

func closeOrSkip[C chan T, T any](c C) {
	select {
	case <-c:
	default:
		if c == nil {
			return
		}

		close(c)
	}
}

// collectErrs collects errors from _closed_ errc and returns the result.
//
// It's a programming error to an open errc.
func collectErrs(errc <-chan error) []error {
	var errs []error

	for err := range errc {
		if err != nil {
			errs = append(errs, err)
		}
	}

	return errs
}

func pickRandomKind(n int) Kind {
	if n%2 == 0 {
		return KindTor
	}

	return KindWireGuard
}
