package gate

import (
	"context"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/cretz/bine/tor"
	"github.com/google/uuid"
)

type Tor struct {
	*baseGate
	refreshing *struct{ value uint32 }
	dev        torSignalCloser
	netd       netDialer
	doer       httpDoer
}

func NewTor(ctx context.Context, dtout, cltout time.Duration) (*Tor, error) {
	return newTorWithFactory(ctx, dtout, cltout, &torCreator{})
}

func newTorWithFactory(ctx context.Context, dtout, cltout time.Duration, tf torFactory) (*Tor, error) {
	return tf.new(ctx, dtout, cltout)
}

func newTor(id uuid.UUID, dev torSignalCloser, netd netDialer, doer httpDoer) *Tor {
	result := &Tor{
		baseGate:   newBaseGateID(KindTor, id),
		refreshing: &struct{ value uint32 }{},
		dev:        dev,
		netd:       netd,
		doer:       doer,
	}

	return result
}

func (g *Tor) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return g.netd.DialContext(ctx, network, addr)
}

func (g *Tor) Do(r *http.Request) (*http.Response, error) {
	return g.doer.Do(r)
}

func (g *Tor) warmup(ctx context.Context) (time.Duration, error) {
	return warmupDoer(ctx, g.doer)
}

func (g *Tor) refresh() error {
	if ok := atomic.CompareAndSwapUint32(&g.refreshing.value, 0, 1); !ok {
		return ErrGateIsRefreshing
	}

	defer func() { atomic.StoreUint32(&g.refreshing.value, 0) }()

	return g.dev.signal("NEWNYM")
}

func (g *Tor) close() error {
	return g.dev.close()
}

func NewTors(ctx context.Context, stutout, cltout time.Duration, n int) ([]*Tor, error) {
	tf := &torCreator{}

	var result []*Tor

	for i := 0; i < n; i++ {
		tg, err := newTorWithFactory(ctx, stutout, cltout, tf)
		if err != nil {
			return nil, err
		}

		result = append(result, tg)
	}

	return result, nil
}

type torCreator struct{}

func (c *torCreator) new(ctx context.Context, dtout, cltout time.Duration) (*Tor, error) {
	dev, err := tor.Start(ctx, &tor.StartConf{TempDataDirBase: "/tmp"})
	if err != nil {
		return nil, err
	}

	dctx, cancel := context.WithTimeout(ctx, dtout)
	defer cancel()

	tnet, err := dev.Dialer(dctx, &tor.DialConf{})
	if err != nil {
		return nil, err
	}

	tdev := &torDev{fnSignal: dev.Control.Signal, fnClose: dev.Close}
	doer := &http.Client{
		Timeout: cltout,
		Transport: &http.Transport{
			DialContext: tnet.DialContext,
		},
	}

	return newTor(uuid.New(), tdev, tnet, doer), nil
}

type torSignalCloser interface {
	signal(s string) error
	close() error
}

type torDev struct {
	fnSignal func(string) error
	fnClose  func() error
}

func (d *torDev) signal(s string) error {
	if d.fnSignal == nil {
		return nil
	}

	return d.fnSignal(s)
}

func (d *torDev) close() error {
	if d.fnClose == nil {
		return nil
	}

	return d.fnClose()
}
