package gate

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	should "github.com/stretchr/testify/assert"
	must "github.com/stretchr/testify/require"

	"github.com/pavelbrm/pumpe/model"
)

type testCase[G, E any] struct {
	name  string
	given G
	exp   E
}

func TestKind_UnmarshalJSON(t *testing.T) {
	type tcExpected struct {
		kind Kind
		err  error
	}

	tests := []testCase[[]byte, tcExpected]{
		{
			name: "error_invalid_input",
			exp: tcExpected{
				err: func() error {
					return json.Unmarshal(nil, &struct{}{})
				}(),
			},
		},

		{
			name:  "error_unknown_kind",
			given: []byte(`"openvpn"`),
			exp: tcExpected{
				err: ErrKindUnknown,
			},
		},

		{
			name:  "valid_tor",
			given: []byte(`"tor"`),
			exp: tcExpected{
				kind: KindTor,
			},
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			var actual Kind

			err := (&actual).UnmarshalJSON(tc.given)
			must.Equal(t, tc.exp.err, err)

			if tc.exp.err != nil {
				return
			}

			should.Equal(t, tc.exp.kind, actual)
		})
	}
}

func TestKind_MarshalJSON(t *testing.T) {
	type tcExpected struct {
		data []byte
		err  error
	}

	tests := []testCase[Kind, tcExpected]{
		{
			name:  "error_unknown_kind",
			given: Kind("openvpn"),
			exp: tcExpected{
				err: ErrKindUnknown,
			},
		},

		{
			name:  "valid_unknown",
			given: KindUnknown,
			exp: tcExpected{
				data: []byte(`"unknown"`),
			},
		},

		{
			name:  "valid_direct",
			given: KindDirect,
			exp: tcExpected{
				data: []byte(`"direct"`),
			},
		},

		{
			name:  "valid_tor",
			given: KindTor,
			exp: tcExpected{
				data: []byte(`"tor"`),
			},
		},

		{
			name:  "valid_wireguard",
			given: KindWireGuard,
			exp: tcExpected{
				data: []byte(`"wireguard"`),
			},
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			actual, err := tc.given.MarshalJSON()
			must.Equal(t, tc.exp.err, err)

			if tc.exp.err != nil {
				return
			}

			should.Equal(t, tc.exp.data, actual)
		})
	}
}

func TestParseKind(t *testing.T) {
	type tcExpected struct {
		kind Kind
		err  error
	}

	tests := []testCase[string, tcExpected]{
		{
			name:  "error_unknown",
			given: "something_else",
			exp: tcExpected{
				kind: KindUnknown,
				err:  ErrKindUnknown,
			},
		},

		{
			name:  "valid_direct",
			given: "direct",
			exp: tcExpected{
				kind: KindDirect,
			},
		},

		{
			name:  "valid_tor",
			given: "tor",
			exp: tcExpected{
				kind: KindTor,
			},
		},

		{
			name:  "valid_wireguard",
			given: "wireguard",
			exp: tcExpected{
				kind: KindWireGuard,
			},
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			actual, err := ParseKind(tc.given)
			must.Equal(t, tc.exp.err, err)

			should.Equal(t, tc.exp.kind, actual)
		})
	}
}

func TestSet_ByID(t *testing.T) {
	type tcGiven struct {
		drt *Direct
		tgs []*Tor
		wgs []*WireGuard
		id  uuid.UUID
	}

	type tcExpected struct {
		gate ExitGate
		err  error
	}

	tests := []testCase[tcGiven, tcExpected]{
		{
			name: "error_not_found",
			given: tcGiven{
				drt: newDirect(uuid.MustParse("facade00-0000-4000-a000-000000000000"), &MockNetDialer{}, &MockHTTPDoer{}),
				id:  uuid.MustParse("5ca1ab1e-0000-4000-a000-000000000000"),
			},
			exp: tcExpected{
				err: ErrGateNotFound,
			},
		},

		{
			name: "error_not_ready",
			given: tcGiven{
				drt: func() *Direct {
					gt := newDirect(uuid.MustParse("facade00-0000-4000-a000-000000000000"), &MockNetDialer{}, &MockHTTPDoer{})
					gt.toState(stateMaintenance)

					return gt
				}(),
				id: uuid.MustParse("facade00-0000-4000-a000-000000000000"),
			},
			exp: tcExpected{
				err: ErrGateNotReady,
			},
		},

		{
			name: "valid_direct",
			given: tcGiven{
				drt: newDirect(uuid.MustParse("facade00-0000-4000-a000-000000000000"), &MockNetDialer{}, &MockHTTPDoer{}),
				id:  uuid.MustParse("facade00-0000-4000-a000-000000000000"),
			},
			exp: tcExpected{
				gate: newDirect(uuid.MustParse("facade00-0000-4000-a000-000000000000"), &MockNetDialer{}, &MockHTTPDoer{}),
			},
		},

		{
			name: "valid_tor",
			given: tcGiven{
				drt: newDirect(uuid.MustParse("facade00-0000-4000-a000-000000000000"), &MockNetDialer{}, &MockHTTPDoer{}),
				tgs: []*Tor{
					newTor(uuid.MustParse("c0c0a000-0000-4000-a000-000000000000"), &torDev{}, &MockNetDialer{}, &MockHTTPDoer{}),
				},
				id: uuid.MustParse("c0c0a000-0000-4000-a000-000000000000"),
			},
			exp: tcExpected{
				gate: newTor(uuid.MustParse("c0c0a000-0000-4000-a000-000000000000"), &torDev{}, &MockNetDialer{}, &MockHTTPDoer{}),
			},
		},

		{
			name: "valid_wg",
			given: tcGiven{
				drt: newDirect(uuid.MustParse("facade00-0000-4000-a000-000000000000"), &MockNetDialer{}, &MockHTTPDoer{}),
				wgs: []*WireGuard{
					newWireGuard(uuid.MustParse("decade00-0000-4000-a000-000000000000"), &wgDev{}, &MockNetDialer{}, &MockHTTPDoer{}),
				},
				id: uuid.MustParse("decade00-0000-4000-a000-000000000000"),
			},
			exp: tcExpected{
				gate: newWireGuard(uuid.MustParse("decade00-0000-4000-a000-000000000000"), &wgDev{}, &MockNetDialer{}, &MockHTTPDoer{}),
			},
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			set := NewSet(&SetConfig{}, tc.given.drt, tc.given.tgs, tc.given.wgs)

			actual, err := set.ByID(tc.given.id)
			must.Equal(t, tc.exp.err, err)

			if tc.exp.err != nil {
				return
			}

			should.Equal(t, tc.exp.gate, actual)
		})
	}
}

func TestSet_ByKind(t *testing.T) {
	type tcGiven struct {
		drt  *Direct
		tgs  []*Tor
		wgs  []*WireGuard
		kind Kind
	}

	type tcExpected struct {
		gate ExitGate
		err  error
	}

	tests := []testCase[tcGiven, tcExpected]{
		{
			name: "valid_direct",
			given: tcGiven{
				drt:  newDirect(uuid.MustParse("facade00-0000-4000-a000-000000000000"), &MockNetDialer{}, &MockHTTPDoer{}),
				kind: KindDirect,
			},
			exp: tcExpected{
				gate: newDirect(uuid.MustParse("facade00-0000-4000-a000-000000000000"), &MockNetDialer{}, &MockHTTPDoer{}),
			},
		},

		{
			name: "valid_tor",
			given: tcGiven{
				drt: newDirect(uuid.MustParse("facade00-0000-4000-a000-000000000000"), &MockNetDialer{}, &MockHTTPDoer{}),
				tgs: []*Tor{
					newTor(uuid.MustParse("c0c0a000-0000-4000-a000-000000000000"), &torDev{}, &MockNetDialer{}, &MockHTTPDoer{}),
				},
				kind: KindTor,
			},
			exp: tcExpected{
				gate: newTor(uuid.MustParse("c0c0a000-0000-4000-a000-000000000000"), &torDev{}, &MockNetDialer{}, &MockHTTPDoer{}),
			},
		},

		{
			name: "valid_wg",
			given: tcGiven{
				drt: newDirect(uuid.MustParse("facade00-0000-4000-a000-000000000000"), &MockNetDialer{}, &MockHTTPDoer{}),
				wgs: []*WireGuard{
					newWireGuard(uuid.MustParse("decade00-0000-4000-a000-000000000000"), &wgDev{}, &MockNetDialer{}, &MockHTTPDoer{}),
				},
				kind: KindWireGuard,
			},
			exp: tcExpected{
				gate: newWireGuard(uuid.MustParse("decade00-0000-4000-a000-000000000000"), &wgDev{}, &MockNetDialer{}, &MockHTTPDoer{}),
			},
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			cfg := &SetConfig{
				RandomLoopTout:  10 * time.Second,
				RandomLoopDelay: 10 * time.Millisecond,
			}

			set := NewSet(cfg, tc.given.drt, tc.given.tgs, tc.given.wgs)

			ctx := context.Background()

			actual, err := set.ByKind(ctx, tc.given.kind)
			must.Equal(t, tc.exp.err, err)

			if tc.exp.err != nil {
				return
			}

			should.Equal(t, tc.exp.gate, actual)
		})
	}
}

func TestSet_New(t *testing.T) {
	type tcGiven struct {
		cfg       *SetConfig
		tgs       []*Tor
		fnPrepSet func(set *Set)
		kind      Kind
	}

	type tcExpected struct {
		id   uuid.UUID
		gate exitGateExt
		err  error
		ok   bool
	}

	tests := []testCase[tcGiven, tcExpected]{
		{
			name: "error_kind_not_supported",
			given: tcGiven{
				cfg: &SetConfig{TorMax: 10},
				fnPrepSet: func(set *Set) {
					tf := &mockTorCreator{
						fnNew: func(ctx context.Context, dtout, cltout time.Duration) (*Tor, error) {
							return nil, model.Error("unexpected_new")
						},
					}

					set.tf = tf
				},
				kind: KindDirect,
			},
			exp: tcExpected{
				id:  uuid.Nil,
				err: ErrKindNotSupported,
			},
		},

		{
			name: "error_set_is_shutting",
			given: tcGiven{
				cfg: &SetConfig{TorMax: 10},
				fnPrepSet: func(set *Set) {
					tf := &mockTorCreator{
						fnNew: func(ctx context.Context, dtout, cltout time.Duration) (*Tor, error) {
							return nil, model.Error("unexpected_new")
						},
					}

					set.tf = tf
					closeOrSkip(set.shutting)
				},
				kind: KindTor,
			},
			exp: tcExpected{
				id:  uuid.Nil,
				err: ErrSetIsShutting,
			},
		},

		{
			name: "error_tor_max_reached",
			given: tcGiven{
				cfg: &SetConfig{TorMax: 1},
				tgs: []*Tor{
					newTor(uuid.MustParse("c0c0a000-0000-4000-a000-000000000000"), &torDev{}, &MockNetDialer{}, &MockHTTPDoer{}),
				},
				fnPrepSet: func(set *Set) {
					tf := &mockTorCreator{
						fnNew: func(ctx context.Context, dtout, cltout time.Duration) (*Tor, error) {
							return nil, model.Error("unexpected_new")
						},
					}

					set.tf = tf
				},
				kind: KindTor,
			},
			exp: tcExpected{
				id:  uuid.Nil,
				err: ErrTorMaxReached,
			},
		},

		{
			name: "error_something_went_wrong",
			given: tcGiven{
				cfg: &SetConfig{TorMax: 10},
				fnPrepSet: func(set *Set) {
					tf := &mockTorCreator{
						fnNew: func(ctx context.Context, dtout, cltout time.Duration) (*Tor, error) {
							return nil, model.Error("something_went_wrong")
						},
					}

					set.tf = tf
				},
				kind: KindTor,
			},
			exp: tcExpected{
				id:  uuid.Nil,
				err: model.Error("something_went_wrong"),
			},
		},

		{
			name: "success",
			given: tcGiven{
				cfg: &SetConfig{TorMax: 10},
				fnPrepSet: func(set *Set) {
					tf := &mockTorCreator{
						fnNew: func(ctx context.Context, dtout, cltout time.Duration) (*Tor, error) {
							return newTor(uuid.MustParse("c0c0a000-0000-4000-a000-000000000000"), &torDev{}, &MockNetDialer{}, &MockHTTPDoer{}), nil
						},
					}

					set.tf = tf
				},
				kind: KindTor,
			},
			exp: tcExpected{
				id:   uuid.MustParse("c0c0a000-0000-4000-a000-000000000000"),
				gate: newTor(uuid.MustParse("c0c0a000-0000-4000-a000-000000000000"), &torDev{}, &MockNetDialer{}, &MockHTTPDoer{}),
				ok:   true,
			},
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			drt := newDirect(uuid.MustParse("facade00-0000-4000-a000-000000000000"), &MockNetDialer{}, &MockHTTPDoer{})
			set := NewSet(tc.given.cfg, drt, tc.given.tgs, nil)
			tc.given.fnPrepSet(set)

			ctx := context.Background()

			actual, err := set.New(ctx, tc.given.kind)
			must.Equal(t, tc.exp.err, err)

			should.Equal(t, tc.exp.id, actual)

			actual2, ok := set.tgs.Get(tc.exp.id)
			must.Equal(t, tc.exp.ok, ok)

			if !tc.exp.ok {
				return
			}

			should.Equal(t, tc.exp.gate, actual2)
		})
	}
}

func TestSet_GateIDs(t *testing.T) {
	type tcGiven struct {
		set  *Set
		kind Kind
	}

	type tcExpected struct {
		ids []uuid.UUID
		err error
	}

	tests := []testCase[tcGiven, tcExpected]{
		{
			name: "error_unknown_kind",
			given: tcGiven{
				set: &Set{
					drt: newDirect(uuid.MustParse("facade00-0000-4000-a000-000000000000"), &MockNetDialer{}, &MockHTTPDoer{}),
					tgs: model.NewSet[uuid.UUID, *Tor](),
					wgs: model.NewSet[uuid.UUID, *WireGuard](),
				},
				kind: Kind("openvpn"),
			},
			exp: tcExpected{
				err: ErrKindUnknown,
			},
		},

		{
			name: "valid_direct",
			given: tcGiven{
				set: &Set{
					drt: newDirect(uuid.MustParse("facade00-0000-4000-a000-000000000000"), &MockNetDialer{}, &MockHTTPDoer{}),
					tgs: model.NewSet[uuid.UUID, *Tor](),
					wgs: model.NewSet[uuid.UUID, *WireGuard](),
				},
				kind: KindDirect,
			},
			exp: tcExpected{
				ids: []uuid.UUID{uuid.MustParse("facade00-0000-4000-a000-000000000000")},
			},
		},

		{
			name: "valid_tor",
			given: tcGiven{
				set: &Set{
					drt: newDirect(uuid.MustParse("facade00-0000-4000-a000-000000000000"), &MockNetDialer{}, &MockHTTPDoer{}),
					tgs: func() *model.Set[uuid.UUID, *Tor] {
						mset := model.NewSet[uuid.UUID, *Tor]()

						{
							gt := newTor(uuid.MustParse("c0c0a000-0000-4000-a000-000000000000"), &torDev{}, &MockNetDialer{}, &MockHTTPDoer{})
							mset.Set(gt.id, gt)
						}

						{
							gt := newTor(uuid.MustParse("ad0be000-0000-4000-a000-000000000000"), &torDev{}, &MockNetDialer{}, &MockHTTPDoer{})
							mset.Set(gt.id, gt)
						}

						return mset
					}(),
					wgs: model.NewSet[uuid.UUID, *WireGuard](),
				},
				kind: KindTor,
			},
			exp: tcExpected{
				ids: []uuid.UUID{
					uuid.MustParse("c0c0a000-0000-4000-a000-000000000000"),
					uuid.MustParse("ad0be000-0000-4000-a000-000000000000"),
				},
			},
		},

		{
			name: "valid_wireguard",
			given: tcGiven{
				set: &Set{
					drt: newDirect(uuid.MustParse("facade00-0000-4000-a000-000000000000"), &MockNetDialer{}, &MockHTTPDoer{}),
					tgs: model.NewSet[uuid.UUID, *Tor](),
					wgs: func() *model.Set[uuid.UUID, *WireGuard] {
						mset := model.NewSet[uuid.UUID, *WireGuard]()

						{
							gt := newWireGuard(uuid.MustParse("c0c0a000-0000-4000-a000-000000000000"), &wgDev{}, &MockNetDialer{}, &MockHTTPDoer{})
							mset.Set(gt.id, gt)
						}

						{
							gt := newWireGuard(uuid.MustParse("ad0be000-0000-4000-a000-000000000000"), &wgDev{}, &MockNetDialer{}, &MockHTTPDoer{})
							mset.Set(gt.id, gt)
						}

						return mset
					}(),
				},
				kind: KindWireGuard,
			},
			exp: tcExpected{
				ids: []uuid.UUID{
					uuid.MustParse("c0c0a000-0000-4000-a000-000000000000"),
					uuid.MustParse("ad0be000-0000-4000-a000-000000000000"),
				},
			},
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			actual, err := tc.given.set.GateIDs(tc.given.kind)
			must.Equal(t, tc.exp.err, err)

			if tc.exp.err != nil {
				return
			}

			should.ElementsMatch(t, tc.exp.ids, actual)
		})
	}
}

func TestSet_RefreshOne(t *testing.T) {
	type tcGiven struct {
		drt       *Direct
		tgs       []*Tor
		wgs       []*WireGuard
		fnPrepSet func(set *Set)
		id        uuid.UUID
	}

	type tcExpected struct {
		st  state
		err error
	}

	tests := []testCase[tcGiven, tcExpected]{
		{
			name: "error_direct_kind_not_supported",
			given: tcGiven{
				drt: newDirect(uuid.MustParse("facade00-0000-4000-a000-000000000000"), &MockNetDialer{}, &MockHTTPDoer{}),
				id:  uuid.MustParse("facade00-0000-4000-a000-000000000000"),
			},
			exp: tcExpected{
				err: ErrKindNotSupported,
			},
		},

		{
			name: "error_not_found",
			given: tcGiven{
				drt: newDirect(uuid.MustParse("facade00-0000-4000-a000-000000000000"), &MockNetDialer{}, &MockHTTPDoer{}),
				id:  uuid.MustParse("ad0be000-0000-4000-a000-000000000000"),
			},
			exp: tcExpected{
				err: ErrGateNotFound,
			},
		},

		{
			name: "error_wireguard_not_supported",
			given: tcGiven{
				drt: newDirect(uuid.MustParse("facade00-0000-4000-a000-000000000000"), &MockNetDialer{}, &MockHTTPDoer{}),
				wgs: []*WireGuard{
					newWireGuard(uuid.MustParse("ad0be000-0000-4000-a000-000000000000"), &wgDev{}, &MockNetDialer{}, &MockHTTPDoer{}),
				},
				id: uuid.MustParse("ad0be000-0000-4000-a000-000000000000"),
			},
			exp: tcExpected{
				err: ErrKindNotSupported,
			},
		},

		{
			name: "error_for_state_shutting",
			given: tcGiven{
				drt: newDirect(uuid.MustParse("facade00-0000-4000-a000-000000000000"), &MockNetDialer{}, &MockHTTPDoer{}),
				tgs: []*Tor{
					newTor(uuid.MustParse("ad0be000-0000-4000-a000-000000000000"), &torDev{}, &MockNetDialer{}, &MockHTTPDoer{}),
				},
				fnPrepSet: func(set *Set) {
					closeOrSkip(set.shutting)
				},
				id: uuid.MustParse("ad0be000-0000-4000-a000-000000000000"),
			},
			exp: tcExpected{
				err: ErrSetIsShutting,
			},
		},

		{
			name: "error_refresh",
			given: tcGiven{
				drt: newDirect(uuid.MustParse("facade00-0000-4000-a000-000000000000"), &MockNetDialer{}, &MockHTTPDoer{}),
				tgs: []*Tor{
					newTor(uuid.MustParse("ad0be000-0000-4000-a000-000000000000"), &torDev{
						fnSignal: func(s string) error { return model.Error("something_went_wrong") },
					}, &MockNetDialer{}, &MockHTTPDoer{}),
				},
				id: uuid.MustParse("ad0be000-0000-4000-a000-000000000000"),
			},
			exp: tcExpected{
				err: model.Error("something_went_wrong"),
			},
		},

		{
			name: "success",
			given: tcGiven{
				drt: newDirect(uuid.MustParse("facade00-0000-4000-a000-000000000000"), &MockNetDialer{}, &MockHTTPDoer{}),
				tgs: []*Tor{
					newTor(uuid.MustParse("ad0be000-0000-4000-a000-000000000000"), &torDev{}, &MockNetDialer{}, &MockHTTPDoer{}),
				},
				id: uuid.MustParse("ad0be000-0000-4000-a000-000000000000"),
			},
			exp: tcExpected{
				st: stateReady,
			},
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			cfg := &SetConfig{
				StateLoopTout:  10 * time.Second,
				StateLoopDelay: 10 * time.Millisecond,
			}

			set := NewSet(cfg, tc.given.drt, tc.given.tgs, tc.given.wgs)
			if tc.given.fnPrepSet != nil {
				tc.given.fnPrepSet(set)
			}

			ctx := context.Background()

			actual := set.RefreshOne(ctx, tc.given.id)
			must.Equal(t, tc.exp.err, actual)

			if tc.exp.err != nil {
				return
			}

			gt, err := set.byID(tc.given.id)
			must.Equal(t, nil, err)

			should.Equal(t, tc.exp.st, gt.getState())
		})
	}
}

func TestSet_CloseOne(t *testing.T) {
	type tcGiven struct {
		drt       *Direct
		tgs       []*Tor
		wgs       []*WireGuard
		fnPrepSet func(set *Set)
		id        uuid.UUID
	}

	type tcExpected struct {
		st  state
		err error
	}

	tests := []testCase[tcGiven, tcExpected]{
		{
			name: "error_direct_kind_not_supported",
			given: tcGiven{
				drt: newDirect(uuid.MustParse("facade00-0000-4000-a000-000000000000"), &MockNetDialer{}, &MockHTTPDoer{}),
				id:  uuid.MustParse("facade00-0000-4000-a000-000000000000"),
			},
			exp: tcExpected{
				err: ErrKindNotSupported,
			},
		},

		{
			name: "error_not_found",
			given: tcGiven{
				drt: newDirect(uuid.MustParse("facade00-0000-4000-a000-000000000000"), &MockNetDialer{}, &MockHTTPDoer{}),
				id:  uuid.MustParse("ad0be000-0000-4000-a000-000000000000"),
			},
			exp: tcExpected{
				err: ErrGateNotFound,
			},
		},

		{
			name: "error_for_state_shutting",
			given: tcGiven{
				drt: newDirect(uuid.MustParse("facade00-0000-4000-a000-000000000000"), &MockNetDialer{}, &MockHTTPDoer{}),
				tgs: []*Tor{
					newTor(uuid.MustParse("ad0be000-0000-4000-a000-000000000000"), &torDev{}, &MockNetDialer{}, &MockHTTPDoer{}),
				},
				fnPrepSet: func(set *Set) {
					closeOrSkip(set.shutting)
				},
				id: uuid.MustParse("ad0be000-0000-4000-a000-000000000000"),
			},
			exp: tcExpected{
				err: ErrSetIsShutting,
			},
		},

		{
			name: "error_shutdown",
			given: tcGiven{
				drt: newDirect(uuid.MustParse("facade00-0000-4000-a000-000000000000"), &MockNetDialer{}, &MockHTTPDoer{}),
				tgs: []*Tor{
					newTor(uuid.MustParse("ad0be000-0000-4000-a000-000000000000"), &torDev{
						fnClose: func() error { return model.Error("something_went_wrong") },
					}, &MockNetDialer{}, &MockHTTPDoer{}),
				},
				id: uuid.MustParse("ad0be000-0000-4000-a000-000000000000"),
			},
			exp: tcExpected{
				err: model.Error("something_went_wrong"),
			},
		},

		{
			name: "success_tor",
			given: tcGiven{
				drt: newDirect(uuid.MustParse("facade00-0000-4000-a000-000000000000"), &MockNetDialer{}, &MockHTTPDoer{}),
				tgs: []*Tor{
					newTor(uuid.MustParse("ad0be000-0000-4000-a000-000000000000"), &torDev{}, &MockNetDialer{}, &MockHTTPDoer{}),
				},
				id: uuid.MustParse("ad0be000-0000-4000-a000-000000000000"),
			},
			exp: tcExpected{
				st: stateClosed,
			},
		},

		{
			name: "success_wireguard",
			given: tcGiven{
				drt: newDirect(uuid.MustParse("facade00-0000-4000-a000-000000000000"), &MockNetDialer{}, &MockHTTPDoer{}),
				wgs: []*WireGuard{
					newWireGuard(uuid.MustParse("ad0be000-0000-4000-a000-000000000000"), &wgDev{}, &MockNetDialer{}, &MockHTTPDoer{}),
				},
				id: uuid.MustParse("ad0be000-0000-4000-a000-000000000000"),
			},
			exp: tcExpected{
				st: stateClosed,
			},
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			cfg := &SetConfig{
				StateLoopTout:  10 * time.Second,
				StateLoopDelay: 10 * time.Millisecond,
			}

			set := NewSet(cfg, tc.given.drt, tc.given.tgs, tc.given.wgs)
			if tc.given.fnPrepSet != nil {
				tc.given.fnPrepSet(set)
			}

			ctx := context.Background()

			var gt exitGateExt
			if tc.exp.err == nil {
				var err error
				gt, err = set.byID(tc.given.id)
				must.Equal(t, nil, err)
			}

			actual := set.CloseOne(ctx, tc.given.id)
			must.Equal(t, tc.exp.err, actual)

			if tc.exp.err != nil {
				return
			}

			should.Equal(t, tc.exp.st, gt.getState())
		})
	}
}

func TestSet_Shutdown(t *testing.T) {
	type tcGiven struct {
		tgs []*Tor
		wgs []*WireGuard

		fnCtx func() context.Context
	}

	tests := []testCase[tcGiven, error]{
		{
			name: "noop_no_tor_no_wg",
		},

		{
			name: "success_tor",
			given: tcGiven{
				tgs: []*Tor{
					newTor(uuid.MustParse("facade00-0000-4000-a000-000000000000"), &torDev{}, &MockNetDialer{}, &MockHTTPDoer{}),
				},
			},
		},

		{
			name: "success_wireguard",
			given: tcGiven{
				wgs: []*WireGuard{
					newWireGuard(uuid.MustParse("facade00-0000-4000-a000-000000000000"), &wgDev{}, &MockNetDialer{}, &MockHTTPDoer{}),
				},
			},
		},

		{
			name: "success_both",
			given: tcGiven{
				tgs: []*Tor{
					newTor(uuid.MustParse("facade00-0000-4000-a000-000000000000"), &torDev{}, &MockNetDialer{}, &MockHTTPDoer{}),
				},
				wgs: []*WireGuard{
					newWireGuard(uuid.MustParse("decade00-0000-4000-a000-000000000000"), &wgDev{}, &MockNetDialer{}, &MockHTTPDoer{}),
				},
			},
		},

		{
			name: "error_context_cancelled",
			given: tcGiven{
				tgs: []*Tor{
					{
						baseGate:   newBaseGateID(KindTor, uuid.MustParse("facade00-0000-4000-a000-000000000000")),
						refreshing: &struct{ value uint32 }{},
						dev: &torDev{
							fnClose: func() error {
								tmr := time.NewTimer(20 * time.Second)
								defer func() {
									if !tmr.Stop() {
										<-tmr.C
									}
								}()

								<-tmr.C

								return model.Error("unexpected_close_tor")
							},
						},
						netd: &MockNetDialer{},
						doer: &MockHTTPDoer{},
					},
				},
				wgs: []*WireGuard{
					{
						baseGate: newBaseGateID(KindWireGuard, uuid.MustParse("decade00-0000-4000-a000-000000000000")),
						dev: &wgDev{
							fnDown: func() error {
								tmr := time.NewTimer(20 * time.Second)
								defer func() {
									if !tmr.Stop() {
										<-tmr.C
									}
								}()

								<-tmr.C

								return model.Error("unexpected_close_wg")
							},
						},
						netd: &MockNetDialer{},
						doer: &MockHTTPDoer{},
					},
				},
				fnCtx: func() context.Context {
					ctx, cancel := context.WithCancel(context.Background())
					cancel()

					return ctx
				},
			},
			exp: errors.Join(errors.Join(context.Canceled), errors.Join(context.Canceled)),
		},

		{
			name: "errors",
			given: tcGiven{
				tgs: []*Tor{
					{
						baseGate:   newBaseGateID(KindTor, uuid.MustParse("facade00-0000-4000-a000-000000000000")),
						refreshing: &struct{ value uint32 }{},
						dev: &torDev{
							fnClose: func() error {
								return model.Error("something_went_wrong_tor")
							},
						},
						netd: &MockNetDialer{},
						doer: &MockHTTPDoer{},
					},
				},
				wgs: []*WireGuard{
					{
						baseGate: newBaseGateID(KindWireGuard, uuid.MustParse("decade00-0000-4000-a000-000000000000")),
						dev: &wgDev{
							fnDown: func() error {
								return model.Error("something_went_wrong_wg")
							},
						},
						netd: &MockNetDialer{},
						doer: &MockHTTPDoer{},
					},
				},
			},
			exp: errors.Join(
				errors.Join(model.Error("something_went_wrong_tor")),
				errors.Join(model.Error("something_went_wrong_wg")),
			),
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			set := NewSet(&SetConfig{}, nil, tc.given.tgs, tc.given.wgs)

			ctx := context.Background()
			if tc.given.fnCtx != nil {
				ctx = tc.given.fnCtx()
			}

			actual := set.Shutdown(ctx)
			must.ElementsMatch(t, model.UnwrapErrs(tc.exp), model.UnwrapErrs(actual))

			actual2 := set.Shutdown(context.Background())
			should.Equal(t, nil, actual2)
		})
	}
}

func TestSet_Warmup(t *testing.T) {
	type tcGiven struct {
		tgs []*Tor
		wgs []*WireGuard

		fnPrepSet func(set *Set)
		fnCtx     func() context.Context
	}

	tests := []testCase[tcGiven, error]{
		{
			name: "error_set_is_shutting",
			given: tcGiven{
				fnPrepSet: func(set *Set) {
					closeOrSkip(set.shutting)
				},
			},
			exp: errors.Join(ErrSetIsShutting),
		},

		{
			name: "error_set_is_warming_up",
			given: tcGiven{
				fnPrepSet: func(set *Set) {
					atomic.StoreUint32(&set.warming.value, 1)
				},
			},
			exp: errors.Join(ErrSetIsWarmingUp),
		},

		{
			name: "noop_no_tor_no_wg",
		},

		{
			name: "success_tor",
			given: tcGiven{
				tgs: []*Tor{
					newTor(uuid.MustParse("facade00-0000-4000-a000-000000000000"), &torDev{}, &MockNetDialer{}, &MockHTTPDoer{}),
				},
			},
		},

		{
			name: "success_wireguard",
			given: tcGiven{
				wgs: []*WireGuard{
					newWireGuard(uuid.MustParse("facade00-0000-4000-a000-000000000000"), &wgDev{}, &MockNetDialer{}, &MockHTTPDoer{}),
				},
			},
		},

		{
			name: "success_both",
			given: tcGiven{
				tgs: []*Tor{
					newTor(uuid.MustParse("facade00-0000-4000-a000-000000000000"), &torDev{}, &MockNetDialer{}, &MockHTTPDoer{}),
				},
				wgs: []*WireGuard{
					newWireGuard(uuid.MustParse("decade00-0000-4000-a000-000000000000"), &wgDev{}, &MockNetDialer{}, &MockHTTPDoer{}),
				},
			},
		},

		{
			name: "error_context_cancelled",
			given: tcGiven{
				tgs: []*Tor{
					{
						baseGate:   newBaseGateID(KindTor, uuid.MustParse("facade00-0000-4000-a000-000000000000")),
						refreshing: &struct{ value uint32 }{},
						dev:        &torDev{},
						netd:       &MockNetDialer{},
						doer: &MockHTTPDoer{
							FnDo: func(r *http.Request) (*http.Response, error) {
								tmr := time.NewTimer(20 * time.Second)
								defer func() {
									if !tmr.Stop() {
										<-tmr.C
									}
								}()

								<-tmr.C

								return nil, model.Error("unexpected_do_tor")
							},
						},
					},
				},
				wgs: []*WireGuard{
					{
						baseGate: newBaseGateID(KindWireGuard, uuid.MustParse("decade00-0000-4000-a000-000000000000")),
						dev:      &wgDev{},
						netd:     &MockNetDialer{},
						doer: &MockHTTPDoer{
							FnDo: func(r *http.Request) (*http.Response, error) {
								tmr := time.NewTimer(20 * time.Second)
								defer func() {
									if !tmr.Stop() {
										<-tmr.C
									}
								}()

								<-tmr.C

								return nil, model.Error("unexpected_do_wg")
							},
						},
					},
				},
				fnCtx: func() context.Context {
					ctx, cancel := context.WithCancel(context.Background())
					cancel()

					return ctx
				},
			},
			exp: errors.Join(errors.Join(context.Canceled), errors.Join(context.Canceled)),
		},

		{
			name: "errors",
			given: tcGiven{
				tgs: []*Tor{
					{
						baseGate:   newBaseGateID(KindTor, uuid.MustParse("facade00-0000-4000-a000-000000000000")),
						refreshing: &struct{ value uint32 }{},
						dev:        &torDev{},
						netd:       &MockNetDialer{},
						doer: &MockHTTPDoer{
							FnDo: func(r *http.Request) (*http.Response, error) {
								return nil, model.Error("something_went_wrong_tor")
							},
						},
					},
				},
				wgs: []*WireGuard{
					{
						baseGate: newBaseGateID(KindWireGuard, uuid.MustParse("decade00-0000-4000-a000-000000000000")),
						dev:      &wgDev{},
						netd:     &MockNetDialer{},
						doer: &MockHTTPDoer{
							FnDo: func(r *http.Request) (*http.Response, error) {
								return nil, model.Error("something_went_wrong_wg")
							},
						},
					},
				},
			},
			exp: errors.Join(
				errors.Join(model.Error("something_went_wrong_tor")),
				errors.Join(model.Error("something_went_wrong_wg")),
			),
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			set := NewSet(&SetConfig{}, nil, tc.given.tgs, tc.given.wgs)
			if tc.given.fnPrepSet != nil {
				tc.given.fnPrepSet(set)
			}

			ctx := context.Background()
			if tc.given.fnCtx != nil {
				ctx = tc.given.fnCtx()
			}

			actual := set.Warmup(ctx)
			must.ElementsMatch(t, model.UnwrapErrs(tc.exp), model.UnwrapErrs(actual))
		})
	}
}

func TestSet_kindOrDefaultN(t *testing.T) {
	type tcGiven struct {
		cfg *SetConfig
		n   int
	}

	tests := []testCase[tcGiven, Kind]{
		{
			name: "default",
			given: tcGiven{
				cfg: &SetConfig{Default: KindTor},
				n:   69,
			},
			exp: KindTor,
		},

		{
			name: "randomise_tor",
			given: tcGiven{
				cfg: &SetConfig{
					Default:        KindWireGuard,
					RandomiseKinds: true,
				},
				n: 42,
			},
			exp: KindTor,
		},

		{
			name: "randomise_wireguard",
			given: tcGiven{
				cfg: &SetConfig{
					Default:        KindTor,
					RandomiseKinds: true,
				},
				n: 69,
			},
			exp: KindWireGuard,
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			set := NewSet(tc.given.cfg, nil, nil, nil)

			actual := set.kindOrDefaultN(tc.given.n)
			should.Equal(t, tc.exp, actual)
		})
	}
}

func TestSet_byKindReady(t *testing.T) {
	type tcGiven struct {
		drt *Direct
		tgs []*Tor
		wgs []*WireGuard

		kind      Kind
		fnPrepSet func(set *Set)
		fnCtx     func() context.Context
	}

	type tcExpected struct {
		gt  exitGateExt
		err error
	}

	tests := []testCase[tcGiven, tcExpected]{
		{
			name: "error_direct_context_cancelled",
			given: tcGiven{
				drt: func() *Direct {
					gt := newDirect(uuid.MustParse("facade00-0000-4000-a000-000000000000"), &MockNetDialer{}, &MockHTTPDoer{})
					gt.toState(stateMaintenance)

					return gt
				}(),
				kind: KindDirect,
				fnCtx: func() context.Context {
					ctx, cancel := context.WithCancel(context.Background())
					cancel()

					return ctx
				},
			},
			exp: tcExpected{
				err: context.Canceled,
			},
		},

		{
			name: "error_set_shutting",
			given: tcGiven{
				drt: func() *Direct {
					gt := newDirect(uuid.MustParse("facade00-0000-4000-a000-000000000000"), &MockNetDialer{}, &MockHTTPDoer{})
					gt.toState(stateMaintenance)

					return gt
				}(),
				kind: KindDirect,
				fnPrepSet: func(set *Set) {
					closeOrSkip(set.shutting)
				},
			},
			exp: tcExpected{
				err: ErrSetIsShutting,
			},
		},

		{
			name: "error_unknown_kind",
			given: tcGiven{
				drt:  newDirect(uuid.MustParse("facade00-0000-4000-a000-000000000000"), &MockNetDialer{}, &MockHTTPDoer{}),
				kind: Kind("something_else"),
			},
			exp: tcExpected{
				err: ErrKindUnknown,
			},
		},

		{
			name: "valid_direct",
			given: tcGiven{
				drt:  newDirect(uuid.MustParse("facade00-0000-4000-a000-000000000000"), &MockNetDialer{}, &MockHTTPDoer{}),
				kind: KindDirect,
			},
			exp: tcExpected{
				gt: newDirect(uuid.MustParse("facade00-0000-4000-a000-000000000000"), &MockNetDialer{}, &MockHTTPDoer{}),
			},
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			cfg := &SetConfig{
				RandomLoopTout:  10 * time.Second,
				RandomLoopDelay: 10 * time.Millisecond,
			}

			set := NewSet(cfg, tc.given.drt, tc.given.tgs, tc.given.wgs)
			if tc.given.fnPrepSet != nil {
				tc.given.fnPrepSet(set)
			}

			ctx := context.Background()
			if tc.given.fnCtx != nil {
				ctx = tc.given.fnCtx()
			}

			gt, err := set.byKindReady(ctx, tc.given.kind)
			must.Equal(t, tc.exp.err, err)

			if tc.exp.err != nil {
				return
			}

			should.Equal(t, tc.exp.gt, gt)
		})
	}
}

func TestSet_byKind(t *testing.T) {
	type tcGiven struct {
		drt *Direct
		tgs []*Tor
		wgs []*WireGuard

		kind Kind
	}

	type tcExpected struct {
		gt  exitGateExt
		err error
	}

	tests := []testCase[tcGiven, tcExpected]{
		{
			name: "error_unknown_kind",
			given: tcGiven{
				drt:  newDirect(uuid.MustParse("facade00-0000-4000-a000-000000000000"), &MockNetDialer{}, &MockHTTPDoer{}),
				kind: Kind("something_else"),
			},
			exp: tcExpected{
				err: ErrKindUnknown,
			},
		},

		{
			name: "valid_direct",
			given: tcGiven{
				drt:  newDirect(uuid.MustParse("facade00-0000-4000-a000-000000000000"), &MockNetDialer{}, &MockHTTPDoer{}),
				kind: KindDirect,
			},
			exp: tcExpected{
				gt: newDirect(uuid.MustParse("facade00-0000-4000-a000-000000000000"), &MockNetDialer{}, &MockHTTPDoer{}),
			},
		},

		{
			name: "error_tor_no_random_gate",
			given: tcGiven{
				drt:  newDirect(uuid.MustParse("facade00-0000-4000-a000-000000000000"), &MockNetDialer{}, &MockHTTPDoer{}),
				kind: KindTor,
			},
			exp: tcExpected{
				err: ErrNoRandomGate,
			},
		},

		{
			name: "error_wireguard_no_random_gate",
			given: tcGiven{
				drt:  newDirect(uuid.MustParse("facade00-0000-4000-a000-000000000000"), &MockNetDialer{}, &MockHTTPDoer{}),
				kind: KindWireGuard,
			},
			exp: tcExpected{
				err: ErrNoRandomGate,
			},
		},

		{
			name: "valid_tor",
			given: tcGiven{
				drt: newDirect(uuid.MustParse("facade00-0000-4000-a000-000000000000"), &MockNetDialer{}, &MockHTTPDoer{}),
				tgs: []*Tor{
					newTor(uuid.MustParse("ad0be000-0000-4000-a000-000000000000"), &torDev{}, &MockNetDialer{}, &MockHTTPDoer{}),
				},
				kind: KindTor,
			},
			exp: tcExpected{
				gt: newTor(uuid.MustParse("ad0be000-0000-4000-a000-000000000000"), &torDev{}, &MockNetDialer{}, &MockHTTPDoer{}),
			},
		},

		{
			name: "valid_wireguard",
			given: tcGiven{
				drt: newDirect(uuid.MustParse("facade00-0000-4000-a000-000000000000"), &MockNetDialer{}, &MockHTTPDoer{}),
				wgs: []*WireGuard{
					newWireGuard(uuid.MustParse("ad0be000-0000-4000-a000-000000000000"), &wgDev{}, &MockNetDialer{}, &MockHTTPDoer{}),
				},
				kind: KindWireGuard,
			},
			exp: tcExpected{
				gt: newWireGuard(uuid.MustParse("ad0be000-0000-4000-a000-000000000000"), &wgDev{}, &MockNetDialer{}, &MockHTTPDoer{}),
			},
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			set := NewSet(&SetConfig{}, tc.given.drt, tc.given.tgs, tc.given.wgs)

			gt, err := set.byKind(tc.given.kind)
			must.Equal(t, tc.exp.err, err)

			if tc.exp.err != nil {
				return
			}

			should.Equal(t, tc.exp.gt, gt)
		})
	}
}

func TestSet_forState(t *testing.T) {
	type tcGiven struct {
		drt *Direct
		tgs []*Tor
		wgs []*WireGuard

		id        uuid.UUID
		forState  state
		fnPrepSet func(set *Set)
		fnCtx     func() context.Context
	}

	type tcExpected struct {
		st      state
		hasReqs bool
		err     error
	}

	tests := []testCase[tcGiven, tcExpected]{
		{
			name: "error_direct_context_cancelled",
			given: tcGiven{
				drt: func() *Direct {
					gt := newDirect(uuid.MustParse("facade00-0000-4000-a000-000000000000"), &MockNetDialer{}, &MockHTTPDoer{})
					gt.AddReq()

					return gt
				}(),
				id:       uuid.MustParse("facade00-0000-4000-a000-000000000000"),
				forState: stateMaintenance,
				fnCtx: func() context.Context {
					ctx, cancel := context.WithCancel(context.Background())
					cancel()

					return ctx
				},
			},
			exp: tcExpected{
				st:  stateReady,
				err: context.Canceled,
			},
		},

		{
			name: "error_set_shutting",
			given: tcGiven{
				drt: func() *Direct {
					gt := newDirect(uuid.MustParse("facade00-0000-4000-a000-000000000000"), &MockNetDialer{}, &MockHTTPDoer{})
					gt.AddReq()

					return gt
				}(),
				id:       uuid.MustParse("facade00-0000-4000-a000-000000000000"),
				forState: stateMaintenance,
				fnPrepSet: func(set *Set) {
					closeOrSkip(set.shutting)
				},
			},
			exp: tcExpected{
				st:      stateMaintenance,
				hasReqs: true,
				err:     ErrSetIsShutting,
			},
		},

		{
			name: "valid_direct",
			given: tcGiven{
				drt:      newDirect(uuid.MustParse("facade00-0000-4000-a000-000000000000"), &MockNetDialer{}, &MockHTTPDoer{}),
				id:       uuid.MustParse("facade00-0000-4000-a000-000000000000"),
				forState: stateMaintenance,
			},
			exp: tcExpected{
				st: stateMaintenance,
			},
		},

		{
			name: "valid_tor",
			given: tcGiven{
				drt: newDirect(uuid.MustParse("facade00-0000-4000-a000-000000000000"), &MockNetDialer{}, &MockHTTPDoer{}),
				tgs: []*Tor{
					newTor(uuid.MustParse("ad0be000-0000-4000-a000-000000000000"), &torDev{}, &MockNetDialer{}, &MockHTTPDoer{}),
				},
				id:       uuid.MustParse("ad0be000-0000-4000-a000-000000000000"),
				forState: stateMaintenance,
			},
			exp: tcExpected{
				st: stateMaintenance,
			},
		},

		{
			name: "valid_wg",
			given: tcGiven{
				drt: newDirect(uuid.MustParse("facade00-0000-4000-a000-000000000000"), &MockNetDialer{}, &MockHTTPDoer{}),
				wgs: []*WireGuard{
					newWireGuard(uuid.MustParse("ad0be000-0000-4000-a000-000000000000"), &wgDev{}, &MockNetDialer{}, &MockHTTPDoer{}),
				},
				id:       uuid.MustParse("ad0be000-0000-4000-a000-000000000000"),
				forState: stateMaintenance,
			},
			exp: tcExpected{
				st: stateMaintenance,
			},
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			cfg := &SetConfig{
				StateLoopTout:  10 * time.Second,
				StateLoopDelay: 10 * time.Millisecond,
			}

			set := NewSet(cfg, tc.given.drt, tc.given.tgs, tc.given.wgs)
			if tc.given.fnPrepSet != nil {
				tc.given.fnPrepSet(set)
			}

			ctx := context.Background()
			if tc.given.fnCtx != nil {
				ctx = tc.given.fnCtx()
			}

			gt, err := set.byID(tc.given.id)
			must.Equal(t, nil, err)

			{
				err := set.forState(ctx, gt, tc.given.forState)
				must.Equal(t, tc.exp.err, err)
			}

			should.Equal(t, tc.exp.st, gt.getState())
			should.NotEqual(t, tc.exp.hasReqs, gt.noReqs())

			switch gt.Kind() {
			case KindDirect:
				return
			case KindTor:
				_, ok := set.tgs.Get(tc.given.id)
				should.Equal(t, false, ok)
			case KindWireGuard:
				_, ok := set.wgs.Get(tc.given.id)
				should.Equal(t, false, ok)
			}
		})
	}
}

func TestSet_toState(t *testing.T) {
	type tcGiven struct {
		drt *Direct
		tgs []*Tor
		wgs []*WireGuard

		id     uuid.UUID
		fromSt state
		toSt   state
	}

	type tcExpected struct {
		st  state
		err error
	}

	tests := []testCase[tcGiven, tcExpected]{
		{
			name: "direct_maint_to_ready",
			given: tcGiven{
				drt:    newDirect(uuid.MustParse("facade00-0000-4000-a000-000000000000"), &MockNetDialer{}, &MockHTTPDoer{}),
				id:     uuid.MustParse("facade00-0000-4000-a000-000000000000"),
				fromSt: stateMaintenance,
				toSt:   stateReady,
			},
			exp: tcExpected{
				st: stateReady,
			},
		},

		{
			name: "tor_maint_ready",
			given: tcGiven{
				drt: newDirect(uuid.MustParse("facade00-0000-4000-a000-000000000000"), &MockNetDialer{}, &MockHTTPDoer{}),
				tgs: []*Tor{
					newTor(uuid.MustParse("ad0be000-0000-4000-a000-000000000000"), &torDev{}, &MockNetDialer{}, &MockHTTPDoer{}),
				},
				id:     uuid.MustParse("ad0be000-0000-4000-a000-000000000000"),
				fromSt: stateMaintenance,
				toSt:   stateReady,
			},
			exp: tcExpected{
				st: stateReady,
			},
		},

		{
			name: "wg_maint_ready",
			given: tcGiven{
				drt: newDirect(uuid.MustParse("facade00-0000-4000-a000-000000000000"), &MockNetDialer{}, &MockHTTPDoer{}),
				wgs: []*WireGuard{
					newWireGuard(uuid.MustParse("ad0be000-0000-4000-a000-000000000000"), &wgDev{}, &MockNetDialer{}, &MockHTTPDoer{}),
				},
				id:     uuid.MustParse("ad0be000-0000-4000-a000-000000000000"),
				fromSt: stateMaintenance,
				toSt:   stateReady,
			},
			exp: tcExpected{
				st: stateReady,
			},
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			cfg := &SetConfig{
				StateLoopTout:  10 * time.Second,
				StateLoopDelay: 10 * time.Millisecond,
			}

			set := NewSet(cfg, tc.given.drt, tc.given.tgs, tc.given.wgs)

			ctx := context.Background()

			gt, err := set.byID(tc.given.id)
			must.Equal(t, nil, err)

			{
				err := set.forState(ctx, gt, tc.given.fromSt)
				must.Equal(t, nil, err)
			}

			actual := set.toState(gt, tc.given.toSt)
			must.Equal(t, tc.exp.err, actual)

			if tc.exp.err != nil {
				return
			}

			gt2, err := set.byID(tc.given.id)
			must.Equal(t, nil, err)

			should.Equal(t, tc.exp.st, gt2.getState())
			should.Equal(t, true, gt2.noReqs())
		})
	}
}

func TestSet_isShutting(t *testing.T) {
	tests := []testCase[*Set, bool]{
		{
			name:  "false_invalid",
			given: &Set{},
		},

		{
			name:  "false",
			given: &Set{shutting: make(chan struct{})},
		},

		{
			name: "true",
			given: &Set{
				shutting: func() chan struct{} {
					out := make(chan struct{})
					close(out)
					return out
				}(),
			},
			exp: true,
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			should.Equal(t, tc.exp, tc.given.isShutting())
		})
	}
}

func TestSetConfig_BaseCtx(t *testing.T) {
	tests := []testCase[*SetConfig, context.Context]{
		{
			name:  "default",
			given: &SetConfig{},
			exp:   context.Background(),
		},

		{
			name:  "configured",
			given: &SetConfig{FnBaseCtx: func() context.Context { return context.TODO() }},
			exp:   context.TODO(),
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			should.Equal(t, tc.exp, tc.given.BaseCtx())
		})
	}
}

func TestShutdownList(t *testing.T) {
	type tcGiven struct {
		list  []*Tor
		fnCtx func() context.Context
	}

	tests := []testCase[tcGiven, error]{
		{
			name: "empty",
			given: tcGiven{
				list: []*Tor{},
			},
		},

		{
			name: "error_single_context_canceled",
			given: tcGiven{
				list: []*Tor{
					{
						baseGate:   newBaseGateID(KindTor, uuid.MustParse("facade00-0000-4000-a000-000000000000")),
						refreshing: &struct{ value uint32 }{},
						dev: &torDev{
							fnClose: func() error {
								tmr := time.NewTimer(20 * time.Second)
								defer func() {
									if !tmr.Stop() {
										<-tmr.C
									}
								}()

								<-tmr.C

								return model.Error("unexpected_close")
							},
						},
						netd: &MockNetDialer{},
						doer: &MockHTTPDoer{},
					},
				},
				fnCtx: func() context.Context {
					ctx, cancel := context.WithCancel(context.Background())
					cancel()

					return ctx
				},
			},
			exp: errors.Join(context.Canceled),
		},

		{
			name: "error_single",
			given: tcGiven{
				list: []*Tor{
					{
						baseGate:   newBaseGateID(KindTor, uuid.MustParse("facade00-0000-4000-a000-000000000000")),
						refreshing: &struct{ value uint32 }{},
						dev: &torDev{
							fnClose: func() error {
								return model.Error("something_went_wrong")
							},
						},
						netd: &MockNetDialer{},
						doer: &MockHTTPDoer{},
					},
				},
			},
			exp: errors.Join(model.Error("something_went_wrong")),
		},

		{
			name: "success_single",
			given: tcGiven{
				list: []*Tor{
					{
						baseGate:   newBaseGateID(KindTor, uuid.MustParse("facade00-0000-4000-a000-000000000000")),
						refreshing: &struct{ value uint32 }{},
						dev:        &torDev{},
						netd:       &MockNetDialer{},
						doer:       &MockHTTPDoer{},
					},
				},
			},
		},

		{
			name: "error_multiple_context_canceled",
			given: tcGiven{
				list: []*Tor{
					{
						baseGate:   newBaseGateID(KindTor, uuid.MustParse("facade00-0000-4000-a000-000000000000")),
						refreshing: &struct{ value uint32 }{},
						dev: &torDev{
							fnClose: func() error {
								tmr := time.NewTimer(20 * time.Second)
								defer func() {
									if !tmr.Stop() {
										<-tmr.C
									}
								}()

								<-tmr.C

								return model.Error("unexpected_close_01")
							},
						},
						netd: &MockNetDialer{},
						doer: &MockHTTPDoer{},
					},

					{
						baseGate:   newBaseGateID(KindTor, uuid.MustParse("decade00-0000-4000-a000-000000000000")),
						refreshing: &struct{ value uint32 }{},
						dev: &torDev{
							fnClose: func() error {
								tmr := time.NewTimer(10 * time.Second)
								defer func() {
									if !tmr.Stop() {
										<-tmr.C
									}
								}()

								<-tmr.C

								return model.Error("unexpected_close_02")
							},
						},
						netd: &MockNetDialer{},
						doer: &MockHTTPDoer{},
					},
				},
				fnCtx: func() context.Context {
					ctx, cancel := context.WithCancel(context.Background())
					cancel()

					return ctx
				},
			},
			exp: errors.Join(context.Canceled, context.Canceled),
		},

		{
			name: "error_multiple",
			given: tcGiven{
				list: []*Tor{
					{
						baseGate:   newBaseGateID(KindTor, uuid.MustParse("facade00-0000-4000-a000-000000000000")),
						refreshing: &struct{ value uint32 }{},
						dev: &torDev{
							fnClose: func() error {
								return model.Error("something_went_wrong")
							},
						},
						netd: &MockNetDialer{},
						doer: &MockHTTPDoer{},
					},

					{
						baseGate:   newBaseGateID(KindTor, uuid.MustParse("decade00-0000-4000-a000-000000000000")),
						refreshing: &struct{ value uint32 }{},
						dev: &torDev{
							fnClose: func() error {
								return model.Error("something_went_wrong")
							},
						},
						netd: &MockNetDialer{},
						doer: &MockHTTPDoer{},
					},
				},
			},
			// The order of the errors is not important.
			exp: errors.Join(model.Error("something_went_wrong"), model.Error("something_went_wrong")),
		},

		{
			name: "success_multiple",
			given: tcGiven{
				list: []*Tor{
					{
						baseGate:   newBaseGateID(KindTor, uuid.MustParse("facade00-0000-4000-a000-000000000000")),
						refreshing: &struct{ value uint32 }{},
						dev:        &torDev{},
						netd:       &MockNetDialer{},
						doer:       &MockHTTPDoer{},
					},

					{
						baseGate:   newBaseGateID(KindTor, uuid.MustParse("decade00-0000-4000-a000-000000000000")),
						refreshing: &struct{ value uint32 }{},
						dev:        &torDev{},
						netd:       &MockNetDialer{},
						doer:       &MockHTTPDoer{},
					},
				},
			},
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			if tc.given.fnCtx != nil {
				ctx = tc.given.fnCtx()
			}

			actual := ShutdownList(ctx, tc.given.list)
			must.Equal(t, tc.exp, actual)
		})
	}
}

func TestWarmupList(t *testing.T) {
	type tcGiven struct {
		list  []*Tor
		fnCtx func() context.Context
	}

	type tcExpected struct {
		n   int
		err error
	}

	tests := []testCase[tcGiven, tcExpected]{
		{
			name: "empty",
			given: tcGiven{
				list: []*Tor{},
			},
		},

		{
			name: "error_single_context_canceled",
			given: tcGiven{
				list: []*Tor{
					{
						baseGate:   newBaseGateID(KindTor, uuid.MustParse("facade00-0000-4000-a000-000000000000")),
						refreshing: &struct{ value uint32 }{},
						dev:        &torDev{},
						netd:       &MockNetDialer{},
						doer: &MockHTTPDoer{
							FnDo: func(r *http.Request) (*http.Response, error) {
								tmr := time.NewTimer(20 * time.Second)
								defer func() {
									if !tmr.Stop() {
										<-tmr.C
									}
								}()

								<-tmr.C

								return nil, model.Error("unexpected_do")
							},
						},
					},
				},
				fnCtx: func() context.Context {
					ctx, cancel := context.WithCancel(context.Background())
					cancel()

					return ctx
				},
			},
			exp: tcExpected{
				err: errors.Join(context.Canceled),
			},
		},

		{
			name: "error_single",
			given: tcGiven{
				list: []*Tor{
					{
						baseGate:   newBaseGateID(KindTor, uuid.MustParse("facade00-0000-4000-a000-000000000000")),
						refreshing: &struct{ value uint32 }{},
						dev:        &torDev{},
						netd:       &MockNetDialer{},
						doer: &MockHTTPDoer{
							FnDo: func(r *http.Request) (*http.Response, error) {
								return nil, model.Error("something_went_wrong")
							},
						},
					},
				},
			},
			exp: tcExpected{
				err: errors.Join(model.Error("something_went_wrong")),
			},
		},

		{
			name: "success_single",
			given: tcGiven{
				list: []*Tor{
					{
						baseGate:   newBaseGateID(KindTor, uuid.MustParse("facade00-0000-4000-a000-000000000000")),
						refreshing: &struct{ value uint32 }{},
						dev:        &torDev{},
						netd:       &MockNetDialer{},
						doer:       &MockHTTPDoer{},
					},
				},
			},
			exp: tcExpected{
				n: 1,
			},
		},

		{
			name: "error_multiple_context_canceled",
			given: tcGiven{
				list: []*Tor{
					{
						baseGate:   newBaseGateID(KindTor, uuid.MustParse("facade00-0000-4000-a000-000000000000")),
						refreshing: &struct{ value uint32 }{},
						dev:        &torDev{},
						netd:       &MockNetDialer{},
						doer: &MockHTTPDoer{
							FnDo: func(r *http.Request) (*http.Response, error) {
								tmr := time.NewTimer(20 * time.Second)
								defer func() {
									if !tmr.Stop() {
										<-tmr.C
									}
								}()

								<-tmr.C

								return nil, model.Error("unexpected_do_01")
							},
						},
					},

					{
						baseGate:   newBaseGateID(KindTor, uuid.MustParse("decade00-0000-4000-a000-000000000000")),
						refreshing: &struct{ value uint32 }{},
						dev:        &torDev{},
						netd:       &MockNetDialer{},
						doer: &MockHTTPDoer{
							FnDo: func(r *http.Request) (*http.Response, error) {
								tmr := time.NewTimer(15 * time.Second)
								defer func() {
									if !tmr.Stop() {
										<-tmr.C
									}
								}()

								<-tmr.C

								return nil, model.Error("unexpected_do_02")
							},
						},
					},
				},
				fnCtx: func() context.Context {
					ctx, cancel := context.WithCancel(context.Background())
					cancel()

					return ctx
				},
			},
			exp: tcExpected{
				err: errors.Join(context.Canceled, context.Canceled),
			},
		},

		{
			name: "error_multiple",
			given: tcGiven{
				list: []*Tor{
					{
						baseGate:   newBaseGateID(KindTor, uuid.MustParse("facade00-0000-4000-a000-000000000000")),
						refreshing: &struct{ value uint32 }{},
						dev:        &torDev{},
						netd:       &MockNetDialer{},
						doer: &MockHTTPDoer{
							FnDo: func(r *http.Request) (*http.Response, error) {
								return nil, model.Error("something_went_wrong")
							},
						},
					},

					{
						baseGate:   newBaseGateID(KindTor, uuid.MustParse("decade00-0000-4000-a000-000000000000")),
						refreshing: &struct{ value uint32 }{},
						dev:        &torDev{},
						netd:       &MockNetDialer{},
						doer: &MockHTTPDoer{
							FnDo: func(r *http.Request) (*http.Response, error) {
								return nil, model.Error("something_went_wrong")
							},
						},
					},
				},
			},
			// The order of the errors is not important.
			exp: tcExpected{
				err: errors.Join(model.Error("something_went_wrong"), model.Error("something_went_wrong")),
			},
		},

		{
			name: "success_multiple",
			given: tcGiven{
				list: []*Tor{
					{
						baseGate:   newBaseGateID(KindTor, uuid.MustParse("facade00-0000-4000-a000-000000000000")),
						refreshing: &struct{ value uint32 }{},
						dev:        &torDev{},
						netd:       &MockNetDialer{},
						doer:       &MockHTTPDoer{},
					},

					{
						baseGate:   newBaseGateID(KindTor, uuid.MustParse("decade00-0000-4000-a000-000000000000")),
						refreshing: &struct{ value uint32 }{},
						dev:        &torDev{},
						netd:       &MockNetDialer{},
						doer:       &MockHTTPDoer{},
					},
				},
			},
			exp: tcExpected{
				n: 2,
			},
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			if tc.given.fnCtx != nil {
				ctx = tc.given.fnCtx()
			}

			actual, err := WarmupList(ctx, tc.given.list)
			must.Equal(t, tc.exp.err, err)

			if tc.exp.err != nil {
				return
			}

			should.Equal(t, tc.exp.n, len(actual))

			for j := range actual {
				should.Equal(t, true, actual[j] > 0)
			}
		})
	}
}

func TestRefreshOne(t *testing.T) {
	type tcGiven struct {
		tor   *Tor
		fnCtx func() context.Context
	}

	type tcExpected struct {
		err error
	}

	tests := []testCase[tcGiven, tcExpected]{
		{
			name: "error_context_canceled",
			given: tcGiven{
				tor: &Tor{
					baseGate:   newBaseGateID(KindTor, uuid.MustParse("facade00-0000-4000-a000-000000000000")),
					refreshing: &struct{ value uint32 }{},
					dev: &torDev{
						fnSignal: func(s string) error {
							tmr := time.NewTimer(20 * time.Second)
							defer func() {
								if !tmr.Stop() {
									<-tmr.C
								}
							}()

							<-tmr.C

							return model.Error("unexpected_signal")
						},
					},
					netd: &MockNetDialer{},
					doer: &MockHTTPDoer{},
				},
				fnCtx: func() context.Context {
					ctx, cancel := context.WithCancel(context.Background())
					cancel()

					return ctx
				},
			},
			exp: tcExpected{
				err: context.Canceled,
			},
		},

		{
			name: "error_refresh",
			given: tcGiven{
				tor: &Tor{
					baseGate:   newBaseGateID(KindTor, uuid.MustParse("facade00-0000-4000-a000-000000000000")),
					refreshing: &struct{ value uint32 }{},
					dev: &torDev{
						fnSignal: func(s string) error {
							return model.Error("something_went_wrong")
						},
					},
					netd: &MockNetDialer{},
					doer: &MockHTTPDoer{},
				},
			},
			exp: tcExpected{
				err: model.Error("something_went_wrong"),
			},
		},

		{
			name: "success",
			given: tcGiven{
				tor: &Tor{
					baseGate:   newBaseGateID(KindTor, uuid.MustParse("facade00-0000-4000-a000-000000000000")),
					refreshing: &struct{ value uint32 }{},
					dev:        &torDev{},
					netd:       &MockNetDialer{},
					doer:       &MockHTTPDoer{},
				},
			},
			exp: tcExpected{},
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			if tc.given.fnCtx != nil {
				ctx = tc.given.fnCtx()
			}

			actual := refreshOne(ctx, tc.given.tor)
			must.Equal(t, tc.exp.err, actual)
		})
	}
}

func TestShutdownOne(t *testing.T) {
	type tcGiven struct {
		gate  interface{ close() error }
		fnCtx func() context.Context
	}

	tests := []testCase[tcGiven, error]{
		{
			name: "error_context_canceled",
			given: tcGiven{
				gate: &Tor{
					baseGate:   newBaseGateID(KindTor, uuid.MustParse("facade00-0000-4000-a000-000000000000")),
					refreshing: &struct{ value uint32 }{},
					dev: &torDev{
						fnClose: func() error {
							tmr := time.NewTimer(20 * time.Second)
							defer func() {
								if !tmr.Stop() {
									<-tmr.C
								}
							}()

							<-tmr.C

							return model.Error("unexpected_close")
						},
					},
					netd: &MockNetDialer{},
					doer: &MockHTTPDoer{},
				},
				fnCtx: func() context.Context {
					ctx, cancel := context.WithCancel(context.Background())
					cancel()

					return ctx
				},
			},
			exp: context.Canceled,
		},

		{
			name: "error_close",
			given: tcGiven{
				gate: &Tor{
					baseGate:   newBaseGateID(KindTor, uuid.MustParse("facade00-0000-4000-a000-000000000000")),
					refreshing: &struct{ value uint32 }{},
					dev: &torDev{
						fnClose: func() error {
							return model.Error("something_went_wrong")
						},
					},
					netd: &MockNetDialer{},
					doer: &MockHTTPDoer{},
				},
			},
			exp: model.Error("something_went_wrong"),
		},

		{
			name: "success",
			given: tcGiven{
				gate: &Tor{
					baseGate:   newBaseGateID(KindTor, uuid.MustParse("facade00-0000-4000-a000-000000000000")),
					refreshing: &struct{ value uint32 }{},
					dev:        &torDev{},
					netd:       &MockNetDialer{},
					doer:       &MockHTTPDoer{},
				},
			},
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			if tc.given.fnCtx != nil {
				ctx = tc.given.fnCtx()
			}

			actual := shutdownOne(ctx, tc.given.gate)
			must.Equal(t, tc.exp, actual)
		})
	}
}

func TestWarmupOne(t *testing.T) {
	type tcGiven struct {
		gate interface {
			warmup(context.Context) (time.Duration, error)
		}
		fnCtx func() context.Context
	}

	tests := []testCase[tcGiven, error]{
		{
			name: "error_context_canceled",
			given: tcGiven{
				gate: &Tor{
					baseGate:   newBaseGateID(KindTor, uuid.MustParse("facade00-0000-4000-a000-000000000000")),
					refreshing: &struct{ value uint32 }{},
					dev:        &torDev{},
					netd:       &MockNetDialer{},
					doer: &MockHTTPDoer{
						FnDo: func(r *http.Request) (*http.Response, error) {
							tmr := time.NewTimer(20 * time.Second)
							defer func() {
								if !tmr.Stop() {
									<-tmr.C
								}
							}()

							<-tmr.C

							return nil, model.Error("unexpected_do")
						},
					},
				},
				fnCtx: func() context.Context {
					ctx, cancel := context.WithCancel(context.Background())
					cancel()

					return ctx
				},
			},
			exp: context.Canceled,
		},

		{
			name: "error_do",
			given: tcGiven{
				gate: &Tor{
					baseGate:   newBaseGateID(KindTor, uuid.MustParse("facade00-0000-4000-a000-000000000000")),
					refreshing: &struct{ value uint32 }{},
					dev:        &torDev{},
					netd:       &MockNetDialer{},
					doer: &MockHTTPDoer{
						FnDo: func(r *http.Request) (*http.Response, error) {
							return nil, model.Error("something_went_wrong")
						},
					},
				},
			},
			exp: model.Error("something_went_wrong"),
		},

		{
			name: "success",
			given: tcGiven{
				gate: &Tor{
					baseGate:   newBaseGateID(KindTor, uuid.MustParse("facade00-0000-4000-a000-000000000000")),
					refreshing: &struct{ value uint32 }{},
					dev:        &torDev{},
					netd:       &MockNetDialer{},
					doer:       &MockHTTPDoer{},
				},
			},
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			if tc.given.fnCtx != nil {
				ctx = tc.given.fnCtx()
			}

			actual := warmupOne(ctx, tc.given.gate)
			must.Equal(t, tc.exp, actual.err)

			if tc.exp != nil {
				return
			}

			should.Equal(t, true, actual.latency > 0)
		})
	}
}

func TestWarmupDoer(t *testing.T) {
	type tcGiven struct {
		doer  httpDoer
		fnCtx func() context.Context
	}

	tests := []testCase[tcGiven, error]{
		{
			name: "error_nil_ctx",
			given: tcGiven{
				doer: &MockHTTPDoer{
					FnDo: func(r *http.Request) (*http.Response, error) {
						return nil, model.Error("unexpected_do")
					},
				},
				fnCtx: func() context.Context { return nil },
			},
			exp: errors.New("net/http: nil Context"),
		},

		{
			name: "error_do",
			given: tcGiven{
				doer: &MockHTTPDoer{
					FnDo: func(r *http.Request) (*http.Response, error) {
						return nil, model.Error("something_went_wrong")
					},
				},
			},
			exp: model.Error("something_went_wrong"),
		},

		{
			name: "error_non_200",
			given: tcGiven{
				doer: &MockHTTPDoer{
					FnDo: func(r *http.Request) (*http.Response, error) {
						result := NewMockResponse()
						result.Status = "500 Internal Server Error"
						result.StatusCode = http.StatusInternalServerError

						return result, nil
					},
				},
			},
			exp: ErrWarmupBadResponse,
		},

		{
			name: "success",
			given: tcGiven{
				doer: &MockHTTPDoer{},
			},
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			if tc.given.fnCtx != nil {
				ctx = tc.given.fnCtx()
			}

			actual, err := warmupDoer(ctx, tc.given.doer)
			must.Equal(t, tc.exp, err)

			if tc.exp != nil {
				return
			}

			should.Equal(t, true, actual > 0)
		})
	}
}

func TestBaseGate(t *testing.T) {
	gt := newBaseGateID(KindTor, uuid.MustParse("decade00-0000-4000-a000-000000000000"))

	t.Run("kind", func(t *testing.T) {
		should.Equal(t, KindTor, gt.Kind())
	})

	t.Run("id", func(t *testing.T) {
		should.Equal(t, uuid.MustParse("decade00-0000-4000-a000-000000000000"), gt.ID())
	})

	t.Run("add_req", func(t *testing.T) {
		gt.AddReq()
		should.Equal(t, uint64(1), gt.state.reqNum())
	})

	t.Run("no_reqs_false", func(t *testing.T) {
		should.Equal(t, false, gt.noReqs())
	})

	t.Run("did_req", func(t *testing.T) {
		gt.DidReq()
		should.Equal(t, uint64(0), gt.state.reqNum())
	})

	t.Run("no_reqs_true", func(t *testing.T) {
		should.Equal(t, true, gt.noReqs())
	})

	t.Run("reset_reqs", func(t *testing.T) {
		gt.AddReq()
		should.Equal(t, uint64(1), gt.state.reqNum())

		gt.resetReqs()
		should.Equal(t, uint64(0), gt.state.reqNum())
	})

	t.Run("get_state", func(t *testing.T) {
		should.Equal(t, stateReady, gt.getState())
	})
}

func TestBaseGate_isReady(t *testing.T) {
	tests := []testCase[*baseGate, bool]{
		{
			name:  "true_ready",
			given: newBaseGateID(KindTor, uuid.MustParse("decade00-0000-4000-a000-000000000000")),
			exp:   true,
		},

		{
			name: "false_maint",
			given: func() *baseGate {
				gt := newBaseGateID(KindTor, uuid.MustParse("decade00-0000-4000-a000-000000000000"))
				gt.state.toMaint()

				return gt
			}(),
		},

		{
			name: "false_closed",
			given: func() *baseGate {
				gt := newBaseGateID(KindTor, uuid.MustParse("decade00-0000-4000-a000-000000000000"))
				gt.state.toClosed()

				return gt
			}(),
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			should.Equal(t, tc.exp, tc.given.isReady())
		})
	}
}

func TestBaseGate_toState(t *testing.T) {
	type tcGiven struct {
		gt *baseGate
		st state
	}

	tests := []testCase[tcGiven, state]{
		{
			name: "maint_to_ready",
			given: tcGiven{
				gt: func() *baseGate {
					gt := newBaseGateID(KindTor, uuid.MustParse("decade00-0000-4000-a000-000000000000"))
					gt.state.toMaint()

					return gt
				}(),
				st: stateReady,
			},
			exp: stateReady,
		},

		{
			name: "ready_to_maint",
			given: tcGiven{
				gt: newBaseGateID(KindTor, uuid.MustParse("decade00-0000-4000-a000-000000000000")),
				st: stateMaintenance,
			},
			exp: stateMaintenance,
		},

		{
			name: "ready_to_closed",
			given: tcGiven{
				gt: newBaseGateID(KindTor, uuid.MustParse("decade00-0000-4000-a000-000000000000")),
				st: stateClosed,
			},
			exp: stateClosed,
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			tc.given.gt.toState(tc.given.st)
			should.Equal(t, tc.exp, tc.given.gt.getState())
		})
	}
}

func TestGateState(t *testing.T) {
	t.Run("states", func(t *testing.T) {
		st := &gateState{
			state: &struct{ value uint32 }{value: 1},
			mu:    &sync.Mutex{},
		}

		t.Run("to_ready", func(t *testing.T) {
			st.toReady()
			should.Equal(t, stateReady, st.getState())
		})

		t.Run("to_maint", func(t *testing.T) {
			st.toMaint()
			should.Equal(t, stateMaintenance, st.getState())
		})

		t.Run("to_closed", func(t *testing.T) {
			st.toClosed()
			should.Equal(t, stateClosed, st.getState())
		})

		t.Run("stays_in_closed", func(t *testing.T) {
			st.toReady()
			should.Equal(t, stateClosed, st.getState())
		})
	})

	t.Run("counters", func(t *testing.T) {
		st := newGateState()

		t.Run("no_reqs", func(t *testing.T) {
			should.Equal(t, true, st.noReqs())
		})

		t.Run("add_req", func(t *testing.T) {
			st.addReq()
			should.Equal(t, uint64(1), st.reqNum())
		})

		t.Run("no_reqs_false", func(t *testing.T) {
			should.Equal(t, false, st.noReqs())
		})

		t.Run("req_num", func(t *testing.T) {
			should.Equal(t, uint64(1), st.reqNum())
		})

		t.Run("did_req", func(t *testing.T) {
			st.didReq()
			should.Equal(t, uint64(0), st.reqNum())
		})

		t.Run("no_reqs_true", func(t *testing.T) {
			should.Equal(t, true, st.noReqs())
		})

		t.Run("reset_reqs", func(t *testing.T) {
			st.addReq()
			should.Equal(t, uint64(1), st.reqNum())

			st.resetReqs()
			should.Equal(t, uint64(0), st.reqNum())

			should.Equal(t, true, st.noReqs())
		})

		t.Run("to_closed", func(t *testing.T) {
			st.toClosed()
			should.Equal(t, stateClosed, st.getState())
		})
	})
}

func TestCloseOrSkip(t *testing.T) {
	type tcGiven struct {
		fnCn func() chan struct{}
	}

	tests := []testCase[tcGiven, struct{}]{
		{
			name: "nil_skip",
			given: tcGiven{
				fnCn: func() chan struct{} { return nil },
			},
		},

		{
			name: "closed_skip",
			given: tcGiven{
				fnCn: func() chan struct{} {
					out := make(chan struct{})
					close(out)

					return out
				},
			},
		},

		{
			name: "open_close",
			given: tcGiven{
				fnCn: func() chan struct{} {
					out := make(chan struct{})

					return out
				},
			},
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			defer func() { must.Equal(t, nil, recover()) }()

			cn := tc.given.fnCn()
			closeOrSkip(cn)

			if cn == nil {
				return
			}

			_, ok := <-cn
			should.Equal(t, false, ok)
		})
	}
}

func TestCollectErrs(t *testing.T) {
	type tcGiven struct {
		fnErrCn func() chan error
	}

	tests := []testCase[tcGiven, []error]{
		{
			name: "empty_channel",
			given: tcGiven{
				fnErrCn: func() chan error {
					out := make(chan error)
					close(out)

					return out
				},
			},
		},

		// This is here for documentation only.
		// This case is illegal, and will block forever.
		//
		// {
		// 	name: "empty_open_channel",
		// 	given: tcGiven{
		// 		fnErrCn: func() chan error {
		// 			return make(chan error)
		// 		},
		// 	},
		// },

		{
			name: "valid",
			given: tcGiven{
				fnErrCn: func() chan error {
					out := make(chan error, 4)

					for i := 0; i < 4; i++ {
						out <- model.Error("something_went_wrong")
					}

					close(out)

					return out
				},
			},
			exp: []error{
				model.Error("something_went_wrong"),
				model.Error("something_went_wrong"),
				model.Error("something_went_wrong"),
				model.Error("something_went_wrong"),
			},
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			actual := collectErrs(tc.given.fnErrCn())
			should.Equal(t, tc.exp, actual)
		})
	}
}

func TestPickRandomKind(t *testing.T) {
	tests := []testCase[int, Kind]{
		{
			name: "zero_tor",
			exp:  KindTor,
		},

		{
			name:  "odd_wireguard",
			given: 1,
			exp:   KindWireGuard,
		},

		{
			name:  "even_tor",
			given: 2,
			exp:   KindTor,
		},

		{
			name:  "negative_odd_wireguard",
			given: -3,
			exp:   KindWireGuard,
		},

		{
			name:  "negative_even_tor",
			given: -8,
			exp:   KindTor,
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			should.Equal(t, tc.exp, pickRandomKind(tc.given))
		})
	}
}
