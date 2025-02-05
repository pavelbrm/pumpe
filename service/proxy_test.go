package service

import (
	"context"
	"testing"

	"github.com/google/uuid"
	should "github.com/stretchr/testify/assert"
	must "github.com/stretchr/testify/require"

	"github.com/pavelbrm/pumpe/gate"
	"github.com/pavelbrm/pumpe/model"
)

func TestProxy_Gates(t *testing.T) {
	type tcExpected struct {
		result *struct{ Direct, Tor, WireGuard []uuid.UUID }
		err    error
	}

	tests := []testCase[*mockGateSetProxy, tcExpected]{
		{
			name: "error_direct",
			given: &mockGateSetProxy{
				fnGateIDs: func(kind gate.Kind) ([]uuid.UUID, error) {
					if kind == gate.KindDirect {
						return nil, model.Error("something_went_wrong")
					}

					return nil, model.Error("unexpected_gate_ids")
				},
			},
			exp: tcExpected{
				err: model.Error("something_went_wrong"),
			},
		},

		{
			name: "error_tor",
			given: &mockGateSetProxy{
				fnGateIDs: func(kind gate.Kind) ([]uuid.UUID, error) {
					switch kind {
					case gate.KindDirect:
						return nil, nil
					case gate.KindTor:
						return nil, model.Error("something_went_wrong")
					default:
						return nil, model.Error("unexpected_gate_ids")
					}
				},
			},
			exp: tcExpected{
				err: model.Error("something_went_wrong"),
			},
		},

		{
			name: "error_wireguard",
			given: &mockGateSetProxy{
				fnGateIDs: func(kind gate.Kind) ([]uuid.UUID, error) {
					switch kind {
					case gate.KindDirect:
						return nil, nil
					case gate.KindTor:
						return nil, nil
					case gate.KindWireGuard:
						return nil, model.Error("something_went_wrong")
					default:
						return nil, model.Error("unexpected_gate_ids")
					}
				},
			},
			exp: tcExpected{
				err: model.Error("something_went_wrong"),
			},
		},

		{
			name:  "valid_empty",
			given: &mockGateSetProxy{},
			exp: tcExpected{
				result: &struct {
					Direct    []uuid.UUID
					Tor       []uuid.UUID
					WireGuard []uuid.UUID
				}{},
			},
		},

		{
			name: "valid_data",
			given: &mockGateSetProxy{
				fnGateIDs: func(kind gate.Kind) ([]uuid.UUID, error) {
					switch kind {
					case gate.KindDirect:
						return []uuid.UUID{uuid.MustParse("f100ded0-0000-4000-a000-000000000000")}, nil

					case gate.KindTor:
						result := []uuid.UUID{
							uuid.MustParse("5ca1ab1e-0000-4000-a000-000000000000"),
							uuid.MustParse("c0c0a000-0000-4000-a000-000000000000"),
						}

						return result, nil

					case gate.KindWireGuard:
						result := []uuid.UUID{
							uuid.MustParse("ad0be000-0000-4000-a000-000000000000"),
							uuid.MustParse("decade00-0000-4000-a000-000000000000"),
						}

						return result, nil

					default:
						return nil, model.Error("unexpected_gate_ids")
					}
				},
			},
			exp: tcExpected{
				result: &struct {
					Direct    []uuid.UUID
					Tor       []uuid.UUID
					WireGuard []uuid.UUID
				}{
					Direct: []uuid.UUID{uuid.MustParse("f100ded0-0000-4000-a000-000000000000")},
					Tor: []uuid.UUID{
						uuid.MustParse("5ca1ab1e-0000-4000-a000-000000000000"),
						uuid.MustParse("c0c0a000-0000-4000-a000-000000000000"),
					},
					WireGuard: []uuid.UUID{
						uuid.MustParse("ad0be000-0000-4000-a000-000000000000"),
						uuid.MustParse("decade00-0000-4000-a000-000000000000"),
					},
				},
			},
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			svc := NewProxy(tc.given)

			ctx := context.Background()

			actual, err := svc.Gates(ctx)
			must.Equal(t, tc.exp.err, err)

			if tc.exp.err != nil {
				return
			}

			should.Equal(t, tc.exp.result, actual)
		})
	}
}

func TestProxy_Create(t *testing.T) {
	type tcGiven struct {
		set  *mockGateSetProxy
		kind gate.Kind
	}

	type tcExpected struct {
		id  uuid.UUID
		err error
	}

	tests := []testCase[tcGiven, tcExpected]{
		{
			name: "error",
			given: tcGiven{
				set: &mockGateSetProxy{
					fnNew: func(ctx context.Context, kind gate.Kind) (uuid.UUID, error) {
						return uuid.Nil, model.Error("something_went_wrong")
					},
				},
				kind: gate.KindTor,
			},
			exp: tcExpected{
				err: model.Error("something_went_wrong"),
			},
		},

		{
			name: "valid",
			given: tcGiven{
				set: &mockGateSetProxy{
					fnNew: func(ctx context.Context, kind gate.Kind) (uuid.UUID, error) {
						if kind != gate.KindTor {
							return uuid.Nil, model.Error("unexpected_kind")
						}

						return uuid.MustParse("5ca1ab1e-0000-4000-a000-000000000000"), nil
					},
				},
				kind: gate.KindTor,
			},
			exp: tcExpected{
				id: uuid.MustParse("5ca1ab1e-0000-4000-a000-000000000000"),
			},
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			svc := NewProxy(tc.given.set)

			ctx := context.Background()

			actual, err := svc.Create(ctx, tc.given.kind)
			must.Equal(t, tc.exp.err, err)

			if tc.exp.err != nil {
				return
			}

			should.Equal(t, tc.exp.id, actual)
		})
	}
}

func TestProxy_Refresh(t *testing.T) {
	type tcGiven struct {
		set *mockGateSetProxy
		id  uuid.UUID
	}

	tests := []testCase[tcGiven, error]{
		{
			name: "error",
			given: tcGiven{
				set: &mockGateSetProxy{
					fnRefreshOne: func(ctx context.Context, id uuid.UUID) error {
						return model.Error("something_went_wrong")
					},
				},
				id: uuid.MustParse("5ca1ab1e-0000-4000-a000-000000000000"),
			},
			exp: model.Error("something_went_wrong"),
		},

		{
			name: "valid",
			given: tcGiven{
				set: &mockGateSetProxy{
					fnRefreshOne: func(ctx context.Context, id uuid.UUID) error {
						if id != uuid.MustParse("5ca1ab1e-0000-4000-a000-000000000000") {
							return model.Error("unexpected_id")
						}

						return nil
					},
				},
				id: uuid.MustParse("5ca1ab1e-0000-4000-a000-000000000000"),
			},
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			svc := NewProxy(tc.given.set)

			ctx := context.Background()

			actual := svc.Refresh(ctx, tc.given.id)
			must.Equal(t, tc.exp, actual)
		})
	}
}

func TestProxy_Stop(t *testing.T) {
	type tcGiven struct {
		set *mockGateSetProxy
		id  uuid.UUID
	}

	tests := []testCase[tcGiven, error]{
		{
			name: "error",
			given: tcGiven{
				set: &mockGateSetProxy{
					fnCloseOne: func(ctx context.Context, id uuid.UUID) error {
						return model.Error("something_went_wrong")
					},
				},
				id: uuid.MustParse("5ca1ab1e-0000-4000-a000-000000000000"),
			},
			exp: model.Error("something_went_wrong"),
		},

		{
			name: "valid",
			given: tcGiven{
				set: &mockGateSetProxy{
					fnCloseOne: func(ctx context.Context, id uuid.UUID) error {
						if id != uuid.MustParse("5ca1ab1e-0000-4000-a000-000000000000") {
							return model.Error("unexpected_id")
						}

						return nil
					},
				},
				id: uuid.MustParse("5ca1ab1e-0000-4000-a000-000000000000"),
			},
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			svc := NewProxy(tc.given.set)

			ctx := context.Background()

			actual := svc.Stop(ctx, tc.given.id)
			must.Equal(t, tc.exp, actual)
		})
	}
}
