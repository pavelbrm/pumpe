package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/julienschmidt/httprouter"
	should "github.com/stretchr/testify/assert"
	must "github.com/stretchr/testify/require"

	"github.com/pavelbrm/pumpe/gate"
	"github.com/pavelbrm/pumpe/model"
)

func TestProxy_List(t *testing.T) {
	type tcGiven struct {
		svc *mockProxySvc
	}

	type tcExpected struct {
		code int
		data *struct {
			Direct    []uuid.UUID `json:"direct"`
			Tor       []uuid.UUID `json:"tor"`
			WireGuard []uuid.UUID `json:"wireguard"`
		}
		err *struct {
			Error string `json:"error"`
		}
	}

	tests := []testCase[tcGiven, tcExpected]{
		{
			name: "error_context_cancelled",
			given: tcGiven{
				svc: &mockProxySvc{
					fnGates: func(ctx context.Context) (*struct{ Direct, Tor, WireGuard []uuid.UUID }, error) {
						return nil, context.Canceled
					},
				},
			},
			exp: tcExpected{
				code: model.StatusClientClosedConn,
				err: &struct {
					Error string `json:"error"`
				}{Error: context.Canceled.Error()},
			},
		},

		{
			name: "error_kind_unknown",
			given: tcGiven{
				svc: &mockProxySvc{
					fnGates: func(ctx context.Context) (*struct{ Direct, Tor, WireGuard []uuid.UUID }, error) {
						return nil, gate.ErrKindUnknown
					},
				},
			},
			exp: tcExpected{
				code: http.StatusBadRequest,
				err: &struct {
					Error string `json:"error"`
				}{Error: gate.ErrKindUnknown.Error()},
			},
		},

		{
			name: "error_default",
			given: tcGiven{
				svc: &mockProxySvc{
					fnGates: func(ctx context.Context) (*struct{ Direct, Tor, WireGuard []uuid.UUID }, error) {
						return nil, model.Error("something_went_wrong")
					},
				},
			},
			exp: tcExpected{
				code: http.StatusInternalServerError,
				err: &struct {
					Error string `json:"error"`
				}{Error: "something_went_wrong"},
			},
		},

		{
			name: "success_empty",
			given: tcGiven{
				svc: &mockProxySvc{
					fnGates: func(ctx context.Context) (*struct{ Direct, Tor, WireGuard []uuid.UUID }, error) {
						result := &struct{ Direct, Tor, WireGuard []uuid.UUID }{}

						return result, nil
					},
				},
			},
			exp: tcExpected{
				code: http.StatusOK,
				data: &struct {
					Direct    []uuid.UUID `json:"direct"`
					Tor       []uuid.UUID `json:"tor"`
					WireGuard []uuid.UUID `json:"wireguard"`
				}{
					Direct:    []uuid.UUID{},
					Tor:       []uuid.UUID{},
					WireGuard: []uuid.UUID{},
				},
			},
		},

		{
			name: "success",
			given: tcGiven{
				svc: &mockProxySvc{
					fnGates: func(ctx context.Context) (*struct{ Direct, Tor, WireGuard []uuid.UUID }, error) {
						result := &struct{ Direct, Tor, WireGuard []uuid.UUID }{
							Direct: []uuid.UUID{
								uuid.MustParse("decade00-0000-4000-a000-000000000000"),
							},
							Tor: []uuid.UUID{
								uuid.MustParse("ad0be000-0000-4000-a000-000000000000"),
							},
							WireGuard: []uuid.UUID{
								uuid.MustParse("c0c0a000-0000-4000-a000-000000000000"),
							},
						}

						return result, nil
					},
				},
			},
			exp: tcExpected{
				code: http.StatusOK,
				data: &struct {
					Direct    []uuid.UUID `json:"direct"`
					Tor       []uuid.UUID `json:"tor"`
					WireGuard []uuid.UUID `json:"wireguard"`
				}{
					Direct: []uuid.UUID{
						uuid.MustParse("decade00-0000-4000-a000-000000000000"),
					},
					Tor: []uuid.UUID{
						uuid.MustParse("ad0be000-0000-4000-a000-000000000000"),
					},
					WireGuard: []uuid.UUID{
						uuid.MustParse("c0c0a000-0000-4000-a000-000000000000"),
					},
				},
			},
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			lg := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{}))
			h := NewProxy(lg, tc.given.svc)

			req := httptest.NewRequest(http.MethodGet, "http://localhost/gates", nil)

			rw := httptest.NewRecorder()
			h.List(rw, req, nil)

			must.Equal(t, tc.exp.code, rw.Code)

			if tc.exp.err != nil {
				actual := &struct {
					Error string `json:"error"`
				}{}

				err := json.Unmarshal(rw.Body.Bytes(), actual)
				must.Equal(t, nil, err)

				should.Equal(t, tc.exp.err, actual)

				return
			}

			actual := &struct {
				Data *struct {
					Direct    []uuid.UUID `json:"direct"`
					Tor       []uuid.UUID `json:"tor"`
					WireGuard []uuid.UUID `json:"wireguard"`
				}
			}{}

			err := json.Unmarshal(rw.Body.Bytes(), actual)
			must.Equal(t, nil, err)

			should.Equal(t, tc.exp.data, actual.Data)
		})
	}
}

func TestProxy_Create(t *testing.T) {
	type tcGiven struct {
		svc *mockProxySvc
		req []byte
	}

	type tcExpected struct {
		code int
		data *struct {
			ID uuid.UUID `json:"id"`
		}
		err *struct {
			Error string `json:"error"`
		}
	}

	tests := []testCase[tcGiven, tcExpected]{
		{
			name: "error_unknown_kind",
			given: tcGiven{
				svc: &mockProxySvc{},
				req: []byte(`{"kind": "openvpn"}`),
			},
			exp: tcExpected{
				code: http.StatusBadRequest,
				err: &struct {
					Error string `json:"error"`
				}{Error: gate.ErrKindUnknown.Error()},
			},
		},

		{
			name: "error_context_cancelled",
			given: tcGiven{
				svc: &mockProxySvc{
					fnCreate: func(ctx context.Context, kind gate.Kind) (uuid.UUID, error) {
						return uuid.Nil, context.Canceled
					},
				},
				req: []byte(`{"kind": "tor"}`),
			},
			exp: tcExpected{
				code: model.StatusClientClosedConn,
				err: &struct {
					Error string `json:"error"`
				}{Error: context.Canceled.Error()},
			},
		},

		{
			name: "error_set_is_shutting",
			given: tcGiven{
				svc: &mockProxySvc{
					fnCreate: func(ctx context.Context, kind gate.Kind) (uuid.UUID, error) {
						return uuid.Nil, gate.ErrSetIsShutting
					},
				},
				req: []byte(`{"kind": "tor"}`),
			},
			exp: tcExpected{
				code: http.StatusBadGateway,
				err: &struct {
					Error string `json:"error"`
				}{Error: gate.ErrSetIsShutting.Error()},
			},
		},

		{
			name: "error_kind_not_supported",
			given: tcGiven{
				svc: &mockProxySvc{
					fnCreate: func(ctx context.Context, kind gate.Kind) (uuid.UUID, error) {
						return uuid.Nil, gate.ErrKindNotSupported
					},
				},
				req: []byte(`{"kind": "direct"}`),
			},
			exp: tcExpected{
				code: http.StatusUnprocessableEntity,
				err: &struct {
					Error string `json:"error"`
				}{Error: gate.ErrKindNotSupported.Error()},
			},
		},

		{
			name: "error_tor_max_reached",
			given: tcGiven{
				svc: &mockProxySvc{
					fnCreate: func(ctx context.Context, kind gate.Kind) (uuid.UUID, error) {
						return uuid.Nil, gate.ErrTorMaxReached
					},
				},
				req: []byte(`{"kind": "tor"}`),
			},
			exp: tcExpected{
				code: http.StatusConflict,
				err: &struct {
					Error string `json:"error"`
				}{Error: gate.ErrTorMaxReached.Error()},
			},
		},

		{
			name: "error_default",
			given: tcGiven{
				svc: &mockProxySvc{
					fnCreate: func(ctx context.Context, kind gate.Kind) (uuid.UUID, error) {
						return uuid.Nil, model.Error("something_went_wrong")
					},
				},
				req: []byte(`{"kind": "tor"}`),
			},
			exp: tcExpected{
				code: http.StatusInternalServerError,
				err: &struct {
					Error string `json:"error"`
				}{Error: "something_went_wrong"},
			},
		},

		{
			name: "success",
			given: tcGiven{
				svc: &mockProxySvc{
					fnCreate: func(ctx context.Context, kind gate.Kind) (uuid.UUID, error) {
						if kind != gate.KindTor {
							return uuid.Nil, model.Error("unexpected_kind")
						}

						return uuid.MustParse("f100ded0-0000-4000-a000-000000000000"), nil
					},
				},
				req: []byte(`{"kind": "tor"}`),
			},
			exp: tcExpected{
				code: http.StatusCreated,
				data: &struct {
					ID uuid.UUID `json:"id"`
				}{ID: uuid.MustParse("f100ded0-0000-4000-a000-000000000000")},
			},
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			lg := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{}))
			h := NewProxy(lg, tc.given.svc)

			req := httptest.NewRequest(http.MethodPost, "http://localhost/gates", bytes.NewReader(tc.given.req))

			rw := httptest.NewRecorder()
			h.Create(rw, req, nil)

			must.Equal(t, tc.exp.code, rw.Code)

			if tc.exp.err != nil {
				actual := &struct {
					Error string `json:"error"`
				}{}

				err := json.Unmarshal(rw.Body.Bytes(), actual)
				must.Equal(t, nil, err)

				should.Equal(t, tc.exp.err, actual)

				return
			}

			actual := &struct {
				Data *struct {
					ID uuid.UUID `json:"id"`
				}
			}{}

			err := json.Unmarshal(rw.Body.Bytes(), actual)
			must.Equal(t, nil, err)

			should.Equal(t, tc.exp.data, actual.Data)
		})
	}
}

func TestProxy_Refresh(t *testing.T) {
	type tcGiven struct {
		svc *mockProxySvc
		id  string
	}

	type tcExpected struct {
		code int
		data []byte
		err  *struct {
			Error string `json:"error"`
		}
	}

	tests := []testCase[tcGiven, tcExpected]{
		{
			name: "error_invalid_param",
			given: tcGiven{
				svc: &mockProxySvc{},
			},
			exp: tcExpected{
				code: http.StatusBadRequest,
				err: &struct {
					Error string `json:"error"`
				}{Error: model.ErrInvalidParam.Error()},
			},
		},

		{
			name: "error_invalid_uuid",
			given: tcGiven{
				svc: &mockProxySvc{},
				id:  "something_else",
			},
			exp: tcExpected{
				code: http.StatusBadRequest,
				err: &struct {
					Error string `json:"error"`
				}{Error: model.ErrInvalidUUID.Error()},
			},
		},

		{
			name: "error_context_cancelled",
			given: tcGiven{
				svc: &mockProxySvc{
					fnRefresh: func(ctx context.Context, id uuid.UUID) error {
						return context.Canceled
					},
				},
				id: "f100ded0-0000-4000-a000-000000000000",
			},
			exp: tcExpected{
				code: model.StatusClientClosedConn,
				err: &struct {
					Error string `json:"error"`
				}{Error: context.Canceled.Error()},
			},
		},

		{
			name: "error_deadline_exceeded",
			given: tcGiven{
				svc: &mockProxySvc{
					fnRefresh: func(ctx context.Context, id uuid.UUID) error {
						return context.DeadlineExceeded
					},
				},
				id: "f100ded0-0000-4000-a000-000000000000",
			},
			exp: tcExpected{
				code: http.StatusGatewayTimeout,
				err: &struct {
					Error string `json:"error"`
				}{Error: context.DeadlineExceeded.Error()},
			},
		},

		{
			name: "error_set_is_shutting",
			given: tcGiven{
				svc: &mockProxySvc{
					fnRefresh: func(ctx context.Context, id uuid.UUID) error {
						return gate.ErrSetIsShutting
					},
				},
				id: "f100ded0-0000-4000-a000-000000000000",
			},
			exp: tcExpected{
				code: http.StatusBadGateway,
				err: &struct {
					Error string `json:"error"`
				}{Error: gate.ErrSetIsShutting.Error()},
			},
		},

		{
			name: "error_gate_not_found",
			given: tcGiven{
				svc: &mockProxySvc{
					fnRefresh: func(ctx context.Context, id uuid.UUID) error {
						return gate.ErrGateNotFound
					},
				},
				id: "f100ded0-0000-4000-a000-000000000000",
			},
			exp: tcExpected{
				code: http.StatusNotFound,
				err: &struct {
					Error string `json:"error"`
				}{Error: gate.ErrGateNotFound.Error()},
			},
		},

		{
			name: "error_kind_not_supported",
			given: tcGiven{
				svc: &mockProxySvc{
					fnRefresh: func(ctx context.Context, id uuid.UUID) error {
						return gate.ErrKindNotSupported
					},
				},
				id: "f100ded0-0000-4000-a000-000000000000",
			},
			exp: tcExpected{
				code: http.StatusUnprocessableEntity,
				err: &struct {
					Error string `json:"error"`
				}{Error: gate.ErrKindNotSupported.Error()},
			},
		},

		{
			name: "error_gate_is_refreshing",
			given: tcGiven{
				svc: &mockProxySvc{
					fnRefresh: func(ctx context.Context, id uuid.UUID) error {
						return gate.ErrGateIsRefreshing
					},
				},
				id: "f100ded0-0000-4000-a000-000000000000",
			},
			exp: tcExpected{
				code: http.StatusConflict,
				err: &struct {
					Error string `json:"error"`
				}{Error: gate.ErrGateIsRefreshing.Error()},
			},
		},

		{
			name: "error_default",
			given: tcGiven{
				svc: &mockProxySvc{
					fnRefresh: func(ctx context.Context, id uuid.UUID) error {
						return model.Error("something_went_wrong")
					},
				},
				id: "f100ded0-0000-4000-a000-000000000000",
			},
			exp: tcExpected{
				code: http.StatusInternalServerError,
				err: &struct {
					Error string `json:"error"`
				}{Error: "something_went_wrong"},
			},
		},

		{
			name: "success",
			given: tcGiven{
				svc: &mockProxySvc{
					fnRefresh: func(ctx context.Context, id uuid.UUID) error {
						if id != uuid.MustParse("f100ded0-0000-4000-a000-000000000000") {
							return model.Error("unexpected_id")
						}

						return nil
					},
				},
				id: "f100ded0-0000-4000-a000-000000000000",
			},
			exp: tcExpected{
				code: http.StatusOK,
				data: []byte("{}"),
			},
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			lg := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{}))
			h := NewProxy(lg, tc.given.svc)

			uri := "http://localhost/gates/" + tc.given.id
			req := httptest.NewRequest(http.MethodPatch, uri, nil)

			rw := httptest.NewRecorder()
			h.Refresh(rw, req, httprouter.Params{{Key: "id", Value: tc.given.id}})

			must.Equal(t, tc.exp.code, rw.Code)

			if tc.exp.err != nil {
				actual := &struct {
					Error string `json:"error"`
				}{}

				err := json.Unmarshal(rw.Body.Bytes(), actual)
				must.Equal(t, nil, err)

				should.Equal(t, tc.exp.err, actual)

				return
			}

			should.Equal(t, tc.exp.data, rw.Body.Bytes())
		})
	}
}

func TestProxy_Stop(t *testing.T) {
	type tcGiven struct {
		svc *mockProxySvc
		id  string
	}

	type tcExpected struct {
		code int
		data []byte
		err  *struct {
			Error string `json:"error"`
		}
	}

	tests := []testCase[tcGiven, tcExpected]{
		{
			name: "error_invalid_param",
			given: tcGiven{
				svc: &mockProxySvc{},
			},
			exp: tcExpected{
				code: http.StatusBadRequest,
				err: &struct {
					Error string `json:"error"`
				}{Error: model.ErrInvalidParam.Error()},
			},
		},

		{
			name: "error_invalid_uuid",
			given: tcGiven{
				svc: &mockProxySvc{},
				id:  "something_else",
			},
			exp: tcExpected{
				code: http.StatusBadRequest,
				err: &struct {
					Error string `json:"error"`
				}{Error: model.ErrInvalidUUID.Error()},
			},
		},

		{
			name: "error_context_cancelled",
			given: tcGiven{
				svc: &mockProxySvc{
					fnStop: func(ctx context.Context, id uuid.UUID) error {
						return context.Canceled
					},
				},
				id: "f100ded0-0000-4000-a000-000000000000",
			},
			exp: tcExpected{
				code: model.StatusClientClosedConn,
				err: &struct {
					Error string `json:"error"`
				}{Error: context.Canceled.Error()},
			},
		},

		{
			name: "error_deadline_exceeded",
			given: tcGiven{
				svc: &mockProxySvc{
					fnStop: func(ctx context.Context, id uuid.UUID) error {
						return context.DeadlineExceeded
					},
				},
				id: "f100ded0-0000-4000-a000-000000000000",
			},
			exp: tcExpected{
				code: http.StatusGatewayTimeout,
				err: &struct {
					Error string `json:"error"`
				}{Error: context.DeadlineExceeded.Error()},
			},
		},

		{
			name: "error_set_is_shutting",
			given: tcGiven{
				svc: &mockProxySvc{
					fnStop: func(ctx context.Context, id uuid.UUID) error {
						return gate.ErrSetIsShutting
					},
				},
				id: "f100ded0-0000-4000-a000-000000000000",
			},
			exp: tcExpected{
				code: http.StatusBadGateway,
				err: &struct {
					Error string `json:"error"`
				}{Error: gate.ErrSetIsShutting.Error()},
			},
		},

		{
			name: "error_gate_not_found",
			given: tcGiven{
				svc: &mockProxySvc{
					fnStop: func(ctx context.Context, id uuid.UUID) error {
						return gate.ErrGateNotFound
					},
				},
				id: "f100ded0-0000-4000-a000-000000000000",
			},
			exp: tcExpected{
				code: http.StatusNotFound,
				err: &struct {
					Error string `json:"error"`
				}{Error: gate.ErrGateNotFound.Error()},
			},
		},

		{
			name: "error_kind_not_supported",
			given: tcGiven{
				svc: &mockProxySvc{
					fnStop: func(ctx context.Context, id uuid.UUID) error {
						return gate.ErrKindNotSupported
					},
				},
				id: "f100ded0-0000-4000-a000-000000000000",
			},
			exp: tcExpected{
				code: http.StatusUnprocessableEntity,
				err: &struct {
					Error string `json:"error"`
				}{Error: gate.ErrKindNotSupported.Error()},
			},
		},

		{
			name: "error_default",
			given: tcGiven{
				svc: &mockProxySvc{
					fnStop: func(ctx context.Context, id uuid.UUID) error {
						return model.Error("something_went_wrong")
					},
				},
				id: "f100ded0-0000-4000-a000-000000000000",
			},
			exp: tcExpected{
				code: http.StatusInternalServerError,
				err: &struct {
					Error string `json:"error"`
				}{Error: "something_went_wrong"},
			},
		},

		{
			name: "success",
			given: tcGiven{
				svc: &mockProxySvc{
					fnStop: func(ctx context.Context, id uuid.UUID) error {
						if id != uuid.MustParse("f100ded0-0000-4000-a000-000000000000") {
							return model.Error("unexpected_id")
						}

						return nil
					},
				},
				id: "f100ded0-0000-4000-a000-000000000000",
			},
			exp: tcExpected{
				code: http.StatusOK,
				data: []byte("{}"),
			},
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			lg := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{}))
			h := NewProxy(lg, tc.given.svc)

			uri := "http://localhost/gates/" + tc.given.id
			req := httptest.NewRequest(http.MethodDelete, uri, nil)

			rw := httptest.NewRecorder()
			h.Stop(rw, req, httprouter.Params{{Key: "id", Value: tc.given.id}})

			must.Equal(t, tc.exp.code, rw.Code)

			if tc.exp.err != nil {
				actual := &struct {
					Error string `json:"error"`
				}{}

				err := json.Unmarshal(rw.Body.Bytes(), actual)
				must.Equal(t, nil, err)

				should.Equal(t, tc.exp.err, actual)

				return
			}

			should.Equal(t, tc.exp.data, rw.Body.Bytes())
		})
	}
}
