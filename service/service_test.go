package service

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	should "github.com/stretchr/testify/assert"
	must "github.com/stretchr/testify/require"

	"github.com/pavelbrm/pumpe/fakenet"
	"github.com/pavelbrm/pumpe/gate"
	"github.com/pavelbrm/pumpe/model"
)

type testCase[G, E any] struct {
	name  string
	given G
	exp   E
}

func TestPumpe_HandleConnect(t *testing.T) {
	type tcGiven struct {
		set  *mockGateSet
		req  *http.Request
		fnRW func() http.ResponseWriter
	}

	type tcExpected struct {
		msg string
		err error
	}

	tests := []testCase[tcGiven, tcExpected]{
		{
			name: "error_hijacking_not_supported",
			given: tcGiven{
				set: &mockGateSet{},
				req: httptest.NewRequest(http.MethodConnect, "httpbin.org:443", nil),
				fnRW: func() http.ResponseWriter {
					return httptest.NewRecorder()
				},
			},
			exp: tcExpected{
				err: model.ErrHijackingNotSupported,
			},
		},

		{
			name: "error_hijack_error",
			given: tcGiven{
				set: &mockGateSet{},
				req: httptest.NewRequest(http.MethodConnect, "httpbin.org:443", nil),
				fnRW: func() http.ResponseWriter {
					rw := fakenet.NewResponseRecorderHJ(nil)
					rw.FnHijack = func() (net.Conn, *bufio.ReadWriter, error) {
						return nil, nil, model.Error("something_went_wrong")
					}

					return rw
				},
			},
			exp: tcExpected{
				err: model.Error("something_went_wrong"),
			},
		},

		{
			name: "error_pick_dialer",
			given: tcGiven{
				set: &mockGateSet{
					fnRandom: func(ctx context.Context) (gate.ExitGate, error) {
						return nil, model.Error("something_went_wrong")
					},
				},
				req: httptest.NewRequest(http.MethodConnect, "httpbin.org:443", nil),
				fnRW: func() http.ResponseWriter {
					return fakenet.NewResponseRecorderHJ(nil)
				},
			},
			exp: tcExpected{
				msg: "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: 20\r\n\r\nsomething_went_wrong",
				err: model.Error("something_went_wrong"),
			},
		},

		{
			name: "error_dial_failed",
			given: tcGiven{
				set: &mockGateSet{
					fnRandom: func(ctx context.Context) (gate.ExitGate, error) {
						result := &gate.MockExitGate{
							Dialer: &gate.MockNetDialer{
								FnDialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
									return nil, model.Error("something_went_wrong")
								},
							},
						}

						return result, nil
					},
				},
				req: httptest.NewRequest(http.MethodConnect, "httpbin.org:443", nil),
				fnRW: func() http.ResponseWriter {
					return fakenet.NewResponseRecorderHJ(nil)
				},
			},
			exp: tcExpected{
				msg: "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: 20\r\n\r\nsomething_went_wrong",
				err: model.Error("something_went_wrong"),
			},
		},

		{
			name: "error_write_200_failed",
			given: tcGiven{
				set: &mockGateSet{
					fnRandom: func(ctx context.Context) (gate.ExitGate, error) {
						result := &gate.MockExitGate{
							Dialer: &gate.MockNetDialer{
								FnDialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
									conn := &fakenet.MockConn{
										Recv: &bytes.Reader{},
										Send: &bytes.Buffer{},
									}

									return conn, nil
								},
							},
						}

						return result, nil
					},
				},
				req: httptest.NewRequest(http.MethodConnect, "httpbin.org:443", nil),
				fnRW: func() http.ResponseWriter {
					rw := fakenet.NewResponseRecorderHJ(nil)

					conn := rw.ConnT()
					conn.FnWrite = func(b []byte) (int, error) {
						return 0, model.Error("something_went_wrong")
					}

					return rw
				},
			},
			exp: tcExpected{
				err: model.Error("something_went_wrong"),
			},
		},

		{
			name: "valid",
			given: tcGiven{
				set: &mockGateSet{
					fnRandom: func(ctx context.Context) (gate.ExitGate, error) {
						result := &gate.MockExitGate{
							Dialer: &gate.MockNetDialer{
								FnDialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
									conn := &fakenet.MockConn{
										Recv: bytes.NewReader([]byte("test response from target\n")),
										Send: &bytes.Buffer{},
									}

									conn.FnWrite = func(b []byte) (int, error) {
										if !bytes.Equal(b, []byte("test request from client\n")) {
											return 0, model.Error("unexpected_write_to_target")
										}

										return conn.Send.Write(b)
									}

									return conn, nil
								},
							},
						}

						return result, nil
					},
				},
				req: httptest.NewRequest(http.MethodConnect, "httpbin.org:443", nil),
				fnRW: func() http.ResponseWriter {
					return fakenet.NewResponseRecorderHJ([]byte("test request from client\n"))
				},
			},
			exp: tcExpected{
				msg: "HTTP/1.1 200 Connection established\r\n\r\ntest response from target\n",
			},
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			svc := NewPumpe(tc.given.set)

			ctx := context.Background()
			rw := tc.given.fnRW()

			actual := svc.HandleConnect(ctx, rw, tc.given.req)
			must.Equal(t, tc.exp.err, actual)

			if tc.exp.err != nil && tc.exp.msg == "" {
				return
			}

			switch rwt := rw.(type) {
			case *fakenet.ResponseRecorderHJ:
				should.Equal(t, tc.exp.msg, rwt.Body.String())

				c, ok := rwt.Conn().(*fakenet.MockConn)
				must.Equal(t, true, ok)

				should.Equal(t, tc.exp.msg, c.Send.String())
			case *httptest.ResponseRecorder:
				should.Equal(t, tc.exp.msg, rwt.Body.String())
			default:
				return
			}
		})
	}
}

func TestPumpe_HandleHTTP(t *testing.T) {
	type tcGiven struct {
		set *mockGateSet
		req *http.Request
	}

	type tcExpected struct {
		code int
		msg  string
		hdr  http.Header
		err  error
	}

	tests := []testCase[tcGiven, tcExpected]{
		{
			name: "error_pick_dialer",
			given: tcGiven{
				set: &mockGateSet{
					fnRandom: func(ctx context.Context) (gate.ExitGate, error) {
						return nil, model.Error("something_went_wrong")
					},
				},
				req: httptest.NewRequest(http.MethodGet, "http://httpbin.org", nil),
			},
			exp: tcExpected{
				err: model.Error("something_went_wrong"),
			},
		},

		{
			name: "error_dialer_do",
			given: tcGiven{
				set: &mockGateSet{
					fnRandom: func(ctx context.Context) (gate.ExitGate, error) {
						result := &gate.MockExitGate{
							Doer: &gate.MockHTTPDoer{
								FnDo: func(r *http.Request) (*http.Response, error) {
									return nil, model.Error("something_went_wrong")
								},
							},
						}

						return result, nil
					},
				},
				req: httptest.NewRequest(http.MethodGet, "http://httpbin.org", nil),
			},
			exp: tcExpected{
				code: http.StatusBadGateway,
				msg:  "server error",
				err:  model.Error("something_went_wrong"),
			},
		},

		{
			name: "valid",
			given: tcGiven{
				set: &mockGateSet{
					fnRandom: func(ctx context.Context) (gate.ExitGate, error) {
						result := &gate.MockExitGate{
							Doer: &gate.MockHTTPDoer{
								FnDo: func(r *http.Request) (*http.Response, error) {
									resp := gate.NewMockResponse()
									resp.Body = io.NopCloser(bytes.NewBufferString("My name is Bane."))

									resp.Header.Add("Proxy-Connection", "test_header_removal")
									resp.Header.Add("X-Custom-App-Header", "test_header_preservation")

									return resp, nil
								},
							},
						}

						return result, nil
					},
				},
				req: httptest.NewRequest(http.MethodGet, "http://httpbin.org", nil),
			},
			exp: tcExpected{
				code: http.StatusOK,
				msg:  "My name is Bane.",
				hdr:  http.Header{"X-Custom-App-Header": []string{"test_header_preservation"}},
			},
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tests[i].name, func(t *testing.T) {
			svc := NewPumpe(tc.given.set)

			ctx := context.Background()
			rw := httptest.NewRecorder()

			actual := svc.HandleHTTP(ctx, rw, tc.given.req)
			must.Equal(t, tc.exp.err, actual)

			if tc.exp.err != nil && tc.exp.code == 0 {
				return
			}

			should.Equal(t, tc.exp.code, rw.Code)
			should.Equal(t, tc.exp.msg, rw.Body.String())

			if len(tc.exp.hdr) > 0 {
				should.Equal(t, tc.exp.hdr, rw.Result().Header)
			}
		})
	}
}

func TestPumpe_pickDialer(t *testing.T) {
	type tcGiven struct {
		set *mockGateSet
		hdr http.Header
	}

	type tcExpected struct {
		id   uuid.UUID
		kind gate.Kind
		err  error
	}

	tests := []testCase[tcGiven, tcExpected]{
		{
			name: "error_invalid_id",
			given: tcGiven{
				set: &mockGateSet{},
				hdr: http.Header{
					"Proxy-Pumpe-Gate-Id": []string{"something"},
				},
			},
			exp: tcExpected{
				err: model.ErrInvalidUUID,
			},
		},

		{
			name: "valid_id",
			given: tcGiven{
				set: &mockGateSet{
					fnByID: func(id uuid.UUID) (gate.ExitGate, error) {
						if id != uuid.MustParse("c0c0a000-0000-4000-a000-000000000000") {
							return nil, model.Error("unexpected_id")
						}

						result := &gate.MockExitGate{
							FnID:   func() uuid.UUID { return uuid.MustParse("c0c0a000-0000-4000-a000-000000000000") },
							FnKind: func() gate.Kind { return gate.KindTor },
						}

						return result, nil
					},
				},
				hdr: http.Header{
					"Proxy-Pumpe-Gate-Id": []string{"c0c0a000-0000-4000-a000-000000000000"},
				},
			},
			exp: tcExpected{
				id:   uuid.MustParse("c0c0a000-0000-4000-a000-000000000000"),
				kind: gate.KindTor,
			},
		},

		{
			name: "valid_type",
			given: tcGiven{
				set: &mockGateSet{
					fnByKind: func(ctx context.Context, kind gate.Kind) (gate.ExitGate, error) {
						if kind != gate.KindTor {
							return nil, model.Error("unexpected_kind")
						}

						result := &gate.MockExitGate{
							FnID:   func() uuid.UUID { return uuid.MustParse("c0c0a000-0000-4000-a000-000000000000") },
							FnKind: func() gate.Kind { return gate.KindTor },
						}

						return result, nil
					},
				},
				hdr: http.Header{
					"Proxy-Pumpe-Gate-Type": []string{"tor"},
				},
			},
			exp: tcExpected{
				id:   uuid.MustParse("c0c0a000-0000-4000-a000-000000000000"),
				kind: gate.KindTor,
			},
		},

		{
			name: "both_id_type_id_wins",
			given: tcGiven{
				set: &mockGateSet{
					fnByID: func(id uuid.UUID) (gate.ExitGate, error) {
						if id != uuid.MustParse("c0c0a000-0000-4000-a000-000000000000") {
							return nil, model.Error("unexpected_id")
						}

						result := &gate.MockExitGate{
							FnID:   func() uuid.UUID { return uuid.MustParse("c0c0a000-0000-4000-a000-000000000000") },
							FnKind: func() gate.Kind { return gate.KindTor },
						}

						return result, nil
					},

					fnByKind: func(ctx context.Context, kind gate.Kind) (gate.ExitGate, error) {
						return nil, model.Error("unexpected_by_kind")
					},
				},
				hdr: http.Header{
					"Proxy-Pumpe-Gate-Id":   []string{"c0c0a000-0000-4000-a000-000000000000"},
					"Proxy-Pumpe-Gate-Type": []string{"tor"},
				},
			},
			exp: tcExpected{
				id:   uuid.MustParse("c0c0a000-0000-4000-a000-000000000000"),
				kind: gate.KindTor,
			},
		},

		{
			name: "valid_random",
			given: tcGiven{
				set: &mockGateSet{
					fnRandom: func(ctx context.Context) (gate.ExitGate, error) {
						result := &gate.MockExitGate{
							FnID:   func() uuid.UUID { return uuid.MustParse("ad0be000-0000-4000-a000-000000000000") },
							FnKind: func() gate.Kind { return gate.KindWireGuard },
						}

						return result, nil
					},
				},
				hdr: make(http.Header),
			},
			exp: tcExpected{
				id:   uuid.MustParse("ad0be000-0000-4000-a000-000000000000"),
				kind: gate.KindWireGuard,
			},
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tests[i].name, func(t *testing.T) {
			svc := NewPumpe(tc.given.set)

			ctx := context.Background()

			actual, err := svc.pickDialer(ctx, tc.given.hdr)
			must.Equal(t, tc.exp.err, err)

			if tc.exp.err != nil {
				return
			}

			should.Equal(t, tc.exp.id, actual.ID())
			should.Equal(t, tc.exp.kind, actual.Kind())
		})
	}
}

func TestNewHopHeaders(t *testing.T) {
	tests := []testCase[struct{}, []string]{
		{
			name: "valid",
			exp: []string{
				"Connection",
				"Keep-Alive",
				"Proxy-Authenticate",
				"Proxy-Authorization",
				"Proxy-Connection",
				"Te",
				"Trailer",
				"Transfer-Encoding",
				"Upgrade",
				"Proxy-Pumpe-Gate-Id",
				"Proxy-Pumpe-Gate-Type",
			},
		},
	}

	for i := range tests {
		t.Run(tests[i].name, func(t *testing.T) {
			should.Equal(t, tests[i].exp, newHopHeaders())
		})
	}
}

func TestDelHeaders(t *testing.T) {
	type tcGiven struct {
		list []string
		hdr  http.Header
	}

	tests := []testCase[tcGiven, http.Header]{
		{
			name: "empty_list",
			given: tcGiven{
				hdr: http.Header{"Hdr_01": []string{"Val_01"}},
			},
			exp: http.Header{"Hdr_01": []string{"Val_01"}},
		},

		{
			name: "empty_headers",
			given: tcGiven{
				list: []string{"Hdr_01"},
				hdr:  http.Header{},
			},
			exp: http.Header{},
		},

		{
			name: "delete",
			given: tcGiven{
				list: []string{"Found_01", "NotFound_02", "Found_03"},
				hdr: http.Header{
					"Hdr_01":   []string{"Val_01"},
					"Found_01": []string{"Found_01"},
					"Found_03": []string{"Found_03_01", "Found_03_02"},
				},
			},
			exp: http.Header{
				"Hdr_01": []string{"Val_01"},
			},
		},
	}

	for i := range tests {
		t.Run(tests[i].name, func(t *testing.T) {
			delHeaders(tests[i].given.list, tests[i].given.hdr)

			should.Equal(t, tests[i].exp, tests[i].given.hdr)
		})
	}
}

func TestDelConnectionHeaders(t *testing.T) {
	tests := []testCase[http.Header, http.Header]{
		{
			name:  "empty",
			given: http.Header{},
			exp:   http.Header{},
		},

		{
			name:  "connection_header_close",
			given: http.Header{"Connection": []string{"close"}},
			exp:   http.Header{"Connection": []string{"close"}},
		},

		{
			name:  "connection_header_keep_alive",
			given: http.Header{"Connection": []string{"keep-alive"}},
			exp:   http.Header{"Connection": []string{"keep-alive"}},
		},

		{
			name: "connection_header_delete",
			given: http.Header{
				"Connection": []string{"keep-alive, Keep-Alive"},
				"Keep-Alive": []string{"100"},
			},
			exp: http.Header{"Connection": []string{"keep-alive, Keep-Alive"}},
		},
	}

	for i := range tests {
		t.Run(tests[i].name, func(t *testing.T) {
			delConnectionHeaders(tests[i].given)

			should.Equal(t, tests[i].exp, tests[i].given)
		})
	}
}

func TestAddHostToXForwardedHeader(t *testing.T) {
	type tcGiven struct {
		hdr  http.Header
		host string
	}

	tests := []testCase[tcGiven, http.Header]{
		{
			name: "no_previous_values",
			given: tcGiven{
				hdr:  http.Header{},
				host: "127.0.0.1",
			},
			exp: http.Header{
				"X-Forwarded-For": []string{"127.0.0.1"},
			},
		},

		{
			name: "one_existing",
			given: tcGiven{
				hdr: http.Header{
					"X-Forwarded-For": []string{"127.0.0.1"},
				},
				host: "127.0.0.2",
			},
			exp: http.Header{
				"X-Forwarded-For": []string{"127.0.0.1, 127.0.0.2"},
			},
		},

		{
			name: "two_existing",
			given: tcGiven{
				hdr: http.Header{
					"X-Forwarded-For": []string{"127.0.0.1", "127.0.0.2"},
				},
				host: "127.0.0.3",
			},
			exp: http.Header{
				"X-Forwarded-For": []string{"127.0.0.1, 127.0.0.2, 127.0.0.3"},
			},
		},
	}

	for i := range tests {
		t.Run(tests[i].name, func(t *testing.T) {
			addHostToXForwardedHeader(tests[i].given.hdr, tests[i].given.host)

			should.Equal(t, tests[i].exp, tests[i].given.hdr)
		})
	}
}

func TestCopyHeader(t *testing.T) {
	tests := []testCase[http.Header, http.Header]{
		{
			name: "nil",
			exp:  http.Header{},
		},

		{
			name:  "empty",
			given: http.Header{},
			exp:   http.Header{},
		},

		{
			name: "single_values",
			given: http.Header{
				"Hdr_01": []string{"val_01"},
				"Hdr_02": []string{"val_02"},
			},
			exp: http.Header{
				"Hdr_01": []string{"val_01"},
				"Hdr_02": []string{"val_02"},
			},
		},

		{
			name: "multiple_values",
			given: http.Header{
				"Hdr_01": []string{"val_01"},
				"Hdr_02": []string{"val_02"},
				"Hdr_03": []string{"val_03_01", "val_03_02"},
			},
			exp: http.Header{
				"Hdr_01": []string{"val_01"},
				"Hdr_02": []string{"val_02"},
				"Hdr_03": []string{"val_03_01", "val_03_02"},
			},
		},
	}

	for i := range tests {
		t.Run(tests[i].name, func(t *testing.T) {
			actual := http.Header{}
			copyHeader(actual, tests[i].given)

			should.Equal(t, tests[i].exp, actual)
		})
	}
}

func TestRemoteAddrFromHost(t *testing.T) {
	tests := []testCase[string, string]{
		{
			name: "empty_string",
			exp:  ":443",
		},

		{
			name:  "no_port",
			given: "example.com",
			exp:   "example.com:443",
		},

		{
			name:  "with_port",
			given: "example.com:5443",
			exp:   "example.com:5443",
		},

		{
			name:  "https",
			given: "example.com:443",
			exp:   "example.com:443",
		},
	}

	for i := range tests {
		t.Run(tests[i].name, func(t *testing.T) {
			should.Equal(t, tests[i].exp, remoteAddrFromHost(tests[i].given))
		})
	}
}

func TestXferData(t *testing.T) {
	type tcGiven struct {
		dst io.Writer
		src io.Reader
	}

	tests := []testCase[tcGiven, []byte]{
		{
			name: "valid",
			given: tcGiven{
				dst: &bytes.Buffer{},
				src: bytes.NewBufferString("Peace is a lie; there is only passion."),
			},
			exp: []byte("Peace is a lie; there is only passion."),
		},

		{
			name: "valid_write_closer",
			given: tcGiven{
				dst: &mockReadWriteCloser{
					Buffer: &bytes.Buffer{},
				},
				src: bytes.NewBufferString("Through passion, I gain strength."),
			},
			exp: []byte("Through passion, I gain strength."),
		},

		{
			name: "valid_read_closer",
			given: tcGiven{
				dst: &bytes.Buffer{},
				src: &mockReadWriteCloser{
					Buffer: bytes.NewBufferString("Through strength, I gain power. Through power, I gain victory."),
				},
			},
			exp: []byte("Through strength, I gain power. Through power, I gain victory."),
		},

		{
			name: "valid_both_closers",
			given: tcGiven{
				dst: &mockReadWriteCloser{
					Buffer: &bytes.Buffer{},
				},
				src: &mockReadWriteCloser{
					Buffer: bytes.NewBufferString("Through victory my chains are broken."),
				},
			},
			exp: []byte("Through victory my chains are broken."),
		},
	}

	for i := range tests {
		t.Run(tests[i].name, func(t *testing.T) {
			xferData(tests[i].given.dst, tests[i].given.src)

			bts, ok := tests[i].given.dst.(interface{ Bytes() []byte })
			if !ok {
				return
			}

			should.Equal(t, tests[i].exp, bts.Bytes())
		})
	}
}

func TestWriteErrToConn(t *testing.T) {
	type tcGiven struct {
		rw interface {
			io.Writer
			fmt.Stringer
		}
		rerr error
	}

	type tcExpected struct {
		text string
		err  error
	}

	tests := []testCase[tcGiven, tcExpected]{
		{
			name: "nil",
			given: tcGiven{
				rw: &mockWriter{},
			},
		},

		{
			name: "valid",
			given: tcGiven{
				rw:   &strings.Builder{},
				rerr: model.Error("something_went_wrong"),
			},
			exp: tcExpected{
				text: "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: 20\r\n\r\nsomething_went_wrong",
			},
		},

		{
			name: "error",
			given: tcGiven{
				rw: &mockWriter{
					fnWrite: func(p []byte) (int, error) {
						return 0, model.Error("something_went_wrong")
					},
				},
				rerr: model.Error("something_else_went_wrong"),
			},
			exp: tcExpected{
				err: model.Error("something_went_wrong"),
			},
		},
	}

	for i := range tests {
		t.Run(tests[i].name, func(t *testing.T) {
			actual := writeErrToConn(tests[i].given.rw, tests[i].given.rerr)
			must.Equal(t, tests[i].exp.err, actual)

			if tests[i].exp.err != nil {
				return
			}

			should.Equal(t, tests[i].exp.text, tests[i].given.rw.String())
		})
	}
}
