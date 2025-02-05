package handler

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	should "github.com/stretchr/testify/assert"

	"github.com/pavelbrm/pumpe/model"
)

func TestPumpe_Handle(t *testing.T) {
	type tcGiven struct {
		svc *mockPumpeSvc
		req *http.Request
	}

	type tcExpected struct {
		code int
		data []byte
		msgs []string
	}

	tests := []testCase[tcGiven, tcExpected]{
		{
			name: "connect_success",
			given: tcGiven{
				svc: &mockPumpeSvc{},
				req: httptest.NewRequest(http.MethodConnect, "https://httpbin.org/ip", nil),
			},

			exp: tcExpected{
				msgs: []string{
					`level=DEBUG msg="handling request" handler.method=handle http.method=CONNECT http.host=https: http.client.ip=192.0.2.1:1234`,
				},
			},
		},

		{
			name: "connect_error",
			given: tcGiven{
				svc: &mockPumpeSvc{
					fnHandleConnect: func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
						return model.Error("something_went_wrong")
					},
				},
				req: httptest.NewRequest(http.MethodConnect, "https://httpbin.org/ip", nil),
			},

			exp: tcExpected{
				msgs: []string{
					`level=DEBUG msg="handling request" handler.method=handle http.method=CONNECT http.host=https: http.client.ip=192.0.2.1:1234`,
					`level=ERROR msg="request ended with error" handler.method=handle http.method=CONNECT http.host=https: http.client.ip=192.0.2.1:1234 error=something_went_wrong`,
				},
			},
		},

		{
			name: "http_connect",
			given: tcGiven{
				svc: &mockPumpeSvc{},
				req: httptest.NewRequest(http.MethodConnect, "http://httpbin.org/ip", nil),
			},

			exp: tcExpected{
				msgs: []string{
					`level=DEBUG msg="handling request" handler.method=handle http.method=CONNECT http.host=http: http.client.ip=192.0.2.1:1234`,
				},
			},
		},

		{
			name: "http_success",
			given: tcGiven{
				svc: &mockPumpeSvc{},
				req: httptest.NewRequest(http.MethodGet, "http://httpbin.org/ip", nil),
			},

			exp: tcExpected{
				msgs: []string{
					`level=DEBUG msg="handling request" handler.method=handle http.method=GET http.host=httpbin.org http.client.ip=192.0.2.1:1234 http.scheme=http http.uri.path=/ip http.header.user_agent=""`,
				},
			},
		},

		{
			name: "http_error",
			given: tcGiven{
				svc: &mockPumpeSvc{
					fnHandleHTTP: func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
						return model.Error("something_went_wrong")
					},
				},
				req: httptest.NewRequest(http.MethodGet, "http://httpbin.org/ip", nil),
			},

			exp: tcExpected{
				msgs: []string{
					`level=DEBUG msg="handling request" handler.method=handle http.method=GET http.host=httpbin.org http.client.ip=192.0.2.1:1234 http.scheme=http http.uri.path=/ip http.header.user_agent=""`,
					`level=ERROR msg="request ended with error" handler.method=handle http.method=GET http.host=httpbin.org http.client.ip=192.0.2.1:1234 http.scheme=http http.uri.path=/ip http.header.user_agent="" error=something_went_wrong`,
				},
			},
		},

		{
			name: "default_error",
			given: tcGiven{
				svc: &mockPumpeSvc{
					fnHandleHTTP: func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
						return model.Error("something_went_wrong")
					},
				},
				req: httptest.NewRequest(http.MethodGet, "htxp://httpbin.org/ip", nil),
			},

			exp: tcExpected{
				code: http.StatusBadRequest,
				data: []byte(`unsupported scheme`),
				msgs: []string{
					`level=WARN msg="unsupported scheme" handler.method=handle http.method=GET http.host=httpbin.org http.client.ip=192.0.2.1:1234`,
				},
			},
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			lgw := &strings.Builder{}

			opts := &slog.HandlerOptions{
				Level: slog.LevelDebug,
				ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
					if a.Key == slog.TimeKey {
						return slog.Attr{}
					}

					return a
				},
			}

			lg := slog.New(slog.NewTextHandler(lgw, opts))
			h := NewPumpe(lg, tc.given.svc)

			rw := httptest.NewRecorder()
			h.Handle(rw, tc.given.req)

			actual := strings.Split(strings.TrimSpace(lgw.String()), "\n")
			should.Equal(t, tc.exp.msgs, actual)

			if tc.exp.code != 0 {
				should.Equal(t, tc.exp.code, rw.Code)
			}

			if tc.exp.data != nil {
				should.Equal(t, tc.exp.data, rw.Body.Bytes())
			}
		})
	}
}
