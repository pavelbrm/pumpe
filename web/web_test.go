package web

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/julienschmidt/httprouter"
	should "github.com/stretchr/testify/assert"
	must "github.com/stretchr/testify/require"
)

type testCase[G, E any] struct {
	name  string
	given G
	exp   E
}

func TestApp_ServeHTTP(t *testing.T) {
	type tcGiven struct {
		m   string
		p   string
		fn  httprouter.Handle
		req *http.Request
	}

	type tcExpected struct {
		code int
		data []byte
	}

	tests := []testCase[tcGiven, tcExpected]{
		{
			name: "valid",
			given: tcGiven{
				m: http.MethodGet,
				p: "/test/found",
				fn: func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte("success"))
				},
				req: httptest.NewRequest(http.MethodGet, "http://localhost/test/found", nil),
			},
			exp: tcExpected{
				code: http.StatusOK,
				data: []byte("success"),
			},
		},

		{
			name: "not_found",
			given: tcGiven{
				m: http.MethodGet,
				p: "/test/found",
				fn: func(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
					w.WriteHeader(http.StatusInternalServerError)
					_, _ = w.Write([]byte("unexpected_body"))
				},
				req: httptest.NewRequest(http.MethodGet, "http://localhost/test/not_found", nil),
			},
			exp: tcExpected{
				code: http.StatusNotFound,
			},
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			opts := &slog.HandlerOptions{
				Level: slog.LevelError,
				ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
					return slog.Attr{}
				},
			}

			lg := slog.New(slog.NewTextHandler(io.Discard, opts))
			app := NewApp(lg)

			app.Handle(tc.given.m, tc.given.p, tc.given.fn)

			rw := httptest.NewRecorder()
			app.ServeHTTP(rw, tc.given.req)

			should.Equal(t, tc.exp.code, rw.Code)
			should.Equal(t, tc.exp.data, rw.Body.Bytes())
		})
	}
}

func TestApp_handlePanic(t *testing.T) {
	type tcExpected struct {
		code        int
		data        []byte
		fnCheckAttr func(slog.Attr)
	}

	tests := []testCase[interface{}, tcExpected]{
		{
			name: "invalid_nil",
			exp: tcExpected{
				code: http.StatusInternalServerError,
			},
		},

		{
			name:  "string",
			given: "something_went_wrong",
			exp: tcExpected{
				code: http.StatusInternalServerError,
				fnCheckAttr: func(a slog.Attr) {
					if a.Key == "error" {
						v := a.Value.Any()

						err, ok := v.(Error)
						if !ok {
							panic("unexpected_error_type")
						}

						if err != Error("something_went_wrong") {
							panic("unexpected_error_value")
						}
					}
				},
			},
		},

		{
			name:  "error",
			given: Error("something_else_went_wrong"),
			exp: tcExpected{
				code: http.StatusInternalServerError,
				fnCheckAttr: func(a slog.Attr) {
					if a.Key == "error" {
						v := a.Value.Any()

						err, ok := v.(Error)
						if !ok {
							panic("unexpected_error_type")
						}

						if err != Error("something_else_went_wrong") {
							panic("unexpected_error_value")
						}
					}
				},
			},
		},

		{
			name:  "anything",
			given: 69,
			exp: tcExpected{
				code: http.StatusInternalServerError,
				fnCheckAttr: func(a slog.Attr) {
					if a.Key == "error" {
						v := a.Value.Any()

						err, ok := v.(Error)
						if !ok {
							panic("unexpected_error_type")
						}

						if err != errPanicked {
							panic("unexpected_error_value")
						}
					}
				},
			},
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			opts := &slog.HandlerOptions{
				Level: slog.LevelError,
				ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
					if tc.exp.fnCheckAttr != nil {
						tc.exp.fnCheckAttr(a)
					}

					return slog.Attr{}
				},
			}

			lg := slog.New(slog.NewTextHandler(io.Discard, opts))
			app := NewApp(lg)

			rw := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "http://localhost/test", nil)

			app.handlePanic(rw, req, tc.given)

			should.Equal(t, tc.exp.code, rw.Code)
			should.Equal(t, tc.exp.data, rw.Body.Bytes())
		})
	}
}

func TestApp_handle404(t *testing.T) {
	type tcExpected struct {
		code int
		data []byte
	}

	tests := []testCase[*http.Request, tcExpected]{
		{
			name:  "text",
			given: httptest.NewRequest(http.MethodGet, "http://localhost/test", nil),
			exp: tcExpected{
				code: http.StatusNotFound,
			},
		},

		{
			name: "json",
			given: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "http://localhost/test", nil)
				req.Header.Add("Content-Type", "application/json")

				return req
			}(),
			exp: tcExpected{
				code: http.StatusNotFound,
				data: []byte("{}"),
			},
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			opts := &slog.HandlerOptions{
				Level: slog.LevelError,
				ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
					return slog.Attr{}
				},
			}

			lg := slog.New(slog.NewTextHandler(io.Discard, opts))
			app := NewApp(lg)

			rw := httptest.NewRecorder()
			app.handle404(rw, tc.given)

			should.Equal(t, tc.exp.code, rw.Code)
			should.Equal(t, tc.exp.data, rw.Body.Bytes())

			resp := rw.Result()
			should.Equal(t, "nosniff", resp.Header.Get("X-Content-Type-Options"))
		})
	}
}

func TestWriteError(t *testing.T) {
	type tcGiven struct {
		code int
		text string
	}

	type tcExpected struct {
		code int
		data []byte
	}

	tests := []testCase[tcGiven, tcExpected]{
		{
			name: "not_found",
			given: tcGiven{
				code: http.StatusNotFound,
				text: "not found",
			},
			exp: tcExpected{
				code: http.StatusNotFound,
				data: []byte("not found"),
			},
		},

		{
			name: "something_went_wroung",
			given: tcGiven{
				code: http.StatusInternalServerError,
				text: "something went wrong",
			},
			exp: tcExpected{
				code: http.StatusInternalServerError,
				data: []byte("something went wrong"),
			},
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			rw := httptest.NewRecorder()

			err := WriteError(rw, tc.given.code, tc.given.text)
			must.Equal(t, nil, err)

			should.Equal(t, tc.exp.code, rw.Code)
			should.Equal(t, tc.exp.data, rw.Body.Bytes())

			resp := rw.Result()
			should.Equal(t, "text/plain; charset=utf-8", resp.Header.Get("Content-Type"))
			should.Equal(t, "nosniff", resp.Header.Get("X-Content-Type-Options"))
		})
	}
}

func TestLattrsFromReq(t *testing.T) {
	tests := []testCase[*http.Request, []slog.Attr]{
		{
			name:  "valid",
			given: httptest.NewRequest(http.MethodGet, "http://localhost/test", nil),
			exp: []slog.Attr{
				slog.String("http.host", "localhost"),
				slog.String("http.method", "GET"),
				slog.String("http.client.ip", "192.0.2.1:1234"),
				slog.String("http.uri.path", "/test"),
				slog.String("http.header.user_agent", ""),
			},
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			actual := lattrsFromReq(tc.given)
			should.Equal(t, tc.exp, actual)
		})
	}
}
