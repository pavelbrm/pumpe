package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	should "github.com/stretchr/testify/assert"
	must "github.com/stretchr/testify/require"

	"github.com/pavelbrm/pumpe/model"
)

type testCase[G, E any] struct {
	name  string
	given G
	exp   E
}

func TestHealth_status(t *testing.T) {
	type tcExpected struct {
		code int
		data *struct {
			Status string    `json:"status"`
			Time   time.Time `json:"time"`
		}
	}

	tests := []testCase[time.Time, tcExpected]{
		{
			name:  "success",
			given: time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC),
			exp: tcExpected{
				code: http.StatusOK,
				data: &struct {
					Status string    `json:"status"`
					Time   time.Time `json:"time"`
				}{
					Status: "ok",
					Time:   time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC),
				},
			},
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			h := NewHealth()

			req := httptest.NewRequest(http.MethodGet, "http://localhost", nil)
			rw := httptest.NewRecorder()

			h.status(rw, req, nil, tc.given)

			must.Equal(t, tc.exp.code, rw.Code)

			resp := rw.Body.Bytes()

			actual := &struct {
				Data *struct {
					Status string    `json:"status"`
					Time   time.Time `json:"time"`
				} `json:"data"`
			}{}

			{
				err := json.Unmarshal(resp, actual)
				must.Equal(t, nil, err)
			}

			should.Equal(t, tc.exp.data, actual.Data)
		})
	}
}

func TestRspondWithDataJSON(t *testing.T) {
	type tcGiven struct {
		data any
		code int
	}

	type tcExpected struct {
		code int
		data any
		err  error
	}

	tests := []testCase[tcGiven, tcExpected]{
		{
			name: "struct_nil",
			given: tcGiven{
				data: (*struct{})(nil),
				code: http.StatusOK,
			},
			exp: tcExpected{
				code: http.StatusOK,
				data: &struct {
					Data *struct{} `json:"data"`
				}{},
			},
		},

		{
			name: "invalid_data",
			given: tcGiven{
				data: (chan struct{})(nil),
				code: http.StatusOK,
			},
			exp: tcExpected{
				code: http.StatusInternalServerError,
				data: &struct {
					Data any `json:"data"`
				}{},
			},
		},

		{
			name: "some_data",
			given: tcGiven{
				data: &struct {
					Field01 string
					Field02 int
					Field03 []string
				}{
					Field01: "field_01",
					Field02: 2,
					Field03: []string{"id_01", "id_02"},
				},
				code: http.StatusOK,
			},
			exp: tcExpected{
				code: http.StatusOK,
				data: &struct {
					Data *struct {
						Field01 string
						Field02 int
						Field03 []string
					} `json:"data"`
				}{
					Data: &struct {
						Field01 string
						Field02 int
						Field03 []string
					}{
						Field01: "field_01",
						Field02: 2,
						Field03: []string{"id_01", "id_02"},
					},
				},
			},
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			rw := httptest.NewRecorder()

			actual := respondWithDataJSON(rw, tc.given.data, tc.given.code)
			must.Equal(t, tc.exp.err, actual)

			if tc.exp.err != nil {
				return
			}

			must.Equal(t, tc.exp.code, rw.Code)

			resp := rw.Body.Bytes()

			actual2 := reflect.New(reflect.TypeOf(tc.exp.data).Elem()).Interface()

			{
				err := json.Unmarshal(resp, actual2)
				must.Equal(t, nil, err)
			}

			should.Equal(t, tc.exp.data, actual2)
		})
	}
}

func TestRespondWithErrJSON(t *testing.T) {
	type tcGiven struct {
		rerr error
		code int
	}

	type tcExpected struct {
		code int
		data *struct {
			Error string `json:"error"`
		}
		err error
	}

	tests := []testCase[tcGiven, tcExpected]{
		{
			name: "valid",
			given: tcGiven{
				rerr: model.Error("something_went_wrong"),
				code: http.StatusServiceUnavailable,
			},
			exp: tcExpected{
				code: http.StatusServiceUnavailable,
				data: &struct {
					Error string `json:"error"`
				}{Error: "something_went_wrong"},
			},
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			rw := httptest.NewRecorder()

			actual := respondWithErrJSON(rw, tc.given.rerr, tc.given.code)
			must.Equal(t, tc.exp.err, actual)

			if tc.exp.err != nil {
				return
			}

			must.Equal(t, tc.exp.code, rw.Code)

			resp := rw.Body.Bytes()

			actual2 := &struct {
				Error string `json:"error"`
			}{}

			{
				err := json.Unmarshal(resp, &actual2)
				must.Equal(t, nil, err)
			}

			should.Equal(t, tc.exp.data, actual2)
		})
	}
}

func TestRespondWithJSON(t *testing.T) {
	type tcGiven struct {
		data []byte
		code int
	}

	type tcExpected struct {
		code int
		data *struct {
			Field string `json:"field"`
		}
		err error
		pnc string
	}

	tests := []testCase[tcGiven, tcExpected]{
		{
			name: "empty",
			given: tcGiven{
				code: http.StatusOK,
				data: []byte{'{', '}'},
			},
			exp: tcExpected{
				code: http.StatusOK,
				data: &struct {
					Field string `json:"field"`
				}{},
			},
		},

		{
			name: "valid",
			given: tcGiven{
				code: http.StatusOK,
				data: []byte(`{"field": "value"}`),
			},
			exp: tcExpected{
				code: http.StatusOK,
				data: &struct {
					Field string `json:"field"`
				}{Field: "value"},
			},
		},

		{
			name: "panic_zero_code",
			given: tcGiven{
				data: []byte(`{"field": "value"}`),
			},
			exp: tcExpected{
				pnc: "invalid WriteHeader code 0",
			},
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			if tc.exp.pnc != "" {
				defer func() {
					if rcv := recover(); rcv != nil {
						pnc, _ := rcv.(string)
						should.Equal(t, tc.exp.pnc, pnc)
					}
				}()
			}

			rw := httptest.NewRecorder()

			actual := respondWithJSON(rw, tc.given.data, tc.given.code)
			must.Equal(t, tc.exp.err, actual)

			if tc.exp.err != nil {
				return
			}

			must.Equal(t, tc.exp.code, rw.Code)

			resp := rw.Body.Bytes()

			actual2 := &struct {
				Field string `json:"field"`
			}{}

			{
				err := json.Unmarshal(resp, &actual2)
				must.Equal(t, nil, err)
			}

			should.Equal(t, tc.exp.data, actual2)
		})
	}
}
