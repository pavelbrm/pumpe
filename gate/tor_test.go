package gate

import (
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	should "github.com/stretchr/testify/assert"
	must "github.com/stretchr/testify/require"

	"github.com/pavelbrm/pumpe/model"
)

func TestTor_refresh(t *testing.T) {
	type tcExpected struct {
		refreshing uint32
		err        error
	}

	tests := []testCase[*Tor, tcExpected]{
		{
			name: "error_refreshing",
			given: &Tor{
				baseGate:   newBaseGateID(KindTor, uuid.MustParse("facade00-0000-4000-a000-000000000000")),
				refreshing: &struct{ value uint32 }{value: 1},
				dev:        &torDev{},
				netd:       &MockNetDialer{},
				doer:       &MockHTTPDoer{},
			},
			exp: tcExpected{
				refreshing: 1,
				err:        ErrGateIsRefreshing,
			},
		},

		{
			name: "error_refresh",
			given: &Tor{
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
			exp: tcExpected{
				err: model.Error("something_went_wrong"),
			},
		},

		{
			name: "success",
			given: &Tor{
				baseGate:   newBaseGateID(KindTor, uuid.MustParse("facade00-0000-4000-a000-000000000000")),
				refreshing: &struct{ value uint32 }{},
				dev:        &torDev{},
				netd:       &MockNetDialer{},
				doer:       &MockHTTPDoer{},
			},
			exp: tcExpected{},
		},
	}

	for i := range tests {
		tc := tests[i]

		t.Run(tc.name, func(t *testing.T) {
			actual := tc.given.refresh()
			must.Equal(t, tc.exp.err, actual)

			should.Equal(t, tc.exp.refreshing, atomic.LoadUint32(&tc.given.refreshing.value))
		})
	}
}
