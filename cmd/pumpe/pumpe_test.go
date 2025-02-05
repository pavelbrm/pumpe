package main

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	should "github.com/stretchr/testify/assert"
	must "github.com/stretchr/testify/require"

	"github.com/pavelbrm/pumpe/model"
)

func TestRawEnvToMap(t *testing.T) {
	tests := []struct {
		name  string
		given []string
		exp   map[string]string
	}{
		{
			name: "nil",
		},

		{
			name:  "empty",
			given: []string{},
			exp:   map[string]string{},
		},

		{
			name: "incomplete_inputs",
			given: []string{
				"TEST_SOME_KEY_01=",
				"TEST_SOME_KEY_02",
				"TEST_SOME_KEY_03/some_val_03",
				"TEST_SOME_KEY_04==",
			},
			exp: map[string]string{
				"TEST_SOME_KEY_01": "",
				"TEST_SOME_KEY_04": "=",
			},
		},

		{
			name: "valid",
			given: []string{
				"TEST_SOME_KEY_01=some_val_01",
				"TEST_SOME_KEY_02=some_val_02",
				"TEST_SOME_KEY_03=some_val_03",
			},
			exp: map[string]string{
				"TEST_SOME_KEY_01": "some_val_01",
				"TEST_SOME_KEY_02": "some_val_02",
				"TEST_SOME_KEY_03": "some_val_03",
			},
		},
	}

	for i := range tests {
		t.Run(tests[i].name, func(t *testing.T) {
			actual := rawEnvToMap(tests[i].given)
			should.Equal(t, tests[i].exp, actual)
		})
	}
}

func TestNewSettingsFromEnv(t *testing.T) {
	tests := []struct {
		name  string
		given map[string]string
		exp   settings
	}{
		{
			name:  "defaults",
			given: map[string]string{},
			exp: settings{
				shutdownTimeout:      30 * time.Second,
				httpClientTimeout:    60 * time.Second,
				setRandomLoopTimeout: 30 * time.Second,
				setRandomLoopDelay:   10 * time.Millisecond,
				setStateLoopTimeout:  30 * time.Second,
				setStateLoopDelay:    10 * time.Millisecond,
				torStartupTimeout:    3 * time.Minute,
				torN:                 4,
				torMax:               128,
				defKind:              "tor",
				wgDNS:                "9.9.9.9",
				port:                 "8080",
				logLvl:               "INFO",
				logFmt:               "json",
			},
		},

		{
			name: "configured",
			given: map[string]string{
				"PUMPE_SHUTDOWN_TIMEOUT":        "29s",
				"PUMPE_HTTP_CLIENT_TIMEOUT":     "59s",
				"PUMPE_SET_RANDOM_LOOP_TIMEOUT": "29s",
				"PUMPE_SET_RANDOM_LOOP_DELAY":   "11ms",
				"PUMPE_SET_STATE_LOOP_TIMEOUT":  "29s",
				"PUMPE_SET_STATE_LOOP_DELAY":    "11ms",
				"PUMPE_TOR_STARTUP_TIMEOUT":     "4m",
				"PUMPE_TOR_NUM":                 "16",
				"PUMPE_TOR_MAX":                 "64",
				"PUMPE_WG_PARSE_MODE":           "2",
				"PUMPE_DEFAULT_KIND":            "direct",
				"PUMPE_WG_DIR":                  "/tmp/wg-ini",
				"PUMPE_WG_DNS":                  "1.1.1.1",
				"PUMPE_PORT":                    "8081",
				"PUMPE_LOG_LEVEL":               "DEBUG",
				"PUMPE_LOG_FORMAT":              "text",
				"PUMPE_RANDOMISE_KINDS":         "true",
				"PUMPE_LOG_ADD_SOURCE":          "true",
			},
			exp: settings{
				shutdownTimeout:      29 * time.Second,
				httpClientTimeout:    59 * time.Second,
				setRandomLoopTimeout: 29 * time.Second,
				setRandomLoopDelay:   11 * time.Millisecond,
				setStateLoopTimeout:  29 * time.Second,
				setStateLoopDelay:    11 * time.Millisecond,
				torStartupTimeout:    4 * time.Minute,
				torN:                 16,
				torMax:               64,
				wgParseMode:          2,
				defKind:              "direct",
				wgDir:                "/tmp/wg-ini",
				wgDNS:                "1.1.1.1",
				port:                 "8081",
				logLvl:               "DEBUG",
				logFmt:               "text",
				randomiseKinds:       true,
				logAddSrc:            true,
			},
		},

		{
			name: "configured_exceeding_limits",
			given: map[string]string{
				"PUMPE_SHUTDOWN_TIMEOUT":        "61s",
				"PUMPE_SET_RANDOM_LOOP_TIMEOUT": "61s",
				"PUMPE_SET_RANDOM_LOOP_DELAY":   "101ms",
				"PUMPE_SET_STATE_LOOP_TIMEOUT":  "61s",
				"PUMPE_SET_STATE_LOOP_DELAY":    "101ms",
				"PUMPE_TOR_STARTUP_TIMEOUT":     "1m",
				"PUMPE_WG_DIR":                  "/tmp/wg-ini",
			},
			exp: settings{
				shutdownTimeout:      30 * time.Second,
				httpClientTimeout:    60 * time.Second,
				setRandomLoopTimeout: 30 * time.Second,
				setRandomLoopDelay:   10 * time.Millisecond,
				setStateLoopTimeout:  30 * time.Second,
				setStateLoopDelay:    10 * time.Millisecond,
				torStartupTimeout:    3 * time.Minute,
				torN:                 4,
				torMax:               128,
				defKind:              "tor",
				wgDir:                "/tmp/wg-ini",
				wgDNS:                "9.9.9.9",
				port:                 "8080",
				logLvl:               "INFO",
				logFmt:               "json",
			},
		},

		{
			name: "direct_no_tor",
			given: map[string]string{
				"PUMPE_DEFAULT_KIND": "direct",
				"PUMPE_TOR_NUM":      "0",
			},
			exp: settings{
				shutdownTimeout:      30 * time.Second,
				httpClientTimeout:    60 * time.Second,
				setRandomLoopTimeout: 30 * time.Second,
				setRandomLoopDelay:   10 * time.Millisecond,
				setStateLoopTimeout:  30 * time.Second,
				setStateLoopDelay:    10 * time.Millisecond,
				torStartupTimeout:    3 * time.Minute,
				torMax:               128,
				defKind:              "direct",
				wgDNS:                "9.9.9.9",
				port:                 "8080",
				logLvl:               "INFO",
				logFmt:               "json",
			},
		},
	}

	for i := range tests {
		t.Run(tests[i].name, func(t *testing.T) {
			actual := newSettingsFromEnv(tests[i].given)
			should.Equal(t, tests[i].exp, actual)
		})
	}
}

func TestHandleWGParseErr(t *testing.T) {
	type tcGiven struct {
		mode int
		err  error
	}

	type tcExpected struct {
		msgs []string
		err  error
	}

	tests := []struct {
		name  string
		given tcGiven
		exp   tcExpected
	}{
		{
			name: "error_default_stop",
			given: tcGiven{
				mode: 1,
				err:  model.Error("something_went_wrong"),
			},
			exp: tcExpected{
				err: model.Error("something_went_wrong"),
			},
		},

		{
			name: "error_default_unknown",
			given: tcGiven{
				mode: -1,
				err:  model.Error("something_went_wrong"),
			},
			exp: tcExpected{
				err: model.Error("something_went_wrong"),
			},
		},

		{
			name: "error_report_not_unwrappable",
			given: tcGiven{
				err: model.Error("something_went_wrong"),
			},
			exp: tcExpected{
				err: model.Error("something_went_wrong"),
			},
		},

		{
			name: "valid_report",
			given: tcGiven{
				err: errors.Join(
					model.Error("something_went_wrong_01"),
					model.Error("something_went_wrong_02"),
				),
			},
			exp: tcExpected{
				msgs: []string{
					`level=WARN msg="unable to parse config" kind=wireguard error=something_went_wrong_01`,
					`level=WARN msg="unable to parse config" kind=wireguard error=something_went_wrong_02`,
				},
			},
		},

		{
			name: "valid_ignore",
			given: tcGiven{
				mode: 2,
				err:  model.Error("something_went_wrong"),
			},
			exp: tcExpected{},
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

			ctx := context.Background()

			actual := handleWGParseErr(ctx, lg, tc.given.mode, tc.given.err)
			must.Equal(t, tc.exp.err, actual)

			if tc.exp.err != nil {
				return
			}

			if tc.exp.msgs != nil {
				actualLogs := strings.Split(strings.TrimSpace(lgw.String()), "\n")
				should.Equal(t, tc.exp.msgs, actualLogs)
			}
		})
	}
}

func TestCallFuncsCtxErr(t *testing.T) {
	type tcGiven struct {
		ctx context.Context
		fns []func(context.Context) error
	}

	tests := []struct {
		name  string
		given tcGiven
		exp   error
	}{
		{
			name:  "empty_channel",
			given: tcGiven{ctx: context.Background()},
		},

		{
			name: "no_error",
			given: tcGiven{
				ctx: context.Background(),
				fns: []func(context.Context) error{
					func(ctx context.Context) error { return nil },
				},
			},
		},

		{
			name: "one_error",
			given: tcGiven{
				ctx: context.Background(),
				fns: []func(context.Context) error{
					func(ctx context.Context) error {
						return model.Error("something_went_wrong")
					},
				},
			},
			exp: errors.Join(model.Error("something_went_wrong")),
		},

		{
			name: "one_error_check_ctx_is_passed",
			given: tcGiven{
				ctx: context.WithValue(context.Background(), model.Error("test"), "test_ctx"),
				fns: []func(context.Context) error{
					func(ctx context.Context) error {
						val, ok := ctx.Value(model.Error("test")).(string)
						if !ok || val != "test_ctx" {
							return model.Error("unexpected_ctx_value")
						}

						return model.Error("something_went_wrong")
					},
				},
			},
			exp: errors.Join(model.Error("something_went_wrong")),
		},

		{
			name: "multiple_errors",
			given: tcGiven{
				ctx: context.Background(),
				fns: []func(context.Context) error{
					func(ctx context.Context) error {
						return model.Error("something_went_wrong_01")
					},

					func(ctx context.Context) error { return nil },

					func(ctx context.Context) error {
						return model.Error("something_went_wrong_02")
					},
				},
			},
			exp: errors.Join(model.Error("something_went_wrong_01"), model.Error("something_went_wrong_02")),
		},
	}

	for i := range tests {
		t.Run(tests[i].name, func(t *testing.T) {
			out := make(chan func(context.Context) error, len(tests[i].given.fns))
			for k := range tests[i].given.fns {
				out <- tests[i].given.fns[k]
			}

			close(out)

			actual := callFuncsCtxErr(tests[i].given.ctx, out)

			should.Equal(t, tests[i].exp, actual)
		})
	}
}

func TestCallFuncsErr(t *testing.T) {
	tests := []struct {
		name  string
		given []func() error
		exp   error
	}{
		{
			name: "empty_channel",
		},

		{
			name: "no_error",
			given: []func() error{
				func() error { return nil },
			},
		},

		{
			name: "one_error",
			given: []func() error{
				func() error {
					return model.Error("something_went_wrong")
				},
			},
			exp: errors.Join(model.Error("something_went_wrong")),
		},

		{
			name: "multiple_errors",
			given: []func() error{
				func() error {
					return model.Error("something_went_wrong_01")
				},

				func() error { return nil },

				func() error {
					return model.Error("something_went_wrong_02")
				},
			},
			exp: errors.Join(model.Error("something_went_wrong_01"), model.Error("something_went_wrong_02")),
		},
	}

	for i := range tests {
		t.Run(tests[i].name, func(t *testing.T) {
			out := make(chan func() error, len(tests[i].given))
			for k := range tests[i].given {
				out <- tests[i].given[k]
			}

			close(out)

			actual := callFuncsErr(out)

			should.Equal(t, tests[i].exp, actual)
		})
	}
}
