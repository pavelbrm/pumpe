package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/golocron/daemon/v2"

	"github.com/pavelbrm/pumpe/app"
	"github.com/pavelbrm/pumpe/gate"
	"github.com/pavelbrm/pumpe/model"
)

func main() {
	cfg := newSettingsFromEnv(rawEnvToMap(os.Environ()))
	plg := newLogger(os.Stderr, cfg.logLvl, cfg.logFmt, cfg.logAddSrc)
	lg := plg.With(slog.String("service", "pumpe"))

	ctx := context.Background()
	if err := run(ctx, lg, cfg, os.Args); err != nil {
		lg.LogAttrs(ctx, slog.LevelError, "finished with error", slog.Any("error", err))

		os.Exit(1)
	}

	lg.LogAttrs(ctx, slog.LevelInfo, "finished")

	os.Exit(0)
}

func run(pctx context.Context, lg *slog.Logger, cfg settings, args []string) error {
	if cfg.wgDir == "" {
		return model.Error("invalid wireguard config directory")
	}

	dkind, err := gate.ParseKind(cfg.defKind)
	if err != nil {
		return err
	}

	wcfgs, err := gate.ParseWGConfigs(gate.WGParseMode(cfg.wgParseMode), cfg.wgDir)
	if err != nil {
		if err2 := handleWGParseErr(pctx, lg, cfg.wgParseMode, err); err2 != nil {
			return err2
		}
	}

	nwgs := len(wcfgs)
	if dkind == gate.KindWireGuard && nwgs == 0 {
		return model.Error("cannot start: unable to use wireguard as default without configs")
	}

	if cfg.randomiseKinds && (nwgs == 0 || cfg.torN == 0) {
		return model.Error("cannot start: unable to randomise kinds without both configured")
	}

	wgdns, err := netip.ParseAddr(cfg.wgDNS)
	if err != nil {
		return err
	}

	shutc := make(chan func(context.Context) error, 2)
	killc := make(chan func() error, 1)

	svc := &daemon.ServiceClosing{
		Service: &daemon.Service{
			ShutTimeout: cfg.shutdownTimeout,

			RunFn: func(ctx context.Context) error {
				wgs, err := gate.NewWireGuards(lg, wcfgs, wgdns, cfg.httpClientTimeout)
				if err != nil {
					return err
				}

				lg.LogAttrs(ctx, slog.LevelDebug, "initialised gates", slog.String("kind", "wireguard"))

				tgs, err := gate.NewTors(ctx, cfg.torStartupTimeout, cfg.httpClientTimeout, cfg.torN)
				if err != nil {
					// Stop WireGuard if failed to start Tor.
					_ = gate.ShutdownList(ctx, wgs)

					return err
				}

				lg.LogAttrs(ctx, slog.LevelDebug, "initialised gates", slog.String("kind", "tor"))

				dct := gate.NewDirect(cfg.httpClientTimeout)

				scfg := &gate.SetConfig{
					Default:         dkind,
					HTTPTimeout:     cfg.httpClientTimeout,
					RandomLoopTout:  cfg.setRandomLoopTimeout,
					RandomLoopDelay: cfg.setRandomLoopDelay,
					StateLoopTout:   cfg.setStateLoopTimeout,
					StateLoopDelay:  cfg.setStateLoopDelay,
					TorStartupTout:  cfg.torStartupTimeout,
					TorMax:          cfg.torMax,
					FnBaseCtx:       func() context.Context { return ctx },
					RandomiseKinds:  cfg.randomiseKinds,
				}

				set := gate.NewSet(scfg, dct, tgs, wgs)
				if err := set.Warmup(ctx); err != nil {
					// Stop everything if failed to warm up.
					_ = set.Shutdown(ctx)

					return err
				}

				lg.LogAttrs(ctx, slog.LevelDebug, "warmed up gates")

				srv := &http.Server{
					Addr:        ":" + cfg.port,
					Handler:     app.NewWeb(lg, set),
					BaseContext: func(l net.Listener) context.Context { return ctx },
				}

				shutc <- srv.Shutdown
				shutc <- set.Shutdown
				close(shutc)

				killc <- srv.Close
				close(killc)

				lg.LogAttrs(ctx, slog.LevelInfo, "starting http server", slog.String("port", cfg.port))

				serr := srv.ListenAndServe()
				if serr != nil && !errors.Is(err, http.ErrServerClosed) {
					// Try out best to stop the gates if failed unexpectedly.
					// Can't use ctx at this point, create new.
					sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()

					_ = set.Shutdown(sctx)
				}

				return serr
			},

			ShutFn: func(ctx context.Context) error {
				return callFuncsCtxErr(ctx, shutc)
			},
		},

		CloseFn: func() error {
			return callFuncsErr(killc)
		},
	}

	lg.LogAttrs(pctx, slog.LevelInfo, "starting service")

	if err := daemon.Run(pctx, svc); err != nil {
		if !errors.Is(err, context.Canceled) {
			return err
		}
	}

	return nil
}

func rawEnvToMap(raw []string) map[string]string {
	if raw == nil {
		return nil
	}

	result := make(map[string]string)
	for i := range raw {
		if idx := strings.Index(raw[i], "="); idx >= 0 {
			result[raw[i][:idx]] = raw[i][idx+1:]
		}
	}

	return result
}

type settings struct {
	shutdownTimeout      time.Duration
	httpClientTimeout    time.Duration
	setRandomLoopTimeout time.Duration
	setRandomLoopDelay   time.Duration
	setStateLoopTimeout  time.Duration
	setStateLoopDelay    time.Duration
	torStartupTimeout    time.Duration
	torN                 int
	torMax               int
	wgParseMode          int
	defKind              string
	wgDir                string
	wgDNS                string
	port                 string
	logLvl               string
	logFmt               string
	randomiseKinds       bool
	logAddSrc            bool
}

func newSettingsFromEnv(env map[string]string) settings {
	result := settings{
		defKind: env["PUMPE_DEFAULT_KIND"],

		// Must be supplied.
		// If no wireguard is needed, specify a path to an empty directory.
		wgDir: env["PUMPE_WG_DIR"],

		wgDNS:  env["PUMPE_WG_DNS"],
		port:   env["PUMPE_PORT"],
		logLvl: env["PUMPE_LOG_LEVEL"],
		logFmt: env["PUMPE_LOG_FORMAT"],
	}

	if result.defKind == "" {
		result.defKind = "tor"
	}

	// Default to reporting errors.
	result.wgParseMode, _ = strconv.Atoi(env["PUMPE_WG_PARSE_MODE"])

	result.shutdownTimeout, _ = time.ParseDuration(env["PUMPE_SHUTDOWN_TIMEOUT"])
	if result.shutdownTimeout == 0 || result.shutdownTimeout > 60*time.Second {
		result.shutdownTimeout = 30 * time.Second
	}

	result.httpClientTimeout, _ = time.ParseDuration(env["PUMPE_HTTP_CLIENT_TIMEOUT"])
	if result.httpClientTimeout == 0 {
		result.httpClientTimeout = 60 * time.Second
	}

	result.setRandomLoopTimeout, _ = time.ParseDuration(env["PUMPE_SET_RANDOM_LOOP_TIMEOUT"])
	if result.setRandomLoopTimeout == 0 || result.setRandomLoopTimeout > 60*time.Second {
		result.setRandomLoopTimeout = 30 * time.Second
	}

	result.setRandomLoopDelay, _ = time.ParseDuration(env["PUMPE_SET_RANDOM_LOOP_DELAY"])
	if result.setRandomLoopDelay == 0 || result.setRandomLoopDelay > 100*time.Millisecond {
		result.setRandomLoopDelay = 10 * time.Millisecond
	}

	result.setStateLoopTimeout, _ = time.ParseDuration(env["PUMPE_SET_STATE_LOOP_TIMEOUT"])
	if result.setStateLoopTimeout == 0 || result.setStateLoopTimeout > 60*time.Second {
		result.setStateLoopTimeout = 30 * time.Second
	}

	result.setStateLoopDelay, _ = time.ParseDuration(env["PUMPE_SET_STATE_LOOP_DELAY"])
	if result.setStateLoopDelay == 0 || result.setStateLoopDelay > 100*time.Millisecond {
		result.setStateLoopDelay = 10 * time.Millisecond
	}

	result.torStartupTimeout, _ = time.ParseDuration(env["PUMPE_TOR_STARTUP_TIMEOUT"])
	if result.torStartupTimeout == 0 || result.torStartupTimeout < 2*time.Minute {
		// Apparently, 1 minute is not always enough.
		result.torStartupTimeout = 3 * time.Minute
	}

	result.torN, _ = strconv.Atoi(env["PUMPE_TOR_NUM"])

	// Start tor only if it's the default kind.
	// With other kinds (direct and wireguard, additional tor gates can always be started via the API).
	if result.defKind == "tor" && result.torN == 0 {
		result.torN = 4
	}

	result.torMax, _ = strconv.Atoi(env["PUMPE_TOR_MAX"])
	if result.torMax == 0 {
		result.torMax = 128
	}

	if result.wgDNS == "" {
		result.wgDNS = "9.9.9.9"
	}

	if on, _ := strconv.ParseBool(env["PUMPE_RANDOMISE_KINDS"]); on {
		result.randomiseKinds = on
	}

	if result.port == "" {
		result.port = "8080"
	}

	if result.logLvl == "" {
		result.logLvl = "INFO"
	}

	if result.logFmt == "" {
		result.logFmt = "json"
	}

	if on, _ := strconv.ParseBool(env["PUMPE_LOG_ADD_SOURCE"]); on {
		result.logAddSrc = on
	}

	return result
}

func newLogger(w io.Writer, rawLvl, format string, addSrc bool) *slog.Logger {
	var lvl slog.Level
	_ = lvl.UnmarshalText([]byte(rawLvl))

	opts := &slog.HandlerOptions{Level: lvl, AddSource: addSrc}

	var h slog.Handler

	switch format {
	case "json":
		h = slog.NewJSONHandler(w, opts)

	default:
		h = slog.NewTextHandler(w, opts)
	}

	return slog.New(h)
}

func handleWGParseErr(ctx context.Context, lg *slog.Logger, mode int, err error) error {
	switch gate.WGParseMode(mode) {
	case gate.WGParseModeReport:
		errs := model.UnwrapErrs(err)
		if errs == nil {
			return err
		}

		kind := slog.String("kind", "wireguard")
		for i := range errs {
			lg.LogAttrs(ctx, slog.LevelWarn, "unable to parse config", kind, slog.Any("error", errs[i]))
		}

		return nil

	case gate.WGParseModeIgnore:
		return nil

	default:
		return err
	}
}

func callFuncsCtxErr(ctx context.Context, fns <-chan func(context.Context) error) error {
	var errs []error
	for fn := range fns {
		if err := fn(ctx); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

func callFuncsErr(fns <-chan func() error) error {
	var errs []error
	for fn := range fns {
		if err := fn(); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}
