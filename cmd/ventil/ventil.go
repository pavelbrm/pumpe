package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	cfg := newSettingsFromEnv(rawEnvToMap(os.Environ()))
	plg := newLogger(os.Stderr, cfg.logLvl, cfg.logFmt, cfg.logAddSrc)
	lg := plg.With(slog.String("service", "ventil"))

	ctx := context.Background()
	if err := run(ctx, lg, cfg, os.Args); err != nil {
		lg.LogAttrs(ctx, slog.LevelError, "finished with error", slog.Any("error", err))

		os.Exit(1)
	}

	lg.LogAttrs(ctx, slog.LevelInfo, "finished")

	os.Exit(0)
}

func run(pctx context.Context, lg *slog.Logger, cfg settings, args []string) error {
	proxyURL, err := url.Parse(cfg.pumpeURL)
	if err != nil {
		return err
	}

	tst := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
	}

	hdr := make(http.Header)

	switch {
	case cfg.pumpeKind != "":
		hdr.Add("Proxy-Pumpe-Gate-Type", cfg.pumpeKind)
	case cfg.pumpeID != "":
		hdr.Add("Proxy-Pumpe-Gate-Id", cfg.pumpeID)
	}

	if len(hdr) > 0 {
		tst.GetProxyConnectHeader = func(ctx context.Context, proxyURL *url.URL, target string) (http.Header, error) {
			return hdr, nil
		}
	}

	cl := &http.Client{
		Timeout:   60 * time.Second,
		Transport: tst,
	}

	req, err := http.NewRequest(http.MethodGet, "https://httpbin.org/ip", nil)
	if err != nil {
		return err
	}

	resp, err := cl.Do(req)
	if err != nil {
		return err
	}

	if resp != nil && resp.Body != nil {
		defer func() { _ = resp.Body.Close() }()
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	result := &struct {
		Origin string `json:"origin"`
	}{}
	if err := json.Unmarshal(data, result); err != nil {
		return err
	}

	lg.LogAttrs(pctx, slog.LevelInfo, "received data", slog.Any("data", result))

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
	pumpeURL  string
	pumpeKind string
	pumpeID   string
	logLvl    string
	logFmt    string
	logAddSrc bool
}

func newSettingsFromEnv(env map[string]string) settings {
	result := settings{
		pumpeURL:  env["VENTIL_PUMPE_URL"],
		pumpeKind: env["VENTIL_PUMPE_KIND"],
		pumpeID:   env["VENTIL_PUMPE_ID"],
		logLvl:    env["VENTIL_LOG_LEVEL"],
		logFmt:    env["VENTIL_LOG_FORMAT"],
	}

	if result.pumpeURL == "" {
		result.pumpeURL = "http://127.0.0.1:8080"
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
