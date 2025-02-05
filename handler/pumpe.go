package handler

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/pavelbrm/pumpe/web"
)

type pumpeSvc interface {
	HandleConnect(ctx context.Context, w http.ResponseWriter, r *http.Request) error
	HandleHTTP(ctx context.Context, w http.ResponseWriter, r *http.Request) error
}

type Pumpe struct {
	lg  *slog.Logger
	svc pumpeSvc
}

func NewPumpe(lg *slog.Logger, svc pumpeSvc) *Pumpe {
	result := &Pumpe{
		lg:  lg,
		svc: svc,
	}

	return result
}

func (h *Pumpe) Handle(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	lg := h.lg.With(
		slog.String("handler.method", "handle"),
		slog.String("http.method", r.Method),
		slog.String("http.host", r.Host),
		slog.String("http.client.ip", r.RemoteAddr),
	)

	switch {
	case r.Method == http.MethodConnect:
		lg.LogAttrs(ctx, slog.LevelDebug, "handling request")

		if err := h.svc.HandleConnect(ctx, w, r); err != nil {
			lg.LogAttrs(ctx, slog.LevelError, "request ended with error", slog.Any("error", err))
		}

		return

	case r.URL.Scheme == "http":
		lg = lg.With(
			slog.String("http.scheme", r.URL.Scheme),
			slog.String("http.uri.path", r.URL.Path),
			slog.String("http.header.user_agent", r.UserAgent()),
		)

		lg.LogAttrs(ctx, slog.LevelDebug, "handling request")

		if err := h.svc.HandleHTTP(ctx, w, r); err != nil {
			lg.LogAttrs(ctx, slog.LevelError, "request ended with error", slog.Any("error", err))
		}

		return

	default:
		lg.LogAttrs(ctx, slog.LevelWarn, "unsupported scheme")

		_ = web.WriteError(w, http.StatusBadRequest, "unsupported scheme")

		return
	}
}
