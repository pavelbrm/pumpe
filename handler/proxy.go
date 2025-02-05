package handler

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	"github.com/julienschmidt/httprouter"

	"github.com/pavelbrm/pumpe/gate"
	"github.com/pavelbrm/pumpe/model"
)

type proxySvc interface {
	Gates(ctx context.Context) (*struct{ Direct, Tor, WireGuard []uuid.UUID }, error)
	Create(ctx context.Context, kind gate.Kind) (uuid.UUID, error)
	Refresh(ctx context.Context, id uuid.UUID) error
	Stop(ctx context.Context, id uuid.UUID) error
}

type Proxy struct {
	lg    *slog.Logger
	svc   proxySvc
	empty []byte
}

func NewProxy(lg *slog.Logger, svc proxySvc) *Proxy {
	result := &Proxy{
		lg:    lg,
		svc:   svc,
		empty: []byte{'{', '}'},
	}

	return result
}

func (h *Proxy) List(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	lg := h.lg.With(slog.String("handler.method", "list"))

	ctx := r.Context()

	gids, err := h.svc.Gates(ctx)
	if err != nil {
		switch {
		case errors.Is(err, context.Canceled):
			lg.LogAttrs(ctx, slog.LevelError, "cancelled request", slog.Any("error", err))

			_ = respondWithErrJSON(w, err, model.StatusClientClosedConn)
			return

		case errors.Is(err, gate.ErrKindUnknown):
			lg.LogAttrs(ctx, slog.LevelError, "requested unknown gate kind", slog.Any("error", err))

			_ = respondWithErrJSON(w, err, http.StatusBadRequest)
			return

		default:
			lg.LogAttrs(ctx, slog.LevelError, "could not fetch gate ids", slog.Any("error", err))

			_ = respondWithErrJSON(w, err, http.StatusInternalServerError)
			return
		}
	}

	lg.LogAttrs(ctx, slog.LevelInfo, "fetched gate ids")

	result := &struct {
		Direct    []uuid.UUID `json:"direct"`
		Tor       []uuid.UUID `json:"tor"`
		WireGuard []uuid.UUID `json:"wireguard"`
	}{
		Direct:    gids.Direct,
		Tor:       gids.Tor,
		WireGuard: gids.WireGuard,
	}

	// Non-Go clients might not understand Go JSON encoding rules.
	if result.Direct == nil {
		result.Direct = []uuid.UUID{}
	}

	if result.Tor == nil {
		result.Tor = []uuid.UUID{}
	}

	if result.WireGuard == nil {
		result.WireGuard = []uuid.UUID{}
	}

	_ = respondWithDataJSON(w, result, http.StatusOK)
}

func (h *Proxy) Create(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	lg := h.lg.With(slog.String("handler.method", "create"))

	ctx := r.Context()

	raw, err := io.ReadAll(r.Body)
	if err != nil {
		lg.LogAttrs(ctx, slog.LevelError, "failed to read request", slog.Any("error", err))

		_ = respondWithErrJSON(w, err, http.StatusBadRequest)
		return
	}

	req := &struct {
		Kind gate.Kind `json:"kind"`
	}{}
	if err := json.Unmarshal(raw, req); err != nil {
		lg.LogAttrs(ctx, slog.LevelError, "failed to parse request", slog.Any("error", err))

		_ = respondWithErrJSON(w, err, http.StatusBadRequest)
		return
	}

	id, err := h.svc.Create(ctx, req.Kind)
	if err != nil {
		switch {
		case errors.Is(err, context.Canceled):
			lg.LogAttrs(ctx, slog.LevelError, "cancelled request", slog.Any("error", err))

			_ = respondWithErrJSON(w, err, model.StatusClientClosedConn)
			return

		case errors.Is(err, gate.ErrSetIsShutting):
			lg.LogAttrs(ctx, slog.LevelError, "service is shutting down", slog.Any("error", err))

			_ = respondWithErrJSON(w, err, http.StatusBadGateway)
			return

		case errors.Is(err, gate.ErrKindNotSupported):
			lg.LogAttrs(ctx, slog.LevelError, "requested unsupported gate kind", slog.Any("error", err))

			_ = respondWithErrJSON(w, err, http.StatusUnprocessableEntity)
			return

		case errors.Is(err, gate.ErrTorMaxReached):
			lg.LogAttrs(ctx, slog.LevelError, "reached maximum number of tor gates", slog.Any("error", err))

			_ = respondWithErrJSON(w, err, http.StatusConflict)
			return

		default:
			lg.LogAttrs(ctx, slog.LevelError, "could not create new gate", slog.Any("error", err))

			_ = respondWithErrJSON(w, err, http.StatusInternalServerError)
			return
		}
	}

	lg.LogAttrs(ctx, slog.LevelInfo, "created new gate", slog.String("kind", req.Kind.String()), slog.String("id", id.String()))

	result := &struct {
		ID uuid.UUID `json:"id"`
	}{
		ID: id,
	}

	_ = respondWithDataJSON(w, result, http.StatusCreated)
}

func (h *Proxy) Refresh(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	lg := h.lg.With(slog.String("handler.method", "refresh"))

	ctx := r.Context()

	gid := p.ByName("id")
	if gid == "" {
		lg.LogAttrs(ctx, slog.LevelError, "invalid param", slog.String("param.name", "id"))

		_ = respondWithErrJSON(w, model.ErrInvalidParam, http.StatusBadRequest)
		return
	}

	id, err := uuid.Parse(gid)
	if err != nil {
		lg.LogAttrs(ctx, slog.LevelError, "failed to parse uuid", slog.Any("error", err))

		_ = respondWithErrJSON(w, model.ErrInvalidUUID, http.StatusBadRequest)
		return
	}

	if err := h.svc.Refresh(ctx, id); err != nil {
		switch {
		case errors.Is(err, context.Canceled):
			lg.LogAttrs(ctx, slog.LevelError, "cancelled request", slog.Any("error", err))

			_ = respondWithErrJSON(w, err, model.StatusClientClosedConn)
			return

		case errors.Is(err, context.DeadlineExceeded):
			lg.LogAttrs(ctx, slog.LevelError, "request timed out", slog.Any("error", err))

			_ = respondWithErrJSON(w, err, http.StatusGatewayTimeout)
			return

		case errors.Is(err, gate.ErrSetIsShutting):
			lg.LogAttrs(ctx, slog.LevelError, "service is shutting down", slog.Any("error", err))

			_ = respondWithErrJSON(w, err, http.StatusBadGateway)
			return

		case errors.Is(err, gate.ErrGateNotFound):
			lg.LogAttrs(ctx, slog.LevelError, "requested gate not found", slog.Any("error", err))

			_ = respondWithErrJSON(w, err, http.StatusNotFound)
			return

		case errors.Is(err, gate.ErrKindNotSupported):
			lg.LogAttrs(ctx, slog.LevelError, "requested unsupported gate kind", slog.Any("error", err))

			_ = respondWithErrJSON(w, err, http.StatusUnprocessableEntity)
			return

		case errors.Is(err, gate.ErrGateIsRefreshing):
			lg.LogAttrs(ctx, slog.LevelError, "gate is refreshing", slog.Any("error", err))

			_ = respondWithErrJSON(w, err, http.StatusConflict)
			return

		default:
			lg.LogAttrs(ctx, slog.LevelError, "could not refresh gate", slog.Any("error", err))

			_ = respondWithErrJSON(w, err, http.StatusInternalServerError)
			return
		}
	}

	lg.LogAttrs(ctx, slog.LevelInfo, "refreshed gate", slog.String("id", id.String()))

	_ = respondWithJSON(w, h.empty, http.StatusOK)
}

func (h *Proxy) Stop(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	lg := h.lg.With(slog.String("handler.method", "stop"))

	ctx := r.Context()

	gid := p.ByName("id")
	if gid == "" {
		lg.LogAttrs(ctx, slog.LevelError, "invalid param", slog.String("param.name", "id"))

		_ = respondWithErrJSON(w, model.ErrInvalidParam, http.StatusBadRequest)
		return
	}

	id, err := uuid.Parse(gid)
	if err != nil {
		lg.LogAttrs(ctx, slog.LevelError, "failed to parse uuid", slog.Any("error", err))

		_ = respondWithErrJSON(w, model.ErrInvalidUUID, http.StatusBadRequest)
		return
	}

	if err := h.svc.Stop(ctx, id); err != nil {
		switch {
		case errors.Is(err, context.Canceled):
			lg.LogAttrs(ctx, slog.LevelError, "cancelled request", slog.Any("error", err))

			_ = respondWithErrJSON(w, err, model.StatusClientClosedConn)
			return

		case errors.Is(err, context.DeadlineExceeded):
			lg.LogAttrs(ctx, slog.LevelError, "request timed out", slog.Any("error", err))

			_ = respondWithErrJSON(w, err, http.StatusGatewayTimeout)
			return

		case errors.Is(err, gate.ErrSetIsShutting):
			lg.LogAttrs(ctx, slog.LevelError, "service is shutting down", slog.Any("error", err))

			_ = respondWithErrJSON(w, err, http.StatusBadGateway)
			return

		case errors.Is(err, gate.ErrGateNotFound):
			lg.LogAttrs(ctx, slog.LevelError, "requested gate not found", slog.Any("error", err))

			_ = respondWithErrJSON(w, err, http.StatusNotFound)
			return

		case errors.Is(err, gate.ErrKindNotSupported):
			lg.LogAttrs(ctx, slog.LevelError, "requested unsupported gate kind", slog.Any("error", err))

			_ = respondWithErrJSON(w, err, http.StatusUnprocessableEntity)
			return

		default:
			lg.LogAttrs(ctx, slog.LevelError, "could not stop gate", slog.Any("error", err))

			_ = respondWithErrJSON(w, err, http.StatusInternalServerError)
			return
		}
	}

	lg.LogAttrs(ctx, slog.LevelInfo, "stopped gate", slog.String("id", id.String()))

	_ = respondWithJSON(w, h.empty, http.StatusOK)
}
