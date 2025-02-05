// Package web provides tools for creating and running a web service.
package web

import (
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/julienschmidt/httprouter"
)

const (
	errPanicked = Error("web: app panicked")
)

type App struct {
	lg  *slog.Logger
	mux *httprouter.Router

	empty  []byte
	jempty []byte
}

func NewApp(lg *slog.Logger) *App {
	result := &App{
		lg:     lg,
		empty:  []byte{},
		jempty: []byte{'{', '}'},
	}

	mux := httprouter.New()
	mux.PanicHandler = result.handlePanic
	mux.NotFound = http.HandlerFunc(result.handle404)

	result.mux = mux

	return result
}

func (h *App) Handle(method, path string, fn httprouter.Handle) {
	h.mux.Handle(method, path, fn)
}

func (h *App) Handler(method, path string, fn http.Handler) {
	h.mux.Handler(method, path, fn)
}

func (h *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now().UTC()

	h.mux.ServeHTTP(w, r)

	attrs := lattrsFromReq(r)
	attrs = append(attrs, slog.Float64("http.latency", time.Since(start).Seconds()))

	h.lg.LogAttrs(r.Context(), slog.LevelInfo, "finished request", attrs...)
}

func (h *App) Set404(nfh http.Handler) {
	h.mux.NotFound = nfh
}

func (h *App) handlePanic(w http.ResponseWriter, r *http.Request, rcv interface{}) {
	if rcv == nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write(h.empty)
		return
	}

	var err error
	switch perr := rcv.(type) {
	case string:
		err = Error(perr)
	case error:
		err = perr
	default:
		err = errPanicked
	}

	attrs := []slog.Attr{
		slog.Any("error", err),
		slog.String("stacktrace", string(debug.Stack())),
	}

	h.lg.LogAttrs(r.Context(), slog.LevelError, "recovered panic", attrs...)

	w.WriteHeader(http.StatusInternalServerError)
	_, _ = w.Write(h.empty)
}

func (h *App) handle404(w http.ResponseWriter, r *http.Request) {
	h.lg.LogAttrs(r.Context(), slog.LevelWarn, "route not found", lattrsFromReq(r)...)

	w.Header().Set("X-Content-Type-Options", "nosniff")

	switch r.Header.Get("Content-Type") {
	case "application/json":
		w.Header().Set("Content-Type", "application/json")

		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write(h.jempty)

	default:
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write(h.empty)
	}
}

type Error string

func (e Error) Error() string {
	return string(e)
}

func WriteError(w http.ResponseWriter, code int, text string) error {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	w.WriteHeader(code)
	_, err := w.Write([]byte(text))

	return err
}

func lattrsFromReq(r *http.Request) []slog.Attr {
	result := []slog.Attr{
		slog.String("http.host", r.Host),
		slog.String("http.method", r.Method),
		slog.String("http.client.ip", r.RemoteAddr),
		slog.String("http.uri.path", r.URL.Path),
		slog.String("http.header.user_agent", r.UserAgent()),
	}

	return result
}
