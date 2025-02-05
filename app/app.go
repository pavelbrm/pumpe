package app

import (
	"log/slog"
	"net/http"

	"github.com/julienschmidt/httprouter"

	"github.com/pavelbrm/pumpe/gate"
	"github.com/pavelbrm/pumpe/handler"
	"github.com/pavelbrm/pumpe/service"
	"github.com/pavelbrm/pumpe/web"
)

func NewWeb(lg *slog.Logger, set *gate.Set) *web.App {
	// System log messages are made from the app itself.
	result := web.NewApp(lg.With(slog.String("app", "web")))

	{
		svc := service.NewPumpe(set)
		h := handler.NewPumpe(lg.With(slog.String("handler.name", "pumpe")), svc)

		// Register the pumpe handler as the catch-all handler:
		// - https requests come with an empty path, which is illegal to reguster in the router;
		// - http requests may contain anything in the path.
		result.Set404(http.HandlerFunc(h.Handle))

		// Register the handler at / as well for clarity.
		methods := []string{
			http.MethodGet, http.MethodHead,
			http.MethodPost, http.MethodPut, http.MethodPatch,
			http.MethodDelete,
			http.MethodConnect, http.MethodOptions, http.MethodTrace,
		}

		for i := range methods {
			result.Handle(methods[i], "/", newRouterHandle(h.Handle))
		}
	}

	{
		svc := service.NewProxy(set)
		h := handler.NewProxy(lg.With(slog.String("handler.name", "proxy")), svc)

		result.Handle(http.MethodGet, "/v1/_service/gates", h.List)
		result.Handle(http.MethodPost, "/v1/_service/gates", h.Create)
		result.Handle(http.MethodPatch, "/v1/_service/gates/:id", h.Refresh)
		result.Handle(http.MethodDelete, "/v1/_service/gates/:id", h.Stop)
	}

	{
		h := handler.NewHealth()

		result.Handle(http.MethodGet, "/v1/_internal/status", h.Status)
	}

	return result
}

func newRouterHandle(h http.HandlerFunc) httprouter.Handle {
	result := func(w http.ResponseWriter, r *http.Request, p httprouter.Params) { h(w, r) }

	return result
}
