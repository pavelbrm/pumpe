package handler

import (
	"context"
	"net/http"

	"github.com/google/uuid"

	"github.com/pavelbrm/pumpe/gate"
)

type mockPumpeSvc struct {
	fnHandleConnect func(ctx context.Context, w http.ResponseWriter, r *http.Request) error
	fnHandleHTTP    func(ctx context.Context, w http.ResponseWriter, r *http.Request) error
}

func (s *mockPumpeSvc) HandleConnect(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	if s.fnHandleConnect == nil {
		return nil
	}

	return s.fnHandleConnect(ctx, w, r)
}

func (s *mockPumpeSvc) HandleHTTP(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	if s.fnHandleHTTP == nil {
		return nil
	}

	return s.fnHandleHTTP(ctx, w, r)
}

type mockProxySvc struct {
	fnGates   func(ctx context.Context) (*struct{ Direct, Tor, WireGuard []uuid.UUID }, error)
	fnCreate  func(ctx context.Context, kind gate.Kind) (uuid.UUID, error)
	fnRefresh func(ctx context.Context, id uuid.UUID) error
	fnStop    func(ctx context.Context, id uuid.UUID) error
}

func (s *mockProxySvc) Gates(ctx context.Context) (*struct{ Direct, Tor, WireGuard []uuid.UUID }, error) {
	if s.fnGates == nil {
		return &struct {
			Direct    []uuid.UUID
			Tor       []uuid.UUID
			WireGuard []uuid.UUID
		}{}, nil
	}

	return s.fnGates(ctx)
}

func (s *mockProxySvc) Create(ctx context.Context, kind gate.Kind) (uuid.UUID, error) {
	if s.fnCreate == nil {
		return uuid.MustParse("f100ded0-0000-4000-a000-000000000000"), nil
	}

	return s.fnCreate(ctx, kind)
}

func (s *mockProxySvc) Refresh(ctx context.Context, id uuid.UUID) error {
	if s.fnRefresh == nil {
		return nil
	}

	return s.fnRefresh(ctx, id)
}

func (s *mockProxySvc) Stop(ctx context.Context, id uuid.UUID) error {
	if s.fnStop == nil {
		return nil
	}

	return s.fnStop(ctx, id)
}
