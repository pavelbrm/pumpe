package service

import (
	"context"

	"github.com/google/uuid"

	"github.com/pavelbrm/pumpe/gate"
)

type gateSetProxy interface {
	GateIDs(kind gate.Kind) ([]uuid.UUID, error)
	New(ctx context.Context, kind gate.Kind) (uuid.UUID, error)
	RefreshOne(ctx context.Context, id uuid.UUID) error
	CloseOne(ctx context.Context, id uuid.UUID) error
}

type Proxy struct {
	set gateSetProxy
}

func NewProxy(set gateSetProxy) *Proxy {
	result := &Proxy{
		set: set,
	}

	return result
}

func (s *Proxy) Gates(ctx context.Context) (*struct{ Direct, Tor, WireGuard []uuid.UUID }, error) {
	dct, err := s.set.GateIDs(gate.KindDirect)
	if err != nil {
		return nil, err
	}

	tgs, err := s.set.GateIDs(gate.KindTor)
	if err != nil {
		return nil, err
	}

	wgs, err := s.set.GateIDs(gate.KindWireGuard)
	if err != nil {
		return nil, err
	}

	result := &struct{ Direct, Tor, WireGuard []uuid.UUID }{
		Direct:    dct,
		Tor:       tgs,
		WireGuard: wgs,
	}

	return result, nil
}

func (s *Proxy) Create(ctx context.Context, kind gate.Kind) (uuid.UUID, error) {
	return s.set.New(ctx, kind)
}

func (s *Proxy) Refresh(ctx context.Context, id uuid.UUID) error {
	return s.set.RefreshOne(ctx, id)
}

func (s *Proxy) Stop(ctx context.Context, id uuid.UUID) error {
	return s.set.CloseOne(ctx, id)
}
