package service

import (
	"bytes"
	"context"

	"github.com/google/uuid"

	"github.com/pavelbrm/pumpe/gate"
	"github.com/pavelbrm/pumpe/model"
)

type mockWriter struct {
	fnWrite  func(p []byte) (int, error)
	fnString func() string
}

func (w *mockWriter) Write(p []byte) (int, error) {
	if w.fnWrite == nil {
		return 0, nil
	}

	return w.fnWrite(p)
}

func (w *mockWriter) String() string {
	if w.fnString == nil {
		return ""
	}

	return w.fnString()
}

type mockReadWriteCloser struct {
	*bytes.Buffer

	wclosed      bool
	rclosed      bool
	fnCloseWrite func() error
	fnCloseRead  func() error
}

func (w *mockReadWriteCloser) Write(p []byte) (int, error) {
	if w.wclosed {
		return 0, model.Error("write_closed")
	}

	return w.Buffer.Write(p)
}

func (w *mockReadWriteCloser) Read(p []byte) (int, error) {
	if w.rclosed {
		return 0, model.Error("read_closed")
	}

	return w.Buffer.Read(p)
}

func (w *mockReadWriteCloser) CloseWrite() error {
	if w.fnCloseWrite == nil {
		if w.wclosed {
			return nil
		}

		w.wclosed = true

		return nil
	}

	return w.fnCloseWrite()
}

func (w *mockReadWriteCloser) CloseRead() error {
	if w.fnCloseRead == nil {
		if w.rclosed {
			return nil
		}

		w.rclosed = true

		return nil
	}

	return w.fnCloseRead()
}

type mockGateSet struct {
	fnByID   func(id uuid.UUID) (gate.ExitGate, error)
	fnByKind func(ctx context.Context, kind gate.Kind) (gate.ExitGate, error)
	fnRandom func(ctx context.Context) (gate.ExitGate, error)
}

func (s *mockGateSet) ByID(id uuid.UUID) (gate.ExitGate, error) {
	if s.fnByID == nil {
		result := &gate.MockExitGate{
			FnID: func() uuid.UUID { return id },
		}

		return result, nil
	}

	return s.fnByID(id)
}

func (s *mockGateSet) ByKind(ctx context.Context, kind gate.Kind) (gate.ExitGate, error) {
	if s.fnByKind == nil {
		result := &gate.MockExitGate{
			FnKind: func() gate.Kind { return kind },
		}

		return result, nil
	}

	return s.fnByKind(ctx, kind)
}

func (s *mockGateSet) Random(ctx context.Context) (gate.ExitGate, error) {
	if s.fnRandom == nil {
		result := &gate.MockExitGate{}

		return result, nil
	}

	return s.fnRandom(ctx)
}

type mockGateSetProxy struct {
	fnGateIDs    func(kind gate.Kind) ([]uuid.UUID, error)
	fnNew        func(ctx context.Context, kind gate.Kind) (uuid.UUID, error)
	fnRefreshOne func(ctx context.Context, id uuid.UUID) error
	fnCloseOne   func(ctx context.Context, id uuid.UUID) error
}

func (s *mockGateSetProxy) GateIDs(kind gate.Kind) ([]uuid.UUID, error) {
	if s.fnGateIDs == nil {
		return nil, nil
	}

	return s.fnGateIDs(kind)
}

func (s *mockGateSetProxy) New(ctx context.Context, kind gate.Kind) (uuid.UUID, error) {
	if s.fnNew == nil {
		return uuid.MustParse("decade00-0000-4000-a000-000000000000"), nil
	}

	return s.fnNew(ctx, kind)
}

func (s *mockGateSetProxy) RefreshOne(ctx context.Context, id uuid.UUID) error {
	if s.fnRefreshOne == nil {
		return nil
	}

	return s.fnRefreshOne(ctx, id)
}

func (s *mockGateSetProxy) CloseOne(ctx context.Context, id uuid.UUID) error {
	if s.fnCloseOne == nil {
		return nil
	}

	return s.fnCloseOne(ctx, id)
}
