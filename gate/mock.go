package gate

import (
	"context"
	"net"
	"net/http"
	"sync/atomic"

	"github.com/google/uuid"

	"github.com/pavelbrm/pumpe/fakenet"
)

type MockExitGate struct {
	FnID   func() uuid.UUID
	FnKind func() Kind

	Reqs     struct{ Value int64 }
	FnAddReq func()
	FnDidReq func()

	Dialer *MockNetDialer
	Doer   *MockHTTPDoer
}

func (g *MockExitGate) ID() uuid.UUID {
	if g.FnID == nil {
		return uuid.MustParse("5ca1ab1e-0000-4000-a000-000000000000")
	}

	return g.FnID()
}

func (g *MockExitGate) Kind() Kind {
	if g.FnKind == nil {
		return KindDirect
	}

	return g.FnKind()
}

func (g *MockExitGate) AddReq() {
	if g.FnAddReq == nil {
		_ = atomic.AddInt64(&g.Reqs.Value, 1)

		return
	}

	g.FnAddReq()
}

func (g *MockExitGate) DidReq() {
	if g.FnDidReq == nil {
		_ = atomic.AddInt64(&g.Reqs.Value, -1)

		return
	}

	g.FnDidReq()
}

func (g *MockExitGate) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if g.Dialer == nil {
		return &fakenet.MockConn{}, nil
	}

	if g.Dialer.FnDialContext == nil {
		return &fakenet.MockConn{}, nil
	}

	return g.Dialer.FnDialContext(ctx, network, addr)
}

func (g *MockExitGate) Do(r *http.Request) (*http.Response, error) {
	if g.Doer == nil {
		return NewMockResponse(), nil
	}

	if g.Doer.FnDo == nil {
		return NewMockResponse(), nil
	}

	return g.Doer.FnDo(r)
}

type MockNetDialer struct {
	FnDialContext func(ctx context.Context, network, addr string) (net.Conn, error)
}

func (d *MockNetDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if d.FnDialContext == nil {
		return &fakenet.MockConn{}, nil
	}

	return d.FnDialContext(ctx, network, addr)
}

type MockHTTPDoer struct {
	FnDo func(r *http.Request) (*http.Response, error)
}

func (d *MockHTTPDoer) Do(r *http.Request) (*http.Response, error) {
	if d.FnDo == nil {
		return NewMockResponse(), nil
	}

	return d.FnDo(r)
}

func NewMockResponse() *http.Response {
	result := &http.Response{
		Status:     "200 OK",
		StatusCode: http.StatusOK,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Body:       http.NoBody,
		Header:     make(http.Header),
	}

	return result
}
