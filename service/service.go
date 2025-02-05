package service

import (
	"context"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/google/uuid"

	"github.com/pavelbrm/pumpe/gate"
	"github.com/pavelbrm/pumpe/model"
	"github.com/pavelbrm/pumpe/web"
)

const (
	headerProxyGateID   = "Proxy-Pumpe-Gate-Id"
	headerProxyGateType = "Proxy-Pumpe-Gate-Type"
)

type gateSet interface {
	ByID(id uuid.UUID) (gate.ExitGate, error)
	ByKind(ctx context.Context, kind gate.Kind) (gate.ExitGate, error)
	Random(ctx context.Context) (gate.ExitGate, error)
}

type readCloser interface {
	CloseRead() error
}

type writeCloser interface {
	CloseWrite() error
}

type Pumpe struct {
	hopHdr  []string
	data200 []byte
	set     gateSet
}

func NewPumpe(set gateSet) *Pumpe {
	result := &Pumpe{
		hopHdr:  newHopHeaders(),
		data200: []byte("HTTP/1.1 200 Connection established\r\n\r\n"),
		set:     set,
	}

	return result
}

func (s *Pumpe) HandleConnect(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	hj, ok := w.(http.Hijacker)
	if !ok {
		return model.ErrHijackingNotSupported
	}

	srcConn, _, err := hj.Hijack()
	if err != nil {
		return err
	}
	defer func() { _ = srcConn.Close() }()

	dialer, err := s.pickDialer(ctx, r.Header)
	if err != nil {
		_ = writeErrToConn(srcConn, err)

		return err
	}

	dialer.AddReq()
	defer func() { dialer.DidReq() }()

	addr := remoteAddrFromHost(r.Host)

	dstConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		_ = writeErrToConn(srcConn, err)

		return err
	}
	defer func() { _ = dstConn.Close() }()

	if _, err := srcConn.Write(s.data200); err != nil {
		return err
	}

	wg := &sync.WaitGroup{}
	wg.Add(2)

	go func() {
		defer wg.Done()

		xferData(dstConn, srcConn)
	}()

	go func() {
		defer wg.Done()

		xferData(srcConn, dstConn)
	}()

	wg.Wait()

	return nil
}

func (s *Pumpe) HandleHTTP(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	dialer, err := s.pickDialer(ctx, r.Header)
	if err != nil {
		return err
	}

	dialer.AddReq()
	defer func() { dialer.DidReq() }()

	r.RequestURI = ""

	delHeaders(s.hopHdr, r.Header)
	delConnectionHeaders(r.Header)

	if ip, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		addHostToXForwardedHeader(r.Header, ip)
	}

	resp, err := dialer.Do(r)
	if err != nil {
		_ = web.WriteError(w, http.StatusBadGateway, "server error")

		return err
	}

	if resp != nil && resp.Body != nil {
		defer func() { _ = resp.Body.Close() }()
	}

	delHeaders(s.hopHdr, resp.Header)
	delConnectionHeaders(resp.Header)

	copyHeader(w.Header(), resp.Header)

	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)

	return nil
}

func (s *Pumpe) pickDialer(ctx context.Context, hdr http.Header) (gate.ExitGate, error) {
	if id := hdr.Get(headerProxyGateID); id != "" {
		id, err := uuid.Parse(id)
		if err != nil {
			return nil, model.ErrInvalidUUID
		}

		return s.set.ByID(id)
	}

	if kind := hdr.Get(headerProxyGateType); kind != "" {
		return s.set.ByKind(ctx, gate.Kind(kind))
	}

	// Default to a random gate.
	return s.set.Random(ctx)
}

// newHopHeaders returns a list of hop-by-hop headers.
func newHopHeaders() []string {
	result := []string{
		"Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Proxy-Connection",
		"Te",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
		headerProxyGateID,
		headerProxyGateType,
	}

	return result
}

func delHeaders(list []string, hdr http.Header) {
	for i := range list {
		hdr.Del(list[i])
	}
}

// delConnectionHeaders deletes hop-by-hop "Connection" headers from hdr.
func delConnectionHeaders(hdr http.Header) {
	h := hdr["Connection"]

	for i := range h {
		ss := strings.Split(h[i], ",")
		for j := range ss {
			if v := strings.TrimSpace(ss[j]); v != "" {
				hdr.Del(v)
			}
		}
	}
}

func addHostToXForwardedHeader(hdr http.Header, host string) {
	if ex, ok := hdr["X-Forwarded-For"]; ok {
		host = strings.Join(ex, ", ") + ", " + host
	}

	hdr.Set("X-Forwarded-For", host)
}

func copyHeader(dst, src http.Header) {
	for k := range src {
		for i := range src[k] {
			dst.Add(k, src[k][i])
		}
	}
}

func remoteAddrFromHost(host string) string {
	result := host
	if !strings.Contains(host, ":") {
		result = net.JoinHostPort(result, "443")
	}

	return result
}

func xferData(dst io.Writer, src io.Reader) {
	_, _ = io.Copy(dst, src)

	if wc, ok := dst.(writeCloser); ok {
		_ = wc.CloseWrite()
	}

	if rc, ok := src.(readCloser); ok {
		_ = rc.CloseRead()
	}
}

func writeErrToConn(dst io.Writer, rerr error) error {
	if rerr == nil {
		return nil
	}

	errm := rerr.Error()
	msg := "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: " + strconv.Itoa(len(errm)) + "\r\n\r\n" + errm

	_, err := io.WriteString(dst, msg)

	return err
}
