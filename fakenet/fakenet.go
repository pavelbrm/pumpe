package fakenet

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"time"
)

type MockConn struct {
	Recv   io.Reader
	FnRead func(b []byte) (int, error)

	Send    *bytes.Buffer
	FnWrite func(b []byte) (int, error)

	FnClose      func() error
	FnLocalAddr  func() net.Addr
	FnRemoteAddr func() net.Addr

	FnSetDeadline      func(t time.Time) error
	FnSetReadDeadline  func(t time.Time) error
	FnSetWriteDeadline func(t time.Time) error
}

func (c *MockConn) Read(b []byte) (int, error) {
	if c.FnRead == nil && c.Recv == nil {
		return 0, io.EOF
	}

	if c.FnRead == nil && c.Recv != nil {
		return c.Recv.Read(b)
	}

	return c.FnRead(b)
}

func (c *MockConn) Write(b []byte) (int, error) {
	if c.FnWrite == nil && c.Send == nil {
		return 0, nil
	}

	if c.FnWrite == nil && c.Send != nil {
		return c.Send.Write(b)
	}

	return c.FnWrite(b)
}

func (c *MockConn) Close() error {
	if c.FnClose == nil {
		return nil
	}

	return c.FnClose()
}

func (c *MockConn) LocalAddr() net.Addr {
	if c.FnLocalAddr == nil {
		result := &net.TCPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: 1234,
		}

		return result
	}

	return c.FnLocalAddr()
}

func (c *MockConn) RemoteAddr() net.Addr {
	if c.FnRemoteAddr == nil {
		result := &net.TCPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: 4321,
		}

		return result
	}

	return c.FnRemoteAddr()
}

func (c *MockConn) SetDeadline(t time.Time) error {
	if c.FnSetDeadline == nil {
		return nil
	}

	return c.FnSetDeadline(t)
}

func (c *MockConn) SetReadDeadline(t time.Time) error {
	if c.FnSetReadDeadline == nil {
		return nil
	}

	return c.FnSetReadDeadline(t)
}

func (c *MockConn) SetWriteDeadline(t time.Time) error {
	if c.FnSetWriteDeadline == nil {
		return nil
	}

	return c.FnSetWriteDeadline(t)
}

type ResponseRecorderHJ struct {
	*httptest.ResponseRecorder
	recv     *bufio.Reader
	snd      *bufio.Writer
	conn     *MockConn
	FnHijack func() (net.Conn, *bufio.ReadWriter, error)
}

func NewResponseRecorderHJ(input []byte) *ResponseRecorderHJ {
	rw := httptest.NewRecorder()

	recv := bufio.NewReader(bytes.NewBuffer(input))
	snd := bufio.NewWriter(rw.Body)

	result := &ResponseRecorderHJ{
		ResponseRecorder: rw,
		recv:             recv,
		snd:              snd,

		// Imitate a server-client connection on the server side:
		// - receiving from the buffer.
		// - sending to the response recorder;
		conn: &MockConn{Recv: recv, Send: rw.Body},
	}

	return result
}

func (r *ResponseRecorderHJ) Header() http.Header {
	return r.ResponseRecorder.Header()
}

func (r *ResponseRecorderHJ) Write(b []byte) (int, error) {
	return r.ResponseRecorder.Write(b)
}

func (r *ResponseRecorderHJ) WriteHeader(code int) {
	r.ResponseRecorder.WriteHeader(code)
}

func (r *ResponseRecorderHJ) WriteString(s string) (int, error) {
	return r.ResponseRecorder.WriteString(s)
}

func (r *ResponseRecorderHJ) Flush() {
	r.ResponseRecorder.Flush()
}

func (r *ResponseRecorderHJ) Result() *http.Response {
	return r.ResponseRecorder.Result()
}

func (r *ResponseRecorderHJ) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if r.FnHijack != nil {
		return r.FnHijack()
	}

	return r.conn, bufio.NewReadWriter(r.recv, r.snd), nil
}

func (r *ResponseRecorderHJ) Conn() net.Conn {
	return r.conn
}

func (r *ResponseRecorderHJ) ConnT() *MockConn {
	return r.conn
}
