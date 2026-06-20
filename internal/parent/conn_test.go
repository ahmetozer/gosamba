package parent

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ahmetozer/gosamba/internal/smb2"
	"github.com/ahmetozer/gosamba/internal/transport"
)

type fakeConn struct {
	rd       io.Reader
	wr       io.Writer
	closed   bool
	closedMu sync.Mutex
}

func (f *fakeConn) Read(p []byte) (int, error)  { return f.rd.Read(p) }
func (f *fakeConn) Write(p []byte) (int, error) { return f.wr.Write(p) }
func (f *fakeConn) Close() error {
	f.closedMu.Lock()
	defer f.closedMu.Unlock()
	f.closed = true
	return nil
}
func (f *fakeConn) LocalAddr() net.Addr                { return &net.IPAddr{} }
func (f *fakeConn) RemoteAddr() net.Addr               { return &net.IPAddr{} }
func (f *fakeConn) SetDeadline(t time.Time) error      { return nil }
func (f *fakeConn) SetReadDeadline(t time.Time) error  { return nil }
func (f *fakeConn) SetWriteDeadline(t time.Time) error { return nil }

func TestServeConn_NegotiateThenBadSessionSetupDropsConn(t *testing.T) {
	// Negotiate succeeds; then we send a SESSION_SETUP with an empty security
	// buffer. UnwrapNTLM fails → handler returns error → ServeConn drops the
	// connection. The first frame back must be the NEGOTIATE response.
	in := &bytes.Buffer{}
	if err := transport.WriteFrame(in, buildClientNegotiate311()); err != nil {
		t.Fatal(err)
	}
	ssHdr := make([]byte, smb2.HeaderSize)
	_ = smb2.EncodeHeader(ssHdr, smb2.Header{
		CreditCharge: 1,
		Command:      smb2.CommandSessionSetup,
		MessageID:    1,
	})
	ssBody := make([]byte, 24)
	ssBody[0] = 25
	if err := transport.WriteFrame(in, append(ssHdr, ssBody...)); err != nil {
		t.Fatal(err)
	}

	out := &bytes.Buffer{}
	c := &fakeConn{rd: in, wr: out}
	lg := slog.New(slog.NewTextHandler(io.Discard, nil))

	ServeConn(context.Background(), c, lg, transport.MaxFrameSize, ConnOptions{
		RequireEncryption: true,
		RequireSigning:    true,
	})

	frame1, err := transport.ReadFrame(out, transport.MaxFrameSize)
	if err != nil {
		t.Fatal(err)
	}
	hdr1, _ := smb2.DecodeHeader(frame1[:smb2.HeaderSize])
	if hdr1.Command != smb2.CommandNegotiate || hdr1.Status != 0 {
		t.Errorf("frame 1 cmd=%s status=%x", hdr1.Command, hdr1.Status)
	}
	if !c.closed {
		t.Error("connection should be closed after malformed session-setup")
	}
}

func TestServeConn_ContextCancel(t *testing.T) {
	pr, pw := net.Pipe()
	defer pr.Close()
	defer pw.Close()

	lg := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		ServeConn(ctx, pr, lg, 64*1024, ConnOptions{})
		close(done)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ServeConn did not return after context cancel")
	}
}
