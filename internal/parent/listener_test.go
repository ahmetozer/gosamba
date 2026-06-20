package parent

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ahmetozer/gosamba/internal/smb2"
	"github.com/ahmetozer/gosamba/internal/transport"
)

func TestListener_AcceptsAndDispatches(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	var logbuf bytes.Buffer
	var logmu sync.Mutex
	lg := slog.New(slog.NewTextHandler(&lockedWriter{w: &logbuf, mu: &logmu}, &slog.HandlerOptions{Level: slog.LevelDebug}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv := &Listener{
		Log:      lg,
		MaxFrame: 64 * 1024,
		Handler: func(ctx context.Context, c net.Conn, lg *slog.Logger, mf uint32) {
			ServeConn(ctx, c, lg, mf, ConnOptions{RequireEncryption: true, RequireSigning: true})
		},
	}

	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln) }()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if err := transport.WriteFrame(conn, buildClientNegotiate311()); err != nil {
		t.Fatal(err)
	}
	resp, err := transport.ReadFrame(conn, transport.MaxFrameSize)
	if err != nil {
		t.Fatal(err)
	}
	hdr, _ := smb2.DecodeHeader(resp[:smb2.HeaderSize])
	if hdr.Command != smb2.CommandNegotiate || hdr.Status != 0 {
		t.Errorf("bad response cmd=%s status=%x", hdr.Command, hdr.Status)
	}
	conn.Close()

	time.Sleep(100 * time.Millisecond)

	logmu.Lock()
	logs := logbuf.String()
	logmu.Unlock()
	if !strings.Contains(logs, "negotiated") {
		t.Errorf("expected 'negotiated' log, got:\n%s", logs)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve returned %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after cancel")
	}
}

type lockedWriter struct {
	w  io.Writer
	mu *sync.Mutex
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}
