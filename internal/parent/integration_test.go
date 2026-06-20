package parent

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ahmetozer/gosamba/internal/smb2"
	"github.com/ahmetozer/gosamba/internal/transport"
)

func TestIntegration_MultipleConnections(t *testing.T) {
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

	const N = 5
	negotiateFrame := buildClientNegotiate311()
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			conn, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Errorf("dial %d: %v", i, err)
				return
			}
			defer conn.Close()
			if err := transport.WriteFrame(conn, negotiateFrame); err != nil {
				t.Errorf("write %d: %v", i, err)
				return
			}
			resp, err := transport.ReadFrame(conn, transport.MaxFrameSize)
			if err != nil {
				t.Errorf("read %d: %v", i, err)
				return
			}
			hdr, _ := smb2.DecodeHeader(resp[:smb2.HeaderSize])
			if hdr.Command != smb2.CommandNegotiate || hdr.Status != 0 {
				t.Errorf("conn %d: bad response cmd=%s status=%x", i, hdr.Command, hdr.Status)
			}
		}(i)
	}
	wg.Wait()

	time.Sleep(150 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("serve returned %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("serve did not return")
	}

	logmu.Lock()
	logs := logbuf.String()
	logmu.Unlock()
	if !strings.Contains(logs, "negotiated") {
		t.Errorf("expected 'negotiated' log line, got:\n%s", logs)
	}
}
