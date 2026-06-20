package parent

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"
)

// ConnHandler handles a single accepted connection. It must close the
// connection before returning.
type ConnHandler func(ctx context.Context, c net.Conn, log *slog.Logger, maxFrame uint32)

// Listener owns the accept loop. Reusable across plans.
type Listener struct {
	Log      *slog.Logger
	MaxFrame uint32
	Handler  ConnHandler

	// ReExec, when true, serves each accepted connection by re-exec'ing a
	// worker process (which drops privileges to the authenticated user) instead
	// of calling Handler in-process. The default (false) preserves the original
	// in-process serving path byte-for-byte.
	ReExec bool
}

// Serve runs the accept loop until ctx is cancelled or ln returns a permanent
// error.
func (s *Listener) Serve(ctx context.Context, ln net.Listener) error {
	if s.Handler == nil {
		return errors.New("listener: Handler is nil")
	}
	if s.MaxFrame == 0 {
		return errors.New("listener: MaxFrame is zero")
	}

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	var wg sync.WaitGroup
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				wg.Wait()
				return nil
			}
			s.Log.Error("accept failed", "err", err)
			wg.Wait()
			return err
		}
		// SMB is roundtrip-bound; explicitly disable Nagle. Go enables this
		// by default but proxies/tunnels can re-enable it.
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.SetNoDelay(true)
			_ = tc.SetKeepAlive(true)
		}
		if s.ReExec {
			// Hand the connection off to a worker process that owns it entirely
			// and drops privileges after auth. The parent does NOT serve it.
			if err := reExecWorker(conn, s.Log); err != nil {
				s.Log.Error("re-exec worker failed; dropping connection", "err", err)
			}
			_ = conn.Close() // parent always closes its copy of the fd
			continue
		}
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			s.Handler(ctx, c, s.Log, s.MaxFrame)
		}(conn)
	}
}
