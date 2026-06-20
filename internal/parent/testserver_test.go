package parent

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"

	"github.com/ahmetozer/gosamba/internal/config"
	"github.com/ahmetozer/gosamba/internal/transport"
)

// startTestServer boots a Listener on 127.0.0.1:0 with the given users,
// shares, and ConnOptions. It returns the address string and port number.
// t.Cleanup cancels the context and closes the listener when the test ends.
func startTestServer(t *testing.T, users []config.UserConfig, shares []config.ShareConfig, opts ConnOptions) (addr string, port int) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	lg := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, cancel := context.WithCancel(context.Background())

	// Populate opts with users/shares so callers don't have to repeat them.
	opts.Users = users
	opts.Shares = shares
	// Always give the test server a durable-handle table so the durable/lease
	// CREATE path is exercised by e2e clients (smbclient itself requests
	// durable + lease contexts). A zero DurableTimeout defaults to 60s.
	if opts.Durable == nil {
		opts.Durable = NewDurableTable()
	}
	if opts.DurableTimeout == 0 {
		opts.DurableTimeout = config.Defaults().Server.DurableTimeout
	}

	srv := &Listener{
		Log:      lg,
		MaxFrame: transport.MaxFrameSize, // match the production server's limit
		Handler: func(ctx context.Context, c net.Conn, lg *slog.Logger, mf uint32) {
			ServeConn(ctx, c, lg, mf, opts)
		},
	}
	go srv.Serve(ctx, ln)

	t.Cleanup(func() {
		cancel()
		ln.Close()
	})

	tcpAddr := ln.Addr().(*net.TCPAddr)
	return ln.Addr().String(), tcpAddr.Port
}
