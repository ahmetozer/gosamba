// Package parent contains the privileged SMB-server bootstrap.
package parent

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/ahmetozer/gosamba/internal/config"
	"github.com/ahmetozer/gosamba/internal/smb2"
	"github.com/ahmetozer/gosamba/internal/smb3"
	"github.com/ahmetozer/gosamba/internal/transport"
)

// bufRW is a tiny io.ReadWriter that pairs a buffered reader with the raw
// writer (so writes don't pass through the buffer and stall waiting for
// bufio's internal flushing).
type bufRW struct {
	r io.Reader
	w io.Writer
}

func (b *bufRW) Read(p []byte) (int, error)  { return b.r.Read(p) }
func (b *bufRW) Write(p []byte) (int, error) { return b.w.Write(p) }

// ConnOptions controls per-connection protocol behavior.
type ConnOptions struct {
	RequireEncryption bool
	RequireSigning    bool
	MaxIOSize         uint32
	ServerStartTime   uint64
	Users             []config.UserConfig
	Shares            []config.ShareConfig

	// Durable is the server-scoped durable-handle table, created once and
	// shared across every ServeConn so durable opens survive a dropped TCP
	// connection. If nil, durable handles are not granted.
	Durable *DurableTable
	// DurableTimeout caps how long a reclaimed handle stays alive.
	DurableTimeout time.Duration

	// OnAuthenticated, if non-nil, is invoked exactly once per session-setup
	// that resolves a user (the first time the connection authenticates). The
	// worker uses this hook to drop privileges to the authenticated user's
	// uid/gid. Returning a non-nil error tears down the connection. Default
	// (nil) is a no-op — the standard in-process serving path is unchanged.
	OnAuthenticated func(sess *Session) error
}

// ServeConn drives one TCP connection through SMB2 NEGOTIATE → SESSION_SETUP.
// Anything beyond SESSION_SETUP returns STATUS_INVALID_PARAMETER (Plan 4).
func ServeConn(ctx context.Context, c net.Conn, log *slog.Logger, maxFrame uint32, opts ConnOptions) {
	defer c.Close()
	log = log.With("remote", c.RemoteAddr().String())
	log.Info("connection opened")

	go func() {
		<-ctx.Done()
		_ = c.Close()
	}()

	// Wrap the connection in a bufio.Reader so we coalesce the small
	// NBSS-header read with whatever else is on the wire — one syscall
	// instead of two per frame.
	br := bufio.NewReaderSize(c, 64*1024)
	rw := &bufRW{r: br, w: c}

	conn, err := Negotiate(rw, NegotiatorOptions{
		RequireEncryption: opts.RequireEncryption,
		RequireSigning:    opts.RequireSigning,
		MaxIOSize:         opts.MaxIOSize,
		ServerStartTime:   opts.ServerStartTime,
	}, log)
	if err != nil {
		log.Warn("negotiate failed", "err", err)
		return
	}
	conn.Durable = opts.Durable
	conn.DurableTimeout = opts.DurableTimeout

	sessions := NewSessionTable()
	// On connection drop, close every file descriptor that is NOT held by a
	// live durable-table entry. Durable opens must stay alive so the client can
	// reconnect and reclaim them; ordinary (non-durable) opens must be closed
	// to release kernel fds.
	defer func() {
		sessions.RangeSessions(func(s *Session) {
			s.RangeOpens(func(o *Open) {
				if o.File == nil {
					return
				}
				// Leave durable opens: the table owns their fd for reclaim.
				if o.IsDurable && opts.Durable != nil &&
					opts.Durable.Has(o.DurableClientGuid, o.DurableCreateGuid) {
					return
				}
				o.File.Close()
			})
		})
	}()
	ssHandler := &SessionSetupHandler{
		Conn:     conn,
		Sessions: sessions,
		Users:    opts.Users,
		Shares:   opts.Shares,
		Log:      log,
	}
	dispatcher := &Dispatcher{
		Conn:     conn,
		Sessions: sessions,
		Shares:   opts.Shares,
		Log:      log,
	}

	for {
		frame, err := transport.ReadFrame(br, maxFrame)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				log.Info("connection closed by peer")
				return
			}
			log.Warn("read error", "err", err)
			return
		}
		// SMB3 transform header: decrypt before any further handling.
		var encryptResp bool
		if smb3.IsTransform(frame) {
			if conn.Selection.Cipher == 0 {
				log.Warn("transform header received but no cipher negotiated")
				return
			}
			if len(frame) < smb3.TransformHeaderSize {
				log.Warn("transform frame too short", "len", len(frame))
				return
			}
			sessID := binary.LittleEndian.Uint64(frame[44:52])
			sess := sessions.Get(sessID)
			if sess == nil || len(sess.C2SCipherKey) == 0 {
				log.Warn("transform: unknown session or no key", "session_id", sessID)
				return
			}
			plain, _, err := smb3.DecryptTransform(uint16(conn.Selection.Cipher), sess.C2SCipherKey, frame)
			if err != nil {
				log.Warn("transform decrypt failed", "err", err)
				return
			}
			frame = plain
			encryptResp = true
			sess.GotEncrypted = true
		}

		// Walk the (possibly compound) chain, dispatching each message over
		// its own slice. Compound chains: the first message's NextCommand
		// gives the offset of the next message; subsequent messages have
		// FlagRelatedOps set. Reset per-chain state (for "previous handle"
		// FileID substitution).
		dispatcher.ResetChainState()
		dispatcher.SetEncryptForChain(encryptResp)
		off := 0
		for off < len(frame) {
			if len(frame)-off < smb2.HeaderSize {
				log.Warn("undersized frame after negotiate", "off", off, "len", len(frame))
				return
			}
			hdr, err := smb2.DecodeHeader(frame[off : off+smb2.HeaderSize])
			if err != nil {
				log.Warn("bad header", "err", err, "off", off)
				return
			}
			end := len(frame)
			if hdr.NextCommand != 0 {
				end = off + int(hdr.NextCommand)
				if end > len(frame) {
					log.Warn("NextCommand overruns frame", "next_command", hdr.NextCommand, "len", len(frame))
					return
				}
			}
			msgBytes := frame[off:end]
			body := msgBytes[smb2.HeaderSize:]

			switch hdr.Command {
			case smb2.CommandSessionSetup:
				sess, err := ssHandler.HandleSessionSetup(rw, hdr, body, msgBytes)
				if err != nil {
					log.Warn("session-setup error", "err", err)
					return
				}
				// Fire the post-auth hook once per resolved session (used by the
				// privilege-drop worker). A nil hook is the default no-op path.
				if sess != nil && opts.OnAuthenticated != nil {
					if err := opts.OnAuthenticated(sess); err != nil {
						log.Error("post-auth hook failed; closing connection", "err", err)
						return
					}
				}
			default:
				if !dispatcher.Dispatch(rw, hdr, body, msgBytes) {
					return
				}
			}

			if hdr.NextCommand == 0 {
				break
			}
			off = end
		}
	}
}
