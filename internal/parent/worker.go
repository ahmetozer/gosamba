package parent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"syscall"

	"github.com/ahmetozer/gosamba/internal/config"
)

// workerEnvKey is the marker env var set on the re-exec'd worker child. When
// present the process serves exactly one connection (inherited as fd 3) instead
// of binding the listener.
const workerEnvKey = "GOSAMBA_WORKER"

// workerConnFD is the fixed file-descriptor number the accepted connection
// lands on inside the worker child. exec.Cmd.ExtraFiles[0] maps to fd 3.
const workerConnFD = 3

// IsWorker reports whether the current process is a re-exec'd worker that
// should serve a single inherited connection rather than bind the listener.
func IsWorker() bool {
	return os.Getenv(workerEnvKey) == "1"
}

// privDropPlan describes a privilege-drop decision computed from the
// authenticated user's identity and the current process state. It is a pure
// data value so the gating logic can be unit-tested without performing the
// destructive Setresuid/Setresgid syscalls.
type privDropPlan struct {
	// Drop is true when dropPrivileges should perform the syscalls.
	Drop bool
	// Skip is true when dropping is intentionally a no-op (e.g. the target is
	// already the current identity, or the process is not privileged enough).
	Skip bool
	// Reason is a human-readable explanation for logging.
	Reason string
	// UID/GID/Groups are the target identity used when Drop is true.
	UID    int
	GID    int
	Groups []int
}

// decidePrivDrop computes the privilege-drop plan for a target uid/gid given
// the process's current euid. It is pure (no syscalls) so it can be tested.
//
// Rules:
//   - Not root (euid != 0): cannot change uid; Skip with a warning reason.
//   - Target uid == current euid: nothing to do; Skip (no-op, still "works").
//   - Otherwise: Drop to the target identity.
func decidePrivDrop(euid, targetUID, targetGID int, groups []int) privDropPlan {
	if euid != 0 {
		return privDropPlan{
			Skip:   true,
			Reason: fmt.Sprintf("not running as root (euid=%d); cannot drop to uid=%d", euid, targetUID),
			UID:    targetUID, GID: targetGID, Groups: groups,
		}
	}
	if targetUID == euid {
		// Dropping to the current (root) identity is a no-op but must still
		// succeed — the serving path continues unchanged.
		return privDropPlan{
			Skip:   true,
			Reason: fmt.Sprintf("target uid=%d equals current euid; no drop needed", targetUID),
			UID:    targetUID, GID: targetGID, Groups: groups,
		}
	}
	return privDropPlan{
		Drop:   true,
		Reason: fmt.Sprintf("dropping to uid=%d gid=%d", targetUID, targetGID),
		UID:    targetUID, GID: targetGID, Groups: groups,
	}
}

// dropPrivileges permanently drops the WHOLE PROCESS (all OS threads) to the
// given uid/gid and supplementary groups.
//
// It uses the Go standard library syscall package on purpose: since Go 1.16 the
// stdlib Setresuid/Setresgid/Setgroups (and the Setuid/Setgid family) are
// implemented as process-wide operations — the runtime coordinates every thread
// so the credential change applies to all of them, not just the caller. This is
// exactly what we need: a goroutine that later runs on a different thread (e.g.
// the async CHANGE_NOTIFY handler) must also be unprivileged. The raw
// golang.org/x/sys/unix calls only affect the calling thread and would leave a
// security hole, so they must NOT be used here.
//
// The order is mandatory: set supplementary groups, then gid, then uid LAST —
// once uid is dropped you can no longer change the group set. Saved-ids are set
// equal to the real/effective ids so privileges cannot be regained.
func dropPrivileges(uid, gid int, groups []int) error {
	plan := decidePrivDrop(syscall.Geteuid(), uid, gid, groups)
	return applyPrivDrop(plan)
}

// applyPrivDrop performs the syscalls described by plan. Separated from
// decidePrivDrop so the decision can be tested without the destructive calls.
func applyPrivDrop(plan privDropPlan) error {
	if !plan.Drop {
		return nil
	}
	// Supplementary groups first (requires privilege; lost after uid drop).
	g := plan.Groups
	if g == nil {
		g = []int{plan.GID}
	}
	if err := syscall.Setgroups(g); err != nil {
		return fmt.Errorf("setgroups %v: %w", g, err)
	}
	// gid before uid; set saved-gid too.
	if err := syscall.Setresgid(plan.GID, plan.GID, plan.GID); err != nil {
		return fmt.Errorf("setresgid %d: %w", plan.GID, err)
	}
	// uid last; set saved-uid too so root cannot be regained.
	if err := syscall.Setresuid(plan.UID, plan.UID, plan.UID); err != nil {
		return fmt.Errorf("setresuid %d: %w", plan.UID, err)
	}
	// Verify the drop actually stuck — defence in depth.
	if syscall.Geteuid() != plan.UID {
		return fmt.Errorf("privilege drop verification failed: euid=%d want=%d", syscall.Geteuid(), plan.UID)
	}
	return nil
}

// ShouldUsePrivdropWorker reports whether the listener should serve connections
// via re-exec workers. It is pure (decision uses the supplied euid) so the
// gating can be unit-tested.
//
// The worker model is used when:
//   - explicit is true (the operator set PerUserPrivdrop), OR
//   - the process is root (euid==0) AND at least one configured user maps to a
//     non-root SystemUID (auto-enable: there is something meaningful to drop to).
//
// In all other cases connections are served in-process unchanged. When explicit
// is true but euid!=0, the caller should warn — drops will be skipped per
// connection, but we still avoid changing behavior silently.
func ShouldUsePrivdropWorker(explicit bool, euid int, users []config.UserConfig) bool {
	if explicit {
		return true
	}
	if euid != 0 {
		return false
	}
	for _, u := range users {
		if u.SystemUID != 0 {
			return true
		}
	}
	return false
}

// reExecWorker launches a worker child for the accepted connection. It passes
// the connection's underlying fd as the child's fd 3 via ExtraFiles, marks the
// child with GOSAMBA_WORKER=1, and re-uses the parent's argv so the child
// re-parses the identical configuration from scratch (no secrets cross the
// process boundary — only the socket fd). The parent does NOT serve the
// connection itself.
//
// The caller is responsible for closing its own copy of conn after this
// returns; reExecWorker only duplicates the fd into the child.
func reExecWorker(conn net.Conn, log *slog.Logger) error {
	fc, ok := conn.(filer)
	if !ok {
		return fmt.Errorf("connection %T does not expose a file descriptor", conn)
	}
	f, err := fc.File()
	if err != nil {
		return fmt.Errorf("conn.File: %w", err)
	}
	// f is a dup of the conn's fd; the worker inherits it. Close our copy once
	// the child has started.
	defer f.Close()

	exe, err := os.Executable()
	if err != nil {
		exe = "/proc/self/exe"
	}

	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.Env = append(os.Environ(), workerEnvKey+"=1")
	cmd.Stdin = nil
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.ExtraFiles = []*os.File{f} // lands as fd 3 in the child

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start worker: %w", err)
	}
	// Reap the child asynchronously so we don't leave zombies. The parent does
	// not block on the worker — each worker owns its connection independently.
	go func() {
		if werr := cmd.Wait(); werr != nil {
			log.Warn("worker exited", "pid", cmd.Process.Pid, "err", werr)
		}
	}()
	log.Info("worker spawned", "pid", cmd.Process.Pid)
	return nil
}

// filer is satisfied by *net.TCPConn (and other *net.*Conn types) which expose
// File() to obtain a dup of the underlying socket fd.
type filer interface {
	File() (*os.File, error)
}

// RunWorker is the entrypoint for a re-exec'd worker process. It reconstructs
// the connection from the inherited fd 3, runs the full SMB serving loop, and
// returns when the connection ends. The worker serves exactly one connection.
//
// opts must already be populated with Users/Shares/etc parsed from the same
// argv as the parent. RunWorker installs an OnAuthenticated hook that performs
// the one-time privilege drop after the user is resolved.
func RunWorker(ctx context.Context, log *slog.Logger, maxFrame uint32, opts ConnOptions) error {
	f := os.NewFile(uintptr(workerConnFD), "gosamba-conn")
	if f == nil {
		return errors.New("worker: no inherited connection fd")
	}
	conn, err := net.FileConn(f)
	// net.FileConn dups the fd; close our original handle either way.
	_ = f.Close()
	if err != nil {
		return fmt.Errorf("worker: reconstruct conn: %w", err)
	}

	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetKeepAlive(true)
	}

	// The privilege drop performed in OnAuthenticated below uses the stdlib
	// syscall.Setres{u,g}id, which the Go runtime applies to ALL OS threads of
	// the process. There is therefore no need (and it would be misleading) to
	// pin this goroutine to a thread: every goroutine — including the async
	// CHANGE_NOTIFY handler that may run on a different thread — observes the
	// dropped, unprivileged identity once the drop completes.

	// Install the one-time privilege-drop hook. Guarded so a second
	// SESSION_SETUP requesting a *different* uid after a drop is rejected (we
	// cannot re-drop within a process). Same-uid re-auth is allowed.
	var dropped bool
	var droppedUID = -1
	opts.OnAuthenticated = func(sess *Session) error {
		uid, gid := sess.User.SystemUID, sess.User.SystemGID
		if dropped {
			if uid == droppedUID {
				return nil // same identity re-authenticating: fine
			}
			return fmt.Errorf("worker already dropped to uid=%d; refusing second user uid=%d on same connection", droppedUID, uid)
		}
		plan := decidePrivDrop(syscall.Geteuid(), uid, gid, nil)
		if plan.Skip {
			log.Warn("privilege drop skipped", "reason", plan.Reason,
				"smb_user", sess.User.Name, "uid", uid, "gid", gid)
			dropped = true
			droppedUID = uid
			return nil
		}
		if err := applyPrivDrop(plan); err != nil {
			return fmt.Errorf("privilege drop: %w", err)
		}
		log.Info("privileges dropped", "smb_user", sess.User.Name, "uid", uid, "gid", gid)
		dropped = true
		droppedUID = uid
		return nil
	}

	ServeConn(ctx, conn, log, maxFrame, opts)
	return nil
}
