package parent

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"testing"
	"time"
)

// --- Finding 1: Register must not orphan the open it replaces ---

// newTempOpen returns an Open backed by a real file in a temp dir, so tests can
// observe whether its descriptor was closed.
func newTempOpen(t *testing.T, name string) *Open {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	f, err := os.Create(p)
	if err != nil {
		t.Fatalf("create %s: %v", p, err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return &Open{Path: p, File: f}
}

// fdClosed reports whether the open's descriptor has already been closed.
func fdClosed(o *Open) bool {
	_, err := o.File.Write([]byte("x"))
	return errors.Is(err, os.ErrClosed)
}

// TestFix_RegisterRefusesToClobberAttachedEntry proves a second CREATE reusing
// a live CreateGuid cannot displace the open that holds it. Before the fix
// Register overwrote the map slot outright: the previous *os.File became
// unreachable, so its fd was never closed and its byte-range locks stayed held
// for the life of the process.
func TestFix_RegisterRefusesToClobberAttachedEntry(t *testing.T) {
	tbl := NewDurableTable()
	var cg, crg [16]byte
	crg[0] = 0x11

	first := newTempOpen(t, "first.txt")
	if ok := tbl.Register(cg, crg, first, time.Minute, "share", "alice"); !ok {
		t.Fatalf("initial Register returned false, want true")
	}

	second := newTempOpen(t, "second.txt")
	if ok := tbl.Register(cg, crg, second, time.Minute, "share", "alice"); ok {
		t.Fatalf("Register over a live attached entry returned true; it clobbered the live open")
	}
	if tbl.len() != 1 {
		t.Fatalf("table len=%d after refused Register, want 1", tbl.len())
	}
	if fdClosed(first) {
		t.Errorf("the live open's fd was closed by a refused re-registration")
	}

	// The entry the table kept must still be the original open. Detach first:
	// a reconnect is only valid against an open whose connection is gone.
	tbl.Detach(cg, crg)
	got, ok := tbl.reclaimForReconnect(cg, crg, "share", "alice")
	if !ok || got != first {
		t.Fatalf("table holds the wrong open after a refused Register: ok=%v same=%v", ok, got == first)
	}
}

// TestFix_RegisterReleasesSupersededDetachedEntry proves that re-registering
// over a DETACHED entry (whose connection is already gone, so nothing else can
// ever reach it) releases that open's fd instead of leaking it.
func TestFix_RegisterReleasesSupersededDetachedEntry(t *testing.T) {
	tbl := NewDurableTable()
	var cg, crg [16]byte
	crg[0] = 0x12

	orphan := newTempOpen(t, "orphan.txt")
	tbl.Register(cg, crg, orphan, time.Minute, "share", "alice")
	tbl.Detach(cg, crg) // owning connection dropped

	replacement := newTempOpen(t, "replacement.txt")
	if ok := tbl.Register(cg, crg, replacement, time.Minute, "share", "alice"); !ok {
		t.Fatalf("Register over a detached entry returned false, want true")
	}
	if !fdClosed(orphan) {
		t.Errorf("superseded detached open's fd leaked: it is still open")
	}
	if fdClosed(replacement) {
		t.Errorf("the new open's fd was closed by its own registration")
	}
	if tbl.len() != 1 {
		t.Fatalf("table len=%d, want 1", tbl.len())
	}
}

// TestFix_RegisterSameOpenIsIdempotent guards the "refresh my own entry" path:
// re-registering the very same Open must never close the descriptor it is
// about to record.
func TestFix_RegisterSameOpenIsIdempotent(t *testing.T) {
	tbl := NewDurableTable()
	var cg, crg [16]byte
	crg[0] = 0x13

	o := newTempOpen(t, "same.txt")
	tbl.Register(cg, crg, o, time.Minute, "share", "alice")
	tbl.Detach(cg, crg)
	if ok := tbl.Register(cg, crg, o, time.Minute, "share", "alice"); !ok {
		t.Fatalf("re-Register of the same open returned false, want true")
	}
	if fdClosed(o) {
		t.Fatalf("re-registering the same open closed its own fd")
	}
	// Re-registering re-attaches, so it must not expire while the connection
	// is live again.
	if n := tbl.Expire(time.Now().Add(time.Hour)); n != 0 {
		t.Errorf("Expire evicted %d re-attached entries, want 0", n)
	}
}

// TestFix_RegisterZeroTimeoutReleasesDetachedEntry proves the non-durable path
// (timeout <= 0, which removes the entry) also releases an orphan rather than
// dropping the only reference to it.
func TestFix_RegisterZeroTimeoutReleasesDetachedEntry(t *testing.T) {
	tbl := NewDurableTable()
	var cg, crg [16]byte
	crg[0] = 0x14

	orphan := newTempOpen(t, "zero.txt")
	tbl.Register(cg, crg, orphan, time.Minute, "share", "alice")
	tbl.Detach(cg, crg)

	replacement := newTempOpen(t, "zero-new.txt")
	if ok := tbl.Register(cg, crg, replacement, 0, "share", "alice"); ok {
		t.Fatalf("Register with timeout=0 returned true, want false (non-durable)")
	}
	if tbl.len() != 0 {
		t.Fatalf("table len=%d after non-durable Register, want 0", tbl.len())
	}
	if !fdClosed(orphan) {
		t.Errorf("superseded detached open's fd leaked on the non-durable path")
	}
}

// --- Finding 2: reconnect is only valid against a disconnected open ---

// TestFix_ReconnectRefusesLiveHandle proves a durable reconnect cannot steal a
// handle whose owning connection is still alive (MS-SMB2 §3.3.5.9.7), and that
// the normal reconnect-after-drop path still works once the entry is detached.
func TestFix_ReconnectRefusesLiveHandle(t *testing.T) {
	tbl := NewDurableTable()
	var cg, crg [16]byte
	crg[0] = 0x21
	open := &Open{Path: "/live"}
	tbl.Register(cg, crg, open, time.Minute, "share", "alice")

	// Attached: the owner is still using it. Even the owner's own credentials
	// on the right share must not reclaim it.
	if _, ok := tbl.reclaimForReconnect(cg, crg, "share", "alice"); ok {
		t.Fatalf("reconnect reclaimed a handle still attached to a live connection")
	}
	// A refused attempt must not consume the entry — otherwise the refusal
	// itself becomes a way to evict another connection's handle.
	if tbl.len() != 1 {
		t.Fatalf("refused reconnect consumed the entry: len=%d, want 1", tbl.len())
	}

	// Detached: the connection dropped, so the reconnect is legitimate.
	tbl.Detach(cg, crg)
	got, ok := tbl.reclaimForReconnect(cg, crg, "share", "alice")
	if !ok {
		t.Fatalf("reconnect after drop was refused, want success")
	}
	if got != open {
		t.Fatalf("reconnect returned a different open")
	}
	if tbl.len() != 0 {
		t.Fatalf("successful reconnect did not consume the entry: len=%d", tbl.len())
	}
}

// TestFix_ReconnectStillChecksShareAndUser confirms the detached gate did not
// displace the share- and identity-binding checks.
func TestFix_ReconnectStillChecksShareAndUser(t *testing.T) {
	tbl := NewDurableTable()
	var cg, crg [16]byte
	crg[0] = 0x22
	tbl.Register(cg, crg, &Open{Path: "/bound"}, time.Minute, "shareA", "alice")
	tbl.Detach(cg, crg)

	if _, ok := tbl.reclaimForReconnect(cg, crg, "shareB", "alice"); ok {
		t.Errorf("reconnect on the wrong share succeeded")
	}
	if _, ok := tbl.reclaimForReconnect(cg, crg, "shareA", "mallory"); ok {
		t.Errorf("reconnect by a different user succeeded")
	}
	if tbl.len() != 1 {
		t.Fatalf("rejected reconnects consumed the entry: len=%d, want 1", tbl.len())
	}
	if _, ok := tbl.reclaimForReconnect(cg, crg, "shareA", "alice"); !ok {
		t.Errorf("the owning user could not reconnect on the right share")
	}
}

// --- Finding 3: a transient Accept error must not kill the server ---

// scriptedListener returns a canned sequence of Accept results, then blocks
// until Close. It lets the accept loop be driven through EMFILE without
// actually exhausting the test process's descriptors.
type scriptedListener struct {
	mu      sync.Mutex
	steps   []error    // one per Accept; nil means "hand over a connection"
	next    int        // index into steps
	conns   []net.Conn // server-side conns handed out, for cleanup
	closed  chan struct{}
	closeMu sync.Once
}

func newScriptedListener(steps []error) *scriptedListener {
	return &scriptedListener{steps: steps, closed: make(chan struct{})}
}

func (l *scriptedListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if l.next < len(l.steps) {
		step := l.steps[l.next]
		l.next++
		if step != nil {
			l.mu.Unlock()
			return nil, step
		}
		server, client := net.Pipe()
		l.conns = append(l.conns, client)
		l.mu.Unlock()
		return server, nil
	}
	l.mu.Unlock()
	// Script exhausted: park until the listener is closed, like a real
	// listener with no pending connections.
	<-l.closed
	return nil, net.ErrClosed
}

func (l *scriptedListener) Close() error {
	l.closeMu.Do(func() { close(l.closed) })
	l.mu.Lock()
	for _, c := range l.conns {
		_ = c.Close()
	}
	l.conns = nil
	l.mu.Unlock()
	return nil
}

func (l *scriptedListener) Addr() net.Addr { return dummyAddr{} }

// acceptCount reports how many scripted steps have been consumed.
func (l *scriptedListener) acceptCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.next
}

type dummyAddr struct{}

func (dummyAddr) Network() string { return "pipe" }
func (dummyAddr) String() string  { return "scripted" }

// TestFix_ServeSurvivesTemporaryAcceptErrors proves that fd exhaustion sheds a
// connection instead of terminating the server. Before the fix Serve returned
// on any Accept error, so a single EMFILE took the whole SMB service down.
func TestFix_ServeSurvivesTemporaryAcceptErrors(t *testing.T) {
	ln := newScriptedListener([]error{
		syscall.EMFILE,
		syscall.ECONNABORTED,
		syscall.ENFILE,
		nil, // recovery: a real connection is accepted after the errors
	})
	defer ln.Close()

	var handled sync.WaitGroup
	handled.Add(1)
	var once sync.Once

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv := &Listener{
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		MaxFrame: 64 * 1024,
		Handler: func(ctx context.Context, c net.Conn, lg *slog.Logger, mf uint32) {
			defer c.Close()
			once.Do(handled.Done)
		},
	}

	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln) }()

	// Serve must still be running and must reach the connection past the
	// errors. The backoff is 5ms+10ms+20ms, so this is quick.
	waitDone := make(chan struct{})
	go func() { handled.Wait(); close(waitDone) }()
	select {
	case <-waitDone:
	case err := <-done:
		t.Fatalf("Serve returned %v instead of shedding the transient accept errors", err)
	case <-time.After(5 * time.Second):
		t.Fatalf("connection after transient errors was never accepted (steps consumed: %d)", ln.acceptCount())
	}

	// Clean shutdown still works.
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve returned %v on cancel, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after cancel")
	}
}

// TestFix_ServeStillReturnsOnFatalAcceptError confirms the loop did not become
// unkillable: a genuinely fatal error must still propagate out of Serve.
func TestFix_ServeStillReturnsOnFatalAcceptError(t *testing.T) {
	ln := newScriptedListener([]error{syscall.EBADF})
	defer ln.Close()

	srv := &Listener{
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		MaxFrame: 64 * 1024,
		Handler:  func(context.Context, net.Conn, *slog.Logger, uint32) {},
	}

	done := make(chan error, 1)
	go func() { done <- srv.Serve(context.Background(), ln) }()
	select {
	case err := <-done:
		if !errors.Is(err, syscall.EBADF) {
			t.Errorf("Serve returned %v, want EBADF", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return on a fatal accept error")
	}
}

func TestFix_IsTemporaryAcceptError(t *testing.T) {
	temporary := []error{
		syscall.EMFILE, syscall.ENFILE, syscall.ENOBUFS, syscall.ENOMEM,
		syscall.ECONNABORTED, syscall.ECONNRESET, syscall.EINTR,
		syscall.EAGAIN, syscall.EPERM,
	}
	for _, err := range temporary {
		if !isTemporaryAcceptError(err) {
			t.Errorf("isTemporaryAcceptError(%v) = false, want true", err)
		}
		// Wrapped errors must be matched too — Accept returns *net.OpError.
		wrapped := &net.OpError{Op: "accept", Err: err}
		if !isTemporaryAcceptError(wrapped) {
			t.Errorf("isTemporaryAcceptError(wrapped %v) = false, want true", err)
		}
	}
	fatal := []error{syscall.EBADF, syscall.EINVAL, net.ErrClosed, errors.New("boom")}
	for _, err := range fatal {
		if isTemporaryAcceptError(err) {
			t.Errorf("isTemporaryAcceptError(%v) = true, want false", err)
		}
	}
}

// --- Finding 4: worker spawns must be bounded ---

func TestFix_WorkerSemaphoreBounds(t *testing.T) {
	sem := newWorkerSemaphore(3)
	for i := 0; i < 3; i++ {
		if !sem.acquire() {
			t.Fatalf("acquire %d failed while slots remain", i)
		}
	}
	if sem.acquire() {
		t.Fatalf("acquire past the bound succeeded; workers are unbounded")
	}
	// A finished worker frees exactly one slot.
	sem.release()
	if !sem.acquire() {
		t.Fatalf("acquire after release failed")
	}
	if sem.acquire() {
		t.Fatalf("release freed more than one slot")
	}
	// Over-releasing must not raise the ceiling (the spawn error paths release
	// unconditionally).
	for i := 0; i < 10; i++ {
		sem.release()
	}
	for i := 0; i < 3; i++ {
		if !sem.acquire() {
			t.Fatalf("acquire %d failed after full drain", i)
		}
	}
	if sem.acquire() {
		t.Fatalf("over-release inflated the semaphore past its bound")
	}
}

// TestFix_ReExecWorkerRefusesPastLimit drives the real spawn path with the
// global semaphore exhausted: it must return errWorkerLimit without forking.
func TestFix_ReExecWorkerRefusesPastLimit(t *testing.T) {
	// Exhaust the process-global semaphore, restoring it afterwards.
	held := 0
	for workerSlots.acquire() {
		held++
	}
	t.Cleanup(func() {
		for i := 0; i < held; i++ {
			workerSlots.release()
		}
	})
	if held != maxConcurrentWorkers {
		t.Fatalf("drained %d slots, want maxConcurrentWorkers=%d", held, maxConcurrentWorkers)
	}

	// A net.Pipe conn has no fd, so if the limit check were missing this would
	// fail with "does not expose a file descriptor" instead of errWorkerLimit —
	// the assertion below therefore proves the check runs first.
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	err := reExecWorker(server, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if !errors.Is(err, errWorkerLimit) {
		t.Fatalf("reExecWorker at the limit returned %v, want errWorkerLimit", err)
	}
}

// TestFix_ReExecWorkerReleasesSlotOnSpawnFailure proves a failed spawn hands
// its slot back; otherwise repeated failures would ratchet the limit to zero
// and permanently wedge the server.
func TestFix_ReExecWorkerReleasesSlotOnSpawnFailure(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	for i := 0; i < 5; i++ {
		// net.Pipe exposes no descriptor, so this always fails before Start.
		if err := reExecWorker(server, log); err == nil || errors.Is(err, errWorkerLimit) {
			t.Fatalf("attempt %d: got %v, want a non-limit spawn failure", i, err)
		}
	}
	// All slots must still be available.
	held := 0
	for workerSlots.acquire() {
		held++
	}
	for i := 0; i < held; i++ {
		workerSlots.release()
	}
	if held != maxConcurrentWorkers {
		t.Fatalf("%d slots free after 5 failed spawns, want %d (slots leaked)", held, maxConcurrentWorkers)
	}
}

// --- Finding 5: supplementary groups are resolved before the drop ---

// TestFix_ResolveSupplementaryGroups exercises the group resolution against the
// account running the tests. The destructive part (setgroups + setuid) needs
// root and is covered by TestPrivdrop_AllThreads; this covers the lookup, which
// is where the actual bug was — the worker previously passed nil and dropped
// with the primary gid only.
func TestFix_ResolveSupplementaryGroups(t *testing.T) {
	uid, gid := os.Getuid(), os.Getgid()
	groups, err := resolveSupplementaryGroups(uid, gid)
	if err != nil {
		t.Skipf("cannot resolve the test account (uid=%d): %v", uid, err)
	}
	if len(groups) == 0 {
		t.Fatalf("resolveSupplementaryGroups returned an empty set")
	}
	// The primary gid leads, matching initgroups(3).
	if groups[0] != gid {
		t.Errorf("groups[0] = %d, want the primary gid %d", groups[0], gid)
	}
	seen := map[int]bool{}
	for _, g := range groups {
		if seen[g] {
			t.Errorf("duplicate group %d in %v", g, groups)
		}
		seen[g] = true
	}
	// The real point of the fix: an account in more than one group must get
	// more than just its primary gid. Only assert it when the process really
	// is in extra groups, so the test holds on minimal container images.
	if cur, cerr := syscall.Getgroups(); cerr == nil && len(cur) > 1 {
		if len(groups) < 2 {
			t.Errorf("resolved %v for an account in %v; supplementary groups were dropped", groups, cur)
		}
	}
}

// TestFix_PrivDropGroupsFailsClosed proves an unresolvable account degrades to
// the primary gid alone rather than leaving root's group set in place.
func TestFix_PrivDropGroupsFailsClosed(t *testing.T) {
	// A uid that cannot exist in passwd.
	const bogusUID = 0x7FFFFFF0
	groups := privDropGroups(bogusUID, 4242, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if len(groups) != 1 || groups[0] != 4242 {
		t.Fatalf("privDropGroups for an unknown uid = %v, want [4242] (primary gid only)", groups)
	}
}

// TestFix_PrivDropGroupsRespectsPlatformLimit guards the darwin NGROUPS_MAX
// cap: setgroups(2) there rejects a list longer than 16 with EINVAL, which
// would fail the whole drop and tear the connection down.
func TestFix_PrivDropGroupsRespectsPlatformLimit(t *testing.T) {
	groups := privDropGroups(os.Getuid(), os.Getgid(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if len(groups) > maxSupplementaryGroups {
		t.Fatalf("privDropGroups returned %d groups, above the platform limit %d",
			len(groups), maxSupplementaryGroups)
	}
	if runtime.GOOS == "darwin" && maxSupplementaryGroups != 16 {
		t.Errorf("darwin maxSupplementaryGroups = %d, want 16 (NGROUPS_MAX)", maxSupplementaryGroups)
	}
}

// --- Finding 6: the ctx watcher must not outlive its connection ---

// TestFix_ServeConnDoesNotLeakCtxWatcher proves the per-connection goroutine
// that closes the socket on server shutdown exits when the connection ends.
// Before the fix it blocked on <-ctx.Done() alone, so every short-lived
// connection left a parked goroutine (holding its net.Conn) until the server
// itself shut down.
func TestFix_ServeConnDoesNotLeakCtxWatcher(t *testing.T) {
	// The server context stays alive for the whole test — that is the point:
	// the watcher must exit without it being cancelled.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	// One warm-up connection so lazily-created runtime goroutines are not
	// counted as leaks.
	runServeConnOnce(ctx, log)
	base := settledGoroutines(t)

	const n = 60
	for i := 0; i < n; i++ {
		runServeConnOnce(ctx, log)
	}
	after := settledGoroutines(t)

	// With the bug, growth is ~n (one parked watcher per connection).
	if growth := after - base; growth > n/4 {
		t.Fatalf("goroutine count grew by %d over %d connections (base=%d after=%d); "+
			"the per-connection ctx watcher is leaking", growth, n, base, after)
	}
}

// runServeConnOnce drives one ServeConn to completion over a net.Pipe by
// closing the client side immediately, so NEGOTIATE fails on EOF and ServeConn
// returns.
func runServeConnOnce(ctx context.Context, log *slog.Logger) {
	server, client := net.Pipe()
	_ = client.Close()
	ServeConn(ctx, server, log, 64*1024, ConnOptions{})
}

// settledGoroutines returns runtime.NumGoroutine() once it has stopped
// shrinking, so goroutines still winding down are not counted.
func settledGoroutines(t *testing.T) int {
	t.Helper()
	prev := -1
	for i := 0; i < 100; i++ {
		runtime.Gosched()
		time.Sleep(5 * time.Millisecond)
		n := runtime.NumGoroutine()
		if n == prev {
			return n
		}
		prev = n
	}
	return prev
}
