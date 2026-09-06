//go:build darwin || linux

package inotify

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// startWatcher runs w.Watch in its own goroutine and hands back the channel
// its return value will land on.
func startWatcher(w *Watcher) <-chan error {
	done := make(chan error, 1)
	go func() { done <- w.Watch() }()
	return done
}

// stopWatcher closes w and waits for the watch goroutine to return, so its
// descriptors are released before the next test runs.
func stopWatcher(t *testing.T, w *Watcher, done <-chan error) {
	t.Helper()
	if err := w.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Error("Watch did not return after Close")
	}
}

// awaitEvent consumes events until one satisfies pred.
func awaitEvent(t *testing.T, w *Watcher, pred func(InotifyEvent) bool) InotifyEvent {
	t.Helper()
	timeout := time.After(5 * time.Second)
	for {
		select {
		case ev, ok := <-w.Events:
			if !ok {
				t.Fatal("Events closed before the expected event arrived")
			}
			if pred(ev) {
				return ev
			}
		case <-timeout:
			t.Fatal("timed out waiting for event")
		}
	}
}

// drainEvents swallows whatever is already queued, so a later assertion
// cannot be satisfied by a stale event from an earlier step.
func drainEvents(w *Watcher, d time.Duration) {
	deadline := time.After(d)
	for {
		select {
		case _, ok := <-w.Events:
			if !ok {
				return
			}
		case <-deadline:
			return
		}
	}
}

// TestCloseUnblocksWatch is the regression test for a watch goroutine (and
// its inotify/kqueue descriptors) leaking for the life of the process:
// Close only closed a channel the loop looked at *between* blocking reads,
// so a watcher over a quiet directory stayed parked in the kernel forever.
// One watcher is created per SMB2 CHANGE_NOTIFY request, so an ordinary
// client using directory notifications leaked steadily.
func TestCloseUnblocksWatch(t *testing.T) {
	w, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	done := startWatcher(w)
	time.Sleep(100 * time.Millisecond) // let the loop reach its blocking wait

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Watch returned %v, want nil", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Watch did not return after Close: the goroutine and its descriptors leak")
	}

	// The caller distinguishes "the watch ended" from "an event arrived" by
	// the channel closing, so Close has to get it closed.
	deadline := time.After(3 * time.Second)
	for {
		select {
		case _, ok := <-w.Events:
			if !ok {
				return
			}
		case <-deadline:
			t.Fatal("Events channel was not closed after Close")
		}
	}
}

// TestCloseIdempotentAndConcurrent hammers Close from several goroutines
// while the loop is running: it must not panic (double channel close,
// double fd close) and must leave the loop stopped exactly once.
func TestCloseIdempotentAndConcurrent(t *testing.T) {
	w, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	done := startWatcher(w)
	time.Sleep(100 * time.Millisecond)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := w.Close(); err != nil {
				t.Errorf("concurrent Close: %v", err)
			}
		}()
	}
	wg.Wait()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Watch did not return after Close")
	}

	// And once more after the loop has already torn everything down.
	if err := w.Close(); err != nil {
		t.Fatalf("Close after teardown: %v", err)
	}
}

// TestCloseBeforeWatch covers the other ordering: the watcher is closed
// before its loop ever starts, which is what happens when a CHANGE_NOTIFY is
// cancelled immediately. Watch must refuse rather than run against released
// descriptors, and Events must still end so a reader is not stranded.
func TestCloseBeforeWatch(t *testing.T) {
	w, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	done := startWatcher(w)
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Watch on a closed watcher returned nil, want an error")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Watch blocked on a closed watcher")
	}

	select {
	case _, ok := <-w.Events:
		if ok {
			t.Fatal("Events delivered a value on a closed watcher")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Events channel was not closed")
	}

	if err := w.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// TestNewWatcherNonRecursive checks the non-recursive constructor: SMB2
// CHANGE_NOTIFY without SMB2_WATCH_TREE only reports changes in the
// directory itself, and the watcher must not pay to watch the subtree whose
// events the caller then discards.
func TestNewWatcherNonRecursive(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}

	w, err := NewWatcher(root, false)
	if err != nil {
		t.Fatal(err)
	}
	if dirs, _ := w.watchCounts(); dirs != 1 {
		t.Fatalf("non-recursive watcher registered %d directory watches, want 1 (the subtree must not be walked)", dirs)
	}
	done := startWatcher(w)
	defer stopWatcher(t, w, done)
	time.Sleep(100 * time.Millisecond)

	// Ordered deliberately: the subtree change happens first, so by the time
	// the top-level create is reported anything from the subtree would
	// already be queued ahead of it.
	if err := os.WriteFile(filepath.Join(sub, "nested.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	top := filepath.Join(root, "top.txt")
	if err := os.WriteFile(top, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	nested := sub + string(filepath.Separator)
	timeout := time.After(5 * time.Second)
	for {
		select {
		case ev, ok := <-w.Events:
			if !ok {
				t.Fatal("Events closed before the top-level create arrived")
			}
			if strings.HasPrefix(ev.Path, nested) {
				t.Fatalf("non-recursive watcher reported a subtree change: %+v", ev)
			}
			if ev.Path == top && ev.Event == FileCreate {
				return
			}
		case <-timeout:
			t.Fatal("timed out waiting for the top-level create")
		}
	}
}

// TestNewStillRecursive pins the behaviour of the existing constructor:
// dispatch.go calls New(path) and must keep getting a whole-subtree watch.
func TestNewStillRecursive(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}

	w, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if dirs, _ := w.watchCounts(); dirs != 2 {
		t.Fatalf("New registered %d directory watches, want 2 (root and its subdirectory)", dirs)
	}
}

// TestWatchDescriptorsBoundedForLargeDirectory is the regression test for
// the watcher opening one descriptor per regular file in the whole subtree:
// watching a large share could exhaust the process descriptor limit (macOS
// defaults to 256) and take the server down. Degrading is fine; running out
// of descriptors is not.
func TestWatchDescriptorsBoundedForLargeDirectory(t *testing.T) {
	const numFiles = 600
	dir := t.TempDir()
	for i := 0; i < numFiles; i++ {
		p := filepath.Join(dir, fmt.Sprintf("f%03d.dat", i))
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	w, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	done := startWatcher(w)
	defer stopWatcher(t, w, done)

	dirs, files := w.watchCounts()
	if total := dirs + files; total >= numFiles/2 {
		t.Fatalf("watcher holds %d descriptors for a %d-file directory; an unbounded watch exhausts the process limit", total, numFiles)
	}

	// The degradation must not cost the directory-level events: creates,
	// deletes and renames come from the directory watch, which is still
	// there.
	time.Sleep(100 * time.Millisecond)
	p := filepath.Join(dir, "new.txt")
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	awaitEvent(t, w, func(e InotifyEvent) bool { return e.Path == p && e.Event == FileCreate })
}

// TestAtomicSaveByRenameKeepsReportingWrites pins the save-by-rename
// behaviour: an editor writes a temp file and renames it over the target, so
// the target's name never appears or disappears while the inode behind it
// changes. The replacement itself must be reported, and — this is the part
// that regresses easily — the watch has to follow the new inode, so an
// ordinary in-place write afterwards is still reported instead of vanishing
// into the old unlinked vnode.
func TestAtomicSaveByRenameKeepsReportingWrites(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "doc.txt")
	if err := os.WriteFile(target, []byte("v1"), 0o644); err != nil {
		t.Fatal(err)
	}

	w, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	done := startWatcher(w)
	defer stopWatcher(t, w, done)
	time.Sleep(100 * time.Millisecond)

	tmp := filepath.Join(dir, ".doc.txt.tmp")
	if err := os.WriteFile(tmp, []byte("v2"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, target); err != nil {
		t.Fatal(err)
	}
	// darwin reports the inode swap as Modified; inotify sees the rename
	// itself and reports MovedTo. Either counts as "the client was told".
	awaitEvent(t, w, func(e InotifyEvent) bool {
		return e.Path == target && (e.Event == Modified || e.Event == MovedTo)
	})

	// Drop anything still queued, so the assertion below can only be
	// satisfied by an event caused by the write that follows it.
	drainEvents(w, 300*time.Millisecond)

	if err := os.WriteFile(target, []byte("v3-longer"), 0o644); err != nil {
		t.Fatal(err)
	}
	awaitEvent(t, w, func(e InotifyEvent) bool { return e.Path == target && e.Event == Modified })
}

// TestWatchesReleasedOnClose walks the create/teardown cycle a CHANGE_NOTIFY
// request performs, repeatedly: every watch a watcher registered has to be
// given back when it closes. A watcher that keeps them bleeds descriptors
// one notify request at a time, and on darwin also drains the shared watch
// budget until later watchers can register nothing but their own root.
func TestWatchesReleasedOnClose(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		p := filepath.Join(sub, fmt.Sprintf("f%d.txt", i))
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// Enough lifetimes that a watcher which failed to give its watches back
	// would have drained the shared budget by the check below, whatever the
	// process descriptor limit sized it at.
	const lifetimes = 150
	for i := 0; i < lifetimes; i++ {
		w, err := New(root)
		if err != nil {
			t.Fatalf("New on iteration %d: %v", i, err)
		}
		done := startWatcher(w)
		stopWatcher(t, w, done)
		if dirs, files := w.watchCounts(); dirs != 0 || files != 0 {
			t.Fatalf("iteration %d: watcher still holds %d directory and %d file watches after Close", i, dirs, files)
		}
	}

	// And the shared budget those watchers drew on has to be intact: a fresh
	// watcher must still be able to register the subdirectory, which (unlike
	// the root) is only registered if there is budget left for it.
	w, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if dirs, _ := w.watchCounts(); dirs != 2 {
		t.Fatalf("after %d watcher lifetimes a new watcher registered %d directory watches, want 2", lifetimes, dirs)
	}
}
