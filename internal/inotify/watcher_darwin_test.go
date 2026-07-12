//go:build darwin

package inotify

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func waitEvent(t *testing.T, w *Watcher, pred func(InotifyEvent) bool) InotifyEvent {
	t.Helper()
	timeout := time.After(3 * time.Second)
	for {
		select {
		case ev, ok := <-w.Events:
			if ok && pred(ev) {
				return ev
			}
		case <-timeout:
			t.Fatal("timed out waiting for event")
		}
	}
}

func TestWatcherDarwinCreateModifyDelete(t *testing.T) {
	dir := t.TempDir()
	w, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	go w.Watch()
	defer w.Close()
	time.Sleep(100 * time.Millisecond) // let the loop register

	p := filepath.Join(dir, "f.txt")
	os.WriteFile(p, []byte("a"), 0o644)
	waitEvent(t, w, func(e InotifyEvent) bool { return e.Path == p && e.Event == FileCreate })

	os.WriteFile(p, []byte("bb"), 0o644)
	waitEvent(t, w, func(e InotifyEvent) bool { return e.Path == p && e.Event == Modified })

	os.Remove(p)
	waitEvent(t, w, func(e InotifyEvent) bool { return e.Path == p && e.Event == Delete })
}

// TestWatcherDarwinRenameSubtree reproduces two bugs found in the initial
// kqueue implementation:
//
//  1. fd-number-reuse race on directory rename: closing the renamed
//     directory's fd and immediately reopening the new path can hand out the
//     same fd number, and a stale pending kqueue event for the old
//     registration can then be misattributed to the new one, permanently
//     losing change-notify for the renamed subtree.
//  2. stale watchedFile.path after an ancestor rename: per-file watches
//     stored the path captured at registration, so events for files under a
//     renamed directory were silently dropped once os.Lstat on the stale
//     path started failing.
//
// It also covers the reactive (non-recursive) addDir bug by relying on the
// pre-existing file.txt inside the renamed subtree, and by creating a fresh
// file inside the renamed directory afterward.
func TestWatcherDarwinRenameSubtree(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	filePath := filepath.Join(sub, "file.txt")
	if err := os.WriteFile(filePath, []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}

	w, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	go w.Watch()
	defer w.Close()
	time.Sleep(100 * time.Millisecond) // let the loop register

	sub2 := filepath.Join(root, "sub2")
	if err := os.Rename(sub, sub2); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond) // let the rename settle

	// Bug 1: the renamed subtree must still be watched — a brand new file
	// created inside it must surface a FileCreate event.
	newFile := filepath.Join(sub2, "new.txt")
	if err := os.WriteFile(newFile, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	waitEvent(t, w, func(e InotifyEvent) bool { return e.Path == newFile && e.Event == FileCreate })

	// Bug 2: the pre-existing file's watch must be re-pathed to its new
	// location — writing to it must still surface a Modified event.
	movedFilePath := filepath.Join(sub2, "file.txt")
	if err := os.WriteFile(movedFilePath, []byte("bb"), 0o644); err != nil {
		t.Fatal(err)
	}
	waitEvent(t, w, func(e InotifyEvent) bool { return e.Path == movedFilePath && e.Event == Modified })
}

// TestWatcherDarwinNewPopulatedDirRecursive covers bug 3: a reactively
// registered directory (via a rename that lands a populated directory into
// the watched tree) must have its pre-existing children watched too, not
// just the directory itself.
func TestWatcherDarwinNewPopulatedDirRecursive(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()

	populated := filepath.Join(outside, "populated")
	if err := os.Mkdir(populated, 0o755); err != nil {
		t.Fatal(err)
	}
	existing := filepath.Join(populated, "existing.txt")
	if err := os.WriteFile(existing, []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	nestedDir := filepath.Join(populated, "nested")
	if err := os.Mkdir(nestedDir, 0o755); err != nil {
		t.Fatal(err)
	}

	w, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	go w.Watch()
	defer w.Close()
	time.Sleep(100 * time.Millisecond)

	dest := filepath.Join(root, "populated")
	if err := os.Rename(populated, dest); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)

	// The pre-existing file must now be watched: writing to it must surface
	// a Modified event.
	destExisting := filepath.Join(dest, "existing.txt")
	if err := os.WriteFile(destExisting, []byte("bb"), 0o644); err != nil {
		t.Fatal(err)
	}
	waitEvent(t, w, func(e InotifyEvent) bool { return e.Path == destExisting && e.Event == Modified })

	// The pre-existing nested subdirectory must now be watched: creating a
	// file inside it must surface a FileCreate event.
	nestedFile := filepath.Join(dest, "nested", "new.txt")
	if err := os.WriteFile(nestedFile, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	waitEvent(t, w, func(e InotifyEvent) bool { return e.Path == nestedFile && e.Event == FileCreate })
}
