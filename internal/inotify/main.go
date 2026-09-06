//go:build linux

// Package inotify is a thin recursive-watch wrapper over Linux inotify.
//
// Vendored from github.com/ahmetozer/sandal/pkg/lib/inotify (same author).
package inotify

import (
	"fmt"
	"log/slog"

	"golang.org/x/sys/unix"
)

// New creates a recursive inotify watcher for the specified path.
func New(path string) (*Watcher, error) {
	return NewWatcher(path, true)
}

// NewWatcher creates an inotify watcher for path. When recursive is true the
// whole subtree is watched; when it is false only path's own directory is,
// which is what an SMB2 CHANGE_NOTIFY without SMB2_WATCH_TREE actually asks
// for — the caller would discard every subtree event anyway, so installing
// those watches only costs walk time and kernel watch slots.
func NewWatcher(path string, recursive bool) (*Watcher, error) {
	w := &Watcher{
		path:      path,
		recursive: recursive,
		state:     stateNotInitialized,
		close:     make(chan struct{}),
		watchMap:  make(map[int]string),
		Events:    make(chan InotifyEvent, 100),
	}

	// Non-blocking: Watch drives the fd through poll(2), so a wakeup that
	// races with another reader must return EAGAIN instead of parking the
	// loop in an uninterruptible read. Close-on-exec keeps the descriptor
	// out of any child process the server spawns.
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize inotify: %w", err)
	}
	w.fd = fd

	// The self-pipe is how Close interrupts the loop; see Watcher.wakeR.
	var pipe [2]int
	if err := unix.Pipe2(pipe[:], unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("failed to create wakeup pipe: %w", err)
	}
	w.wakeR, w.wakeW = pipe[0], pipe[1]

	if err := w.watchDir(path); err != nil {
		w.mu.Lock()
		w.closeFDsLocked()
		w.state = stateClosed
		w.mu.Unlock()
		return nil, err
	}

	w.state = stateInitialized
	slog.Debug("inotify.New", "path", path, "recursive", recursive)
	return w, nil
}

// watchCounts reports how many kernel watch registrations the watcher
// currently holds, split into directory and per-file registrations. inotify
// needs no per-file registration (a directory watch already reports
// IN_MODIFY for its children), so files is always zero here; the darwin
// kqueue backend, which does need one descriptor per watched vnode, reports
// a real count. Used by the tests to assert the watch set stays bounded.
func (w *Watcher) watchCounts() (dirs, files int) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return len(w.watchMap), 0
}
