//go:build darwin

// Package inotify's darwin implementation: a recursive change-notify watcher
// built on kqueue (EVFILT_VNODE) plus directory-snapshot diffing.
//
// kqueue only tells us *that* a watched vnode changed, not *what* changed.
// For directories, NOTE_WRITE fires when an entry is added, removed, or
// renamed — but not when an existing file's contents are modified in place.
// So every regular file discovered under a watched directory is also opened
// and registered individually: its own NOTE_WRITE/NOTE_EXTEND is what lets
// us detect in-place modification and report a Modified event. On a
// directory wakeup we re-scan the directory, diff the old and new snapshots
// via diffSnapshot, emit the resulting events, and register/drop file and
// subdirectory watches for whatever appeared or disappeared.
//
// Rename correlation is best-effort: diffSnapshot only pairs an inode that
// disappeared and reappeared within the same directory's diff pass. A rename
// that moves an entry into a different watched directory will therefore
// surface as a Delete in the source directory plus a Create in the
// destination directory rather than a single Moved pair. SMB clients
// tolerate this degradation (they treat it as two independent changes).
//
// NOTE_DELETE/NOTE_RENAME on a watched vnode's own fd means that vnode was
// removed or renamed away; we close its fd and drop it from the watch set.
// For directories/files still reachable under a common watched ancestor,
// the ancestor's own directory diff is what actually reports the
// Delete/MovedFrom/MovedTo event — the vnode-level notification here only
// drives watch-set cleanup.
package inotify

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// watchedDir is the per-directory bookkeeping kept while it is under watch.
type watchedDir struct {
	fd    int
	path  string
	token *byte // see addDir's doc comment
	snap  map[string]dirEntry
}

// watchedFile is the per-file bookkeeping kept while a regular file is
// individually watched.
type watchedFile struct {
	fd    int
	path  string
	token *byte // see addDir's doc comment
}

// Watcher handles kqueue-based watching for a directory tree (recursive).
type Watcher struct {
	mu           sync.Mutex
	kq           int
	root         string
	dirs         map[int]*watchedDir  // dir fd (kqueue ident) -> dir state
	pathToFd     map[string]int       // dir path -> dir fd
	files        map[int]*watchedFile // file fd (kqueue ident) -> file state
	filePathToFd map[string]int       // file path -> file fd
	closed       bool
	watching     bool
	close        chan struct{}
	Events       chan InotifyEvent
}

// New creates a new kqueue watcher for the specified path.
func New(path string) (*Watcher, error) {
	kq, err := unix.Kqueue()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize kqueue: %w", err)
	}

	w := &Watcher{
		kq:           kq,
		root:         path,
		dirs:         make(map[int]*watchedDir),
		pathToFd:     make(map[string]int),
		files:        make(map[int]*watchedFile),
		filePathToFd: make(map[string]int),
		close:        make(chan struct{}),
		Events:       make(chan InotifyEvent, 100),
	}

	if err := w.watchDir(path); err != nil {
		w.closeAllLocked()
		return nil, err
	}

	slog.Debug("inotify.New", "path", path)
	return w, nil
}

// closeAllLocked closes every currently-registered fd (kqueue included). It
// takes the lock itself; callers must not already hold w.mu.
func (w *Watcher) closeAllLocked() {
	w.mu.Lock()
	for fd := range w.dirs {
		unix.Close(fd)
	}
	w.dirs = nil
	w.pathToFd = nil
	for fd := range w.files {
		unix.Close(fd)
	}
	w.files = nil
	w.filePathToFd = nil
	unix.Close(w.kq)
	w.mu.Unlock()
}

// watchDir walks the tree rooted at path and registers a kqueue watch on
// every directory and regular file found.
func (w *Watcher) watchDir(path string) error {
	return filepath.Walk(path, func(walkPath string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if fi.IsDir() {
			return w.addDir(walkPath)
		}
		if fi.Mode().IsRegular() {
			return w.addFile(walkPath)
		}
		return nil
	})
}

// addDir opens path, snapshots it, and registers it with kqueue. Safe to
// call concurrently with Watch's event loop. It registers only path itself;
// callers that need pre-existing children covered too (e.g. a directory
// reactively discovered via FolderCreate/MovedTo) must use watchDir instead,
// which walks and registers the whole subtree.
//
// Every registration gets a fresh, uniquely-addressed token (a lone
// heap-allocated byte) stashed in the kevent's Udata field. Because kqueue
// idents are just fd numbers, a closed fd can be reused by an unrelated
// later Open (e.g. after a directory rename tears down the old watch and a
// fresh one is opened at the new path with the same fd number). A kqueue
// notification queued for the old registration but delivered after the new
// one is live would otherwise be misattributed to the new entry purely by
// ident match; comparing the delivered event's Udata pointer against the
// current entry's token lets handleEvent detect and discard such stale
// events instead of acting on them. The token is a genuine Go pointer (not
// an integer smuggled through unsafe.Pointer/uintptr, which -race's checkptr
// instrumentation rejects), and the owning watchedDir/watchedFile entry
// keeps it reachable for as long as the registration is live.
func (w *Watcher) addDir(path string) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_EVTONLY, 0)
	if err != nil {
		return fmt.Errorf("failed to open %s: %w", path, err)
	}

	snap := scanDir(path)
	token := new(byte)

	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		unix.Close(fd)
		return nil
	}
	kev := unix.Kevent_t{
		Ident:  uint64(fd),
		Filter: unix.EVFILT_VNODE,
		Flags:  unix.EV_ADD | unix.EV_CLEAR,
		Fflags: unix.NOTE_WRITE | unix.NOTE_DELETE | unix.NOTE_RENAME,
		Udata:  token,
	}
	if _, err := unix.Kevent(w.kq, []unix.Kevent_t{kev}, nil, nil); err != nil {
		unix.Close(fd)
		return fmt.Errorf("failed to register watch for %s: %w", path, err)
	}
	w.dirs[fd] = &watchedDir{fd: fd, path: path, token: token, snap: snap}
	w.pathToFd[path] = fd
	return nil
}

// addFile opens path and registers it with kqueue so in-place writes to an
// already-existing file (which do not touch its parent directory's own
// NOTE_WRITE) are still observed. See addDir's doc comment for why every
// registration carries a fresh generation token.
func (w *Watcher) addFile(path string) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_EVTONLY, 0)
	if err != nil {
		return fmt.Errorf("failed to open %s: %w", path, err)
	}

	token := new(byte)

	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		unix.Close(fd)
		return nil
	}
	kev := unix.Kevent_t{
		Ident:  uint64(fd),
		Filter: unix.EVFILT_VNODE,
		Flags:  unix.EV_ADD | unix.EV_CLEAR,
		Fflags: unix.NOTE_WRITE | unix.NOTE_EXTEND | unix.NOTE_DELETE | unix.NOTE_RENAME,
		Udata:  token,
	}
	if _, err := unix.Kevent(w.kq, []unix.Kevent_t{kev}, nil, nil); err != nil {
		unix.Close(fd)
		return fmt.Errorf("failed to register watch for %s: %w", path, err)
	}
	w.files[fd] = &watchedFile{fd: fd, path: path, token: token}
	w.filePathToFd[path] = fd
	return nil
}

// removeFileByPath drops and closes the file watch registered at path, if any.
func (w *Watcher) removeFileByPath(path string) {
	w.mu.Lock()
	fd, ok := w.filePathToFd[path]
	if ok {
		delete(w.filePathToFd, path)
		delete(w.files, fd)
	}
	w.mu.Unlock()
	if ok {
		unix.Close(fd)
	}
}

// removeSubtree drops and closes every dir/file watch rooted at prefix: the
// entry at prefix itself plus every entry whose path is nested under it.
// Used both when a watched directory is itself deleted/renamed away (its own
// vnode notification only tells us the ident is gone, not what replaced it)
// and when the caller is about to fully re-walk and re-register a subtree
// from scratch (e.g. re-pathing after a rename) and wants a clean slate
// first. Removing every descendant from the maps before closing any fd
// ensures each fd is closed exactly once, even though prefix's own dir watch
// and its descendants' dir/file watches are torn down together here.
func (w *Watcher) removeSubtree(prefix string) {
	nested := prefix + string(filepath.Separator)
	w.mu.Lock()
	var fds []int
	for path, fd := range w.pathToFd {
		if path == prefix || strings.HasPrefix(path, nested) {
			delete(w.pathToFd, path)
			delete(w.dirs, fd)
			fds = append(fds, fd)
		}
	}
	for path, fd := range w.filePathToFd {
		if path == prefix || strings.HasPrefix(path, nested) {
			delete(w.filePathToFd, path)
			delete(w.files, fd)
			fds = append(fds, fd)
		}
	}
	w.mu.Unlock()
	for _, fd := range fds {
		unix.Close(fd)
	}
}

// scanDir lists path's immediate children as a name -> dirEntry snapshot.
// Missing/unreadable entries are silently skipped (they raced with the scan
// and will show up as a create/delete on the next diff pass).
func scanDir(path string) map[string]dirEntry {
	snap := make(map[string]dirEntry)
	entries, err := os.ReadDir(path)
	if err != nil {
		return snap
	}
	for _, e := range entries {
		fi, err := os.Lstat(filepath.Join(path, e.Name()))
		if err != nil {
			continue
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}
		snap[e.Name()] = dirEntry{
			ino:   st.Ino,
			mtime: fi.ModTime().UnixNano(),
			isDir: fi.IsDir(),
		}
	}
	return snap
}

// Watch starts the event loop. Blocks until Close.
func (w *Watcher) Watch() error {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return fmt.Errorf("watcher closed")
	}
	w.watching = true
	w.mu.Unlock()

	defer func() {
		w.closeAllLocked()
		select {
		case w.Events <- InotifyEvent{Event: WatchStop}:
		default:
		}
		close(w.Events)
	}()

	events := make([]unix.Kevent_t, 16)
	// Poll with a short timeout so we periodically notice w.close being
	// signalled even though EVFILT_VNODE otherwise blocks indefinitely.
	timeout := unix.NsecToTimespec(int64(500 * 1000 * 1000))
	for {
		select {
		case <-w.close:
			return nil
		default:
		}

		n, err := unix.Kevent(w.kq, nil, events, &timeout)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return fmt.Errorf("kevent: %w", err)
		}
		for i := 0; i < n; i++ {
			w.handleEvent(events[i])
		}
	}
}

// handleEvent routes one kqueue notification to the directory or file
// handler, based on which watch set its ident (fd) belongs to. Events whose
// Udata token doesn't match the current registration at that ident are
// stale — the fd number was reused by a later, unrelated registration after
// this event was queued but before it was delivered — and are discarded
// rather than misattributed to the new entry. See addDir's doc comment.
func (w *Watcher) handleEvent(kev unix.Kevent_t) {
	fd := int(kev.Ident)
	w.mu.Lock()
	dir, isDir := w.dirs[fd]
	file, isFile := w.files[fd]
	w.mu.Unlock()

	switch {
	case isDir:
		if dir.token != kev.Udata {
			slog.Debug("inotify stale event ignored", "path", dir.path, "fd", fd)
			return
		}
		w.handleDirEvent(dir, kev)
	case isFile:
		if file.token != kev.Udata {
			slog.Debug("inotify stale event ignored", "path", file.path, "fd", fd)
			return
		}
		w.handleFileEvent(file, kev)
	}
}

// handleDirEvent processes one kqueue notification for a watched directory:
// it re-scans the directory, diffs it against the prior snapshot, emits the
// resulting events, and adjusts the watch set for any files or
// subdirectories that appeared or disappeared.
func (w *Watcher) handleDirEvent(dir *watchedDir, kev unix.Kevent_t) {
	if kev.Fflags&(unix.NOTE_DELETE|unix.NOTE_RENAME) != 0 {
		// The vnode itself was removed or renamed away. We don't know its
		// new path (if any) from this notification alone — that comes from
		// the parent directory's own diff pass (Delete/MovedFrom below, or
		// FolderCreate/MovedTo re-registering the new path). Tear down the
		// whole old subtree now so a reused fd number can't later be
		// misattributed to a freshly registered entry, and so we don't leak
		// the fds of any descendants that were watched under this path.
		w.removeSubtree(dir.path)
		return
	}

	if kev.Fflags&unix.NOTE_WRITE == 0 {
		return
	}

	oldSnap := dir.snap
	newSnap := scanDir(dir.path)

	w.mu.Lock()
	dir.snap = newSnap
	w.mu.Unlock()

	evs := diffSnapshot(dir.path, oldSnap, newSnap)
	for _, ev := range evs {
		select {
		case w.Events <- ev:
		case <-w.close:
			return
		}

		name := filepath.Base(ev.Path)
		switch ev.Event {
		case FolderCreate:
			// Recursive: a directory can appear already populated (e.g. a
			// rename within the tree, or an mv of a populated directory
			// into the share), so walk it and register every pre-existing
			// file and subdirectory too, not just the directory itself.
			if err := w.watchDir(ev.Path); err != nil {
				slog.Debug("inotify watchDir", "path", ev.Path, "err", err)
			}
		case FileCreate:
			if err := w.addFile(ev.Path); err != nil {
				slog.Debug("inotify addFile", "path", ev.Path, "err", err)
			}
		case MovedTo:
			if e, ok := newSnap[name]; ok {
				var err error
				if e.isDir {
					// Same reasoning as FolderCreate: re-register the whole
					// subtree at its new path so pre-existing children stay
					// watched and stored paths are refreshed (fixes stale
					// watchedFile.path after an ancestor rename).
					err = w.watchDir(ev.Path)
				} else {
					err = w.addFile(ev.Path)
				}
				if err != nil {
					slog.Debug("inotify addWatch", "path", ev.Path, "err", err)
				}
			}
		case Modified:
			// If the inode behind this name changed, the file was replaced
			// (the write-temp-then-rename save pattern). Our kqueue watch is
			// still on the old, unlinked vnode and would never fire again, so
			// swap it onto the new inode.
			if oldE, ok := oldSnap[name]; ok {
				if newE, ok2 := newSnap[name]; ok2 && oldE.ino != newE.ino && !newE.isDir {
					w.removeFileByPath(ev.Path)
					if err := w.addFile(ev.Path); err != nil {
						slog.Debug("inotify re-arm after replace", "path", ev.Path, "err", err)
					}
				}
			}
		case Delete, MovedFrom:
			if e, ok := oldSnap[name]; ok {
				if e.isDir {
					w.removeSubtree(ev.Path)
				} else {
					w.removeFileByPath(ev.Path)
				}
			}
		}
	}
}

// handleFileEvent processes one kqueue notification for an individually
// watched regular file. NOTE_WRITE/NOTE_EXTEND means its contents changed in
// place, which we report directly as Modified (the parent directory's own
// NOTE_WRITE does not fire for this case, since no directory entry was
// added/removed/renamed). NOTE_DELETE/NOTE_RENAME just tears down this
// watch — the owning directory's diff pass is what reports the actual
// Delete/MovedFrom event.
func (w *Watcher) handleFileEvent(file *watchedFile, kev unix.Kevent_t) {
	if kev.Fflags&(unix.NOTE_DELETE|unix.NOTE_RENAME) != 0 {
		w.removeFileByPath(file.path)
		return
	}

	if kev.Fflags&(unix.NOTE_WRITE|unix.NOTE_EXTEND) == 0 {
		return
	}

	fi, err := os.Lstat(file.path)
	if err != nil {
		return
	}

	// Keep the parent directory's cached snapshot in sync so a later
	// directory-level diff doesn't re-report this file as Modified again
	// from a now-stale cached mtime.
	w.mu.Lock()
	if dfd, ok := w.pathToFd[filepath.Dir(file.path)]; ok {
		if dir, ok := w.dirs[dfd]; ok {
			name := filepath.Base(file.path)
			if e, ok := dir.snap[name]; ok {
				e.mtime = fi.ModTime().UnixNano()
				dir.snap[name] = e
			}
		}
	}
	w.mu.Unlock()

	select {
	case w.Events <- InotifyEvent{Path: file.path, Event: Modified}:
	case <-w.close:
	}
}

// Close signals the watch loop to stop and releases the kqueue and all
// watched directory/file fds. Safe to call more than once.
func (w *Watcher) Close() error {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return nil
	}
	w.closed = true
	watching := w.watching
	w.mu.Unlock()

	if !watching {
		// Watch was never started, so nothing will drain w.close and run
		// the loop's teardown; clean up directly.
		w.closeAllLocked()
		return nil
	}
	close(w.close)
	return nil
}
