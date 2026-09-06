//go:build darwin

// Package inotify's darwin implementation: a recursive change-notify watcher
// built on kqueue (EVFILT_VNODE) plus directory-snapshot diffing.
//
// kqueue only tells us *that* a watched vnode changed, not *what* changed.
// For directories, NOTE_WRITE fires when an entry is added, removed, or
// renamed — but not when an existing file's contents are modified in place.
// So regular files discovered under a watched directory are also opened and
// registered individually: a file's own NOTE_WRITE/NOTE_EXTEND is what lets
// us detect in-place modification and report a Modified event. On a
// directory wakeup we re-scan the directory, diff the old and new snapshots
// via diffSnapshot, emit the resulting events, and register/drop file and
// subdirectory watches for whatever appeared or disappeared.
//
// Every watch costs an open descriptor for as long as it lives, so the
// number of watches is capped process-wide by watchBudget; see its comment
// for the cap and for what is lost once it is reached.
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

// wakeIdent is the EVFILT_USER ident Close triggers to interrupt a blocked
// kevent. kqueue keys registrations on (ident, filter), so it cannot collide
// with the EVFILT_VNODE registrations, whose idents are file descriptors.
const wakeIdent = 1

// Bounds on the process-wide watch descriptor budget; see fdBudget.
const (
	minWatchFDs = 32
	maxWatchFDs = 512
)

// fdBudget caps how many descriptors all watchers in this process may hold
// open for watches at once.
//
// kqueue can only watch an *open* descriptor, so each watched directory and
// each individually watched file costs one fd for as long as the watch
// lives. A watcher is created per SMB2 CHANGE_NOTIFY request and, when the
// client asked for SMB2_WATCH_TREE, registers the entire subtree — so a
// large share, or a handful of concurrent notify requests, could otherwise
// walk the process straight into EMFILE (macOS's default RLIMIT_NOFILE is
// 256) and take the whole server down with it.
//
// The budget is process-global on purpose: a per-watcher cap would still let
// N concurrent requests multiply their way past the limit.
//
// Exhausting it is a degradation, never an error. Directory watches are what
// produce create/delete/rename events, so they may use the whole budget;
// per-file watches, which only add in-place-modification detection, may use
// at most half of it, so a single enormous directory cannot starve every
// other watcher of its directory watches. What is lost past the cap is
// notification for the entries that could not be registered — an SMB client
// recovers by re-enumerating the directory, which is exactly what it already
// has to do when the event buffer overflows.
type fdBudget struct {
	mu    sync.Mutex
	limit int
	dirs  int
	files int
}

// watchBudget is the budget every watcher created through New/NewWatcher
// draws on.
var watchBudget = newFDBudget()

// newFDBudget sizes the budget from the process's own descriptor limit,
// leaving the large majority of it for the connections and open files that
// are the server's actual job.
func newFDBudget() *fdBudget {
	limit := minWatchFDs
	var rl unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &rl); err == nil && rl.Cur > 0 {
		if share := rl.Cur / 8; share < uint64(maxWatchFDs) {
			limit = int(share)
		} else {
			limit = maxWatchFDs
		}
	}
	if limit < minWatchFDs {
		limit = minWatchFDs
	}
	return &fdBudget{limit: limit}
}

// acquireDir reserves a slot for a directory watch. force bypasses the cap
// and is used only for a watcher's own root: a watcher holding no watch at
// all would silently report nothing forever, and one guaranteed descriptor
// per watcher is bounded by the number of CHANGE_NOTIFY requests in flight.
func (b *fdBudget) acquireDir(force bool) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !force && b.dirs+b.files >= b.limit {
		return false
	}
	b.dirs++
	return true
}

// acquireFile reserves a slot for an individual file watch.
func (b *fdBudget) acquireFile() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.dirs+b.files >= b.limit || b.files >= b.limit/2 {
		return false
	}
	b.files++
	return true
}

// release returns dirs directory slots and files file slots to the budget.
func (b *fdBudget) release(dirs, files int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.dirs -= dirs
	b.files -= files
	if b.dirs < 0 {
		b.dirs = 0
	}
	if b.files < 0 {
		b.files = 0
	}
}

// exhausted reports whether no further watch of any kind fits. A tree walk
// checks this to stop early rather than stat its way through the rest of a
// subtree it has no descriptors left to watch.
func (b *fdBudget) exhausted() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.dirs+b.files >= b.limit
}

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

// Watcher handles kqueue-based watching for a directory tree.
type Watcher struct {
	mu   sync.Mutex
	kq   int
	root string
	// recursive is set by the constructor and never mutated afterwards, so
	// the event loop reads it without holding mu.
	recursive    bool
	budget       *fdBudget
	dirs         map[int]*watchedDir  // dir fd (kqueue ident) -> dir state
	pathToFd     map[string]int       // dir path -> dir fd
	files        map[int]*watchedFile // file fd (kqueue ident) -> file state
	filePathToFd map[string]int       // file path -> file fd
	closed       bool
	// fdsClosed records that closeAll already ran, so it runs exactly once
	// and so Close knows whether w.kq is still safe to poke.
	fdsClosed bool
	watching  bool
	// degraded records that the budget refused at least one registration,
	// so the warning is logged once per watcher rather than once per entry.
	degraded   bool
	close      chan struct{}
	eventsOnce sync.Once
	Events     chan InotifyEvent
}

// New creates a recursive kqueue watcher for the specified path.
func New(path string) (*Watcher, error) {
	return NewWatcher(path, true)
}

// NewWatcher creates a kqueue watcher for path. When recursive is true the
// whole subtree is watched; when it is false only path's own directory and
// the regular files directly inside it are, which is what an SMB2
// CHANGE_NOTIFY without SMB2_WATCH_TREE actually asks for — the caller would
// discard every subtree event anyway, so registering them only costs walk
// time and descriptors.
func NewWatcher(path string, recursive bool) (*Watcher, error) {
	return newWatcher(path, recursive, watchBudget)
}

// newWatcher is NewWatcher with an explicit descriptor budget, so tests can
// exercise the exhausted path against a small budget of their own instead of
// mutating the process-wide one out from under any live watcher.
func newWatcher(path string, recursive bool, budget *fdBudget) (*Watcher, error) {
	kq, err := unix.Kqueue()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize kqueue: %w", err)
	}

	// Register the wakeup up front. EVFILT_VNODE gives Close nothing to
	// interrupt — a blocked kevent returns only when a watched vnode
	// changes — and closing w.kq underneath a blocked kevent is racy, since
	// the descriptor number can be reused before the loop notices. A user
	// event registered here is triggerable at any later point, and stays
	// pending if it is triggered before the loop ever reaches kevent.
	wake := unix.Kevent_t{
		Ident:  wakeIdent,
		Filter: unix.EVFILT_USER,
		Flags:  unix.EV_ADD | unix.EV_CLEAR,
	}
	if _, err := unix.Kevent(kq, []unix.Kevent_t{wake}, nil, nil); err != nil {
		unix.Close(kq)
		return nil, fmt.Errorf("failed to register wakeup: %w", err)
	}

	w := &Watcher{
		kq:           kq,
		root:         path,
		recursive:    recursive,
		budget:       budget,
		dirs:         make(map[int]*watchedDir),
		pathToFd:     make(map[string]int),
		files:        make(map[int]*watchedFile),
		filePathToFd: make(map[string]int),
		close:        make(chan struct{}),
		Events:       make(chan InotifyEvent, 100),
	}

	if err := w.watchTree(path, true); err != nil {
		w.closeAll()
		return nil, err
	}

	slog.Debug("inotify.New", "path", path, "recursive", recursive)
	return w, nil
}

// closeAll closes every currently-registered fd (kqueue included) and hands
// their slots back to the budget. It takes the lock itself; callers must not
// already hold w.mu. Idempotent, so the watch loop's teardown and a Close
// that beat it there cannot double-close a descriptor or double-credit the
// budget.
func (w *Watcher) closeAll() {
	w.mu.Lock()
	if w.fdsClosed {
		w.mu.Unlock()
		return
	}
	w.fdsClosed = true
	nDirs, nFiles := len(w.dirs), len(w.files)
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
	w.budget.release(nDirs, nFiles)
}

// noteDegraded records, once per watcher, that the descriptor budget refused
// a registration — so an operator gets one line explaining why changes under
// this watch may go unreported, instead of silence.
func (w *Watcher) noteDegraded(path string) {
	w.mu.Lock()
	first := !w.degraded
	w.degraded = true
	w.mu.Unlock()
	if first {
		slog.Warn("inotify watch budget exhausted, some changes may go unreported",
			"root", w.root, "path", path, "limit", w.budget.limit)
	}
}

// watchTree registers path and everything under it that this watcher covers:
// the whole subtree when recursive, otherwise just path plus the regular
// files directly inside it (an in-place write never touches the parent
// directory's vnode, so without a per-file watch nothing would report it).
//
// forceRoot exempts path's own directory watch from the descriptor budget;
// it is set only for the watcher's root. Budget exhaustion below that point
// is not an error: the watch set is simply smaller than the tree.
func (w *Watcher) watchTree(path string, forceRoot bool) error {
	// Registered outside the walk below so that a forced root is registered
	// before any budget check can cut the walk short.
	if err := w.addDir(path, forceRoot); err != nil {
		return err
	}

	if !w.recursive {
		entries, err := os.ReadDir(path)
		if err != nil {
			// The directory vanished under us; its parent's diff pass is
			// what reports that, so there is nothing to do here.
			return nil
		}
		for _, e := range entries {
			if !e.Type().IsRegular() {
				continue
			}
			child := filepath.Join(path, e.Name())
			if err := w.addFile(child); err != nil {
				slog.Debug("inotify addFile", "path", child, "err", err)
			}
		}
		return nil
	}

	return filepath.Walk(path, func(walkPath string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if walkPath == path {
			return nil // already registered above
		}
		if w.budget.exhausted() {
			// Nothing further can be registered, so stop walking rather than
			// stat every remaining entry of what may be a very large tree.
			return filepath.SkipAll
		}
		if fi.IsDir() {
			return w.addDir(walkPath, false)
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
// reactively discovered via FolderCreate/MovedTo) must use watchTree
// instead, which walks and registers the whole subtree.
//
// force bypasses the descriptor budget and is reserved for a watcher's own
// root; see fdBudget.acquireDir. A registration the budget refuses is not an
// error — it is the documented degradation — so addDir returns nil for it.
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
func (w *Watcher) addDir(path string, force bool) error {
	if !w.budget.acquireDir(force) {
		w.noteDegraded(path)
		return nil
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_EVTONLY, 0)
	if err != nil {
		w.budget.release(1, 0)
		return fmt.Errorf("failed to open %s: %w", path, err)
	}

	snap := scanDir(path)
	token := new(byte)

	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		unix.Close(fd)
		w.budget.release(1, 0)
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
		w.budget.release(1, 0)
		return fmt.Errorf("failed to register watch for %s: %w", path, err)
	}
	// A path can end up registered twice (a subtree re-walked at its new name
	// while the old registration is still live, say); drop the previous one
	// so neither its descriptor nor its budget slot is orphaned.
	if oldFd, ok := w.pathToFd[path]; ok {
		delete(w.dirs, oldFd)
		unix.Close(oldFd)
		w.budget.release(1, 0)
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
	if !w.budget.acquireFile() {
		// Degraded, not fatal: the parent directory's own watch still
		// reports this file being created, deleted or renamed. Only
		// modification of its contents in place goes unreported.
		w.noteDegraded(path)
		return nil
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_EVTONLY, 0)
	if err != nil {
		w.budget.release(0, 1)
		return fmt.Errorf("failed to open %s: %w", path, err)
	}

	token := new(byte)

	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		unix.Close(fd)
		w.budget.release(0, 1)
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
		w.budget.release(0, 1)
		return fmt.Errorf("failed to register watch for %s: %w", path, err)
	}
	// See addDir: never orphan a previous registration of the same path.
	if oldFd, ok := w.filePathToFd[path]; ok {
		delete(w.files, oldFd)
		unix.Close(oldFd)
		w.budget.release(0, 1)
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
		w.budget.release(0, 1)
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
	var nDirs, nFiles int
	for path, fd := range w.pathToFd {
		if path == prefix || strings.HasPrefix(path, nested) {
			delete(w.pathToFd, path)
			delete(w.dirs, fd)
			fds = append(fds, fd)
			nDirs++
		}
	}
	for path, fd := range w.filePathToFd {
		if path == prefix || strings.HasPrefix(path, nested) {
			delete(w.filePathToFd, path)
			delete(w.files, fd)
			fds = append(fds, fd)
			nFiles++
		}
	}
	w.mu.Unlock()
	for _, fd := range fds {
		unix.Close(fd)
	}
	w.budget.release(nDirs, nFiles)
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
		w.closeAll()
		select {
		case w.Events <- InotifyEvent{Event: WatchStop}:
		default:
		}
		w.eventsOnce.Do(func() { close(w.Events) })
	}()

	events := make([]unix.Kevent_t, 16)
	for {
		select {
		case <-w.close:
			return nil
		default:
		}

		// No timeout: every reason to wake up — a watched vnode changing, or
		// Close triggering the wakeup registered in newWatcher — has its own
		// kqueue registration, so a periodic tick would only burn cycles.
		// There is one watcher per outstanding CHANGE_NOTIFY request, so
		// those ticks used to add up.
		n, err := unix.Kevent(w.kq, nil, events, nil)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return fmt.Errorf("kevent: %w", err)
		}
		for i := 0; i < n; i++ {
			if events[i].Filter == unix.EVFILT_USER {
				// Close asked us to stop.
				return nil
			}
			w.handleEvent(events[i])
		}
	}
}

// triggerWakeLocked fires the EVFILT_USER event so a kevent blocked in Watch
// returns now. Callers must hold w.mu and must have checked that closeAll
// has not run, so w.kq cannot be closed (and its number reused) underneath.
func (w *Watcher) triggerWakeLocked() {
	kev := unix.Kevent_t{
		Ident:  wakeIdent,
		Filter: unix.EVFILT_USER,
		Fflags: unix.NOTE_TRIGGER,
	}
	if _, err := unix.Kevent(w.kq, []unix.Kevent_t{kev}, nil, nil); err != nil {
		slog.Debug("inotify wake", "err", err)
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
			// A directory can appear already populated (e.g. a rename within
			// the tree, or an mv of a populated directory into the share),
			// so walk it and register every pre-existing file and
			// subdirectory too, not just the directory itself. A
			// non-recursive watcher does not follow it at all.
			if w.recursive {
				if err := w.watchTree(ev.Path, false); err != nil {
					slog.Debug("inotify watchTree", "path", ev.Path, "err", err)
				}
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
					// watchedFile.path after an ancestor rename). Again, a
					// non-recursive watcher does not follow subdirectories.
					if w.recursive {
						err = w.watchTree(ev.Path, false)
					}
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
// watched directory/file fds. Idempotent and safe to call concurrently with
// Watch.
func (w *Watcher) Close() error {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return nil
	}
	w.closed = true
	watching := w.watching
	if watching && !w.fdsClosed {
		// Wake the blocked kevent so the loop tears down (and hands its
		// descriptors back) now, rather than whenever the next filesystem
		// event happens to arrive. Done while holding w.mu: the loop's own
		// teardown takes the same lock before closing w.kq, so the
		// descriptor cannot be closed, or its number reused, between the
		// fdsClosed check and the trigger.
		w.triggerWakeLocked()
	}
	w.mu.Unlock()

	if !watching {
		// Watch was never started, so nothing will drain w.close and run the
		// loop's teardown; clean up directly, and close Events so a reader
		// that never saw the loop start still observes the end of the stream.
		w.closeAll()
		w.eventsOnce.Do(func() { close(w.Events) })
		return nil
	}
	close(w.close)
	return nil
}

// watchCounts reports how many descriptors this watcher currently holds for
// directory and for individual-file watches. Used by the tests to assert the
// watch set stays bounded.
func (w *Watcher) watchCounts() (dirs, files int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.dirs), len(w.files)
}
