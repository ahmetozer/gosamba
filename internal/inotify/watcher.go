//go:build linux

package inotify

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/sys/unix"
)

type watchState uint8

const (
	stateNotInitialized watchState = iota
	stateInitialized
	stateWatching
	stateClosed
)

// Watcher handles inotify watching for a directory tree.
type Watcher struct {
	mu    sync.RWMutex
	state watchState
	close chan struct{}
	// closeOnce guards close(w.close) so Close is idempotent and safe to call
	// from several goroutines at once.
	closeOnce sync.Once
	// eventsOnce guards close(w.Events): it is closed either by Watch's
	// teardown or, when Watch never ran, by Close — never by both.
	eventsOnce sync.Once
	fd         int
	// wakeR/wakeW are the two ends of a self-pipe used purely to interrupt
	// the event loop. An inotify fd offers no way to cancel a pending read:
	// a goroutine blocked in read(2) stays blocked until an event happens to
	// arrive, and closing the fd underneath it neither reliably returns the
	// reader nor is safe (the fd number can be recycled by another
	// goroutine's open between the close and the reader noticing). So Watch
	// waits on the inotify fd *and* this pipe via poll(2), and Close writes a
	// byte to wakeW to bring the poll back immediately.
	wakeR, wakeW int
	path         string
	// recursive is set by the constructor and never mutated afterwards, so
	// the event loop reads it without holding mu.
	recursive bool
	watchMap  map[int]string
	Events    chan InotifyEvent
}

// addWatch registers a single inotify watch on dir.
func (w *Watcher) addWatch(dir string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.state == stateClosed {
		// w.fd is gone (and its number may already have been reused), so
		// there is nothing safe to register against.
		return nil
	}
	watch, err := unix.InotifyAddWatch(w.fd, dir,
		unix.IN_CREATE|unix.IN_DELETE|
			unix.IN_MODIFY|unix.IN_MOVED_FROM|
			unix.IN_MOVED_TO)
	if err != nil {
		return fmt.Errorf("failed to add watch for %s: %w", dir, err)
	}
	w.watchMap[watch] = dir
	return nil
}

// watchDir registers path and, for a recursive watcher, every subdirectory
// beneath it. A non-recursive watcher deliberately stops at path: SMB2
// CHANGE_NOTIFY without SMB2_WATCH_TREE only reports changes in the
// immediate directory, so walking the whole subtree to install watches whose
// events the caller then discards is pure cost.
func (w *Watcher) watchDir(path string) error {
	if !w.recursive {
		return w.addWatch(path)
	}
	return filepath.Walk(path, func(walkPath string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !fi.IsDir() {
			return nil
		}
		return w.addWatch(walkPath)
	})
}

// closeFDsLocked releases every descriptor the watcher owns and drops the
// watch map with them, since closing the inotify fd is what invalidates
// every watch descriptor in it. Callers must hold w.mu and must set state to
// stateClosed in the same critical section, which is what makes "state ==
// stateWatching under the lock" a reliable proof that the descriptors below
// are still open.
func (w *Watcher) closeFDsLocked() {
	unix.Close(w.fd)
	unix.Close(w.wakeR)
	unix.Close(w.wakeW)
	clear(w.watchMap)
}

// wakeLocked nudges the self-pipe so a poll blocked in Watch returns now.
// Callers must hold w.mu with state == stateWatching so wakeW cannot have
// been closed (and its number reused) underneath us. The pipe is
// non-blocking and only ever holds wakeup bytes, so this cannot block; a
// full pipe already means a wakeup is pending, which is all we need.
func (w *Watcher) wakeLocked() {
	for {
		_, err := unix.Write(w.wakeW, []byte{0})
		if err == unix.EINTR {
			continue
		}
		return
	}
}

// Watch starts the event loop. Blocks until Close.
func (w *Watcher) Watch() error {
	w.mu.Lock()
	if w.state != stateInitialized {
		w.mu.Unlock()
		return fmt.Errorf("invalid state: %d", w.state)
	}
	w.state = stateWatching
	fd, wakeR := w.fd, w.wakeR
	w.mu.Unlock()

	defer func() {
		w.mu.Lock()
		w.closeFDsLocked()
		w.state = stateClosed
		w.mu.Unlock()
		select {
		case w.Events <- InotifyEvent{Event: WatchStop}:
		default:
		}
		w.eventsOnce.Do(func() { close(w.Events) })
	}()

	// Watch both the inotify fd and the wakeup pipe. poll(2) blocks with no
	// timeout: every reason to wake up (an inotify event, or Close) has its
	// own descriptor here, so there is nothing for a periodic tick to notice.
	fds := []unix.PollFd{
		{Fd: int32(fd), Events: unix.POLLIN},
		{Fd: int32(wakeR), Events: unix.POLLIN},
	}
	buf := make([]byte, 4096)
	for {
		select {
		case <-w.close:
			return nil
		default:
		}

		fds[0].Revents, fds[1].Revents = 0, 0
		if _, err := unix.Poll(fds, -1); err != nil {
			if err == unix.EINTR {
				continue
			}
			return fmt.Errorf("poll: %w", err)
		}
		if fds[1].Revents != 0 {
			// Close wrote to (or tore down) the self-pipe.
			return nil
		}
		if fds[0].Revents&unix.POLLIN == 0 {
			// POLLERR/POLLNVAL/POLLHUP on the inotify fd: nothing left to
			// read, and spinning on poll would burn a core.
			if fds[0].Revents != 0 {
				return fmt.Errorf("poll: inotify fd revents 0x%x", fds[0].Revents)
			}
			continue
		}
		n, err := unix.Read(fd, buf)
		if err != nil {
			// The fd is non-blocking, so a wakeup with nothing left to read
			// (another reader, or a false-positive POLLIN) yields EAGAIN.
			if err == unix.EINTR || err == unix.EAGAIN {
				continue
			}
			return fmt.Errorf("read: %w", err)
		}
		if err := w.parseEvents(buf[:n]); err != nil {
			slog.Debug("inotify parseEvents", "err", err)
		}
	}
}

// Close stops the watch loop and releases the inotify instance. It is
// idempotent and safe to call concurrently with Watch.
func (w *Watcher) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	switch w.state {
	case stateNotInitialized, stateClosed:
		return nil
	case stateInitialized:
		// Watch was never started, so nothing will run the loop's teardown:
		// release the descriptors here and close Events so a reader that
		// never saw the loop start still observes the end of the stream.
		w.closeFDsLocked()
		w.state = stateClosed
		w.closeOnce.Do(func() { close(w.close) })
		w.eventsOnce.Do(func() { close(w.Events) })
		return nil
	}

	// stateWatching: the loop owns the descriptors and will close them on the
	// way out. Signal it and wake the blocked poll so it exits now rather
	// than whenever the next filesystem event happens to arrive.
	w.closeOnce.Do(func() { close(w.close) })
	w.wakeLocked()
	return nil
}
