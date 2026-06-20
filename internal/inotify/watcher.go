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

// Watcher handles inotify watching for a directory tree (recursive).
type Watcher struct {
	mu       sync.RWMutex
	state    watchState
	close    chan struct{}
	fd       int
	path     string
	watchMap map[int]string
	Events   chan InotifyEvent
}

func (w *Watcher) watchDir(path string) error {
	return filepath.Walk(path, func(walkPath string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !fi.IsDir() {
			return nil
		}
		w.mu.Lock()
		defer w.mu.Unlock()
		watch, err := unix.InotifyAddWatch(w.fd, walkPath,
			unix.IN_CREATE|unix.IN_DELETE|
				unix.IN_MODIFY|unix.IN_MOVED_FROM|
				unix.IN_MOVED_TO)
		if err != nil {
			return fmt.Errorf("failed to add watch for %s: %w", walkPath, err)
		}
		w.watchMap[watch] = walkPath
		return nil
	})
}

// Watch starts the event loop. Blocks until Close.
func (w *Watcher) Watch() error {
	w.mu.Lock()
	if w.state != stateInitialized {
		w.mu.Unlock()
		return fmt.Errorf("invalid state: %d", w.state)
	}
	w.state = stateWatching
	w.mu.Unlock()

	defer func() {
		w.mu.Lock()
		unix.Close(w.fd)
		w.state = stateClosed
		w.mu.Unlock()
		select {
		case w.Events <- InotifyEvent{Event: WatchStop}:
		default:
		}
		close(w.Events)
	}()

	buf := make([]byte, 4096)
	for {
		select {
		case <-w.close:
			return nil
		default:
			n, err := unix.Read(w.fd, buf)
			if err != nil {
				if err == unix.EINTR {
					continue
				}
				return fmt.Errorf("read: %w", err)
			}
			if err := w.parseEvents(buf[:n]); err != nil {
				slog.Debug("inotify parseEvents", "err", err)
			}
		}
	}
}

func (w *Watcher) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.state != stateWatching && w.state != stateInitialized {
		return nil
	}
	if w.state == stateInitialized {
		unix.Close(w.fd)
		w.state = stateClosed
		return nil
	}
	w.state = stateClosed
	close(w.close)
	return nil
}
