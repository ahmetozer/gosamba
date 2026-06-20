//go:build linux

package inotify

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

type EventType uint8

const (
	FolderCreate EventType = iota
	FileCreate
	Delete
	Modified
	MovedFrom
	MovedTo
	WatchStop
)

const inotifyEventBaseSize = 16

type InotifyEvent struct {
	Path  string
	Event EventType
}

type systemInotifyEvent struct {
	Wd     int32
	Mask   uint32
	Cookie uint32
	Len    uint32
}

func (w *Watcher) parseEvents(buf []byte) error {
	var offset int
	for offset < len(buf) {
		if offset+inotifyEventBaseSize > len(buf) {
			return fmt.Errorf("insufficient buffer size")
		}
		var event systemInotifyEvent
		if err := binary.Read(bytes.NewReader(buf[offset:offset+inotifyEventBaseSize]), binary.LittleEndian, &event); err != nil {
			return fmt.Errorf("read event: %w", err)
		}
		name := ""
		if event.Len > 0 {
			nameBytes := buf[offset+inotifyEventBaseSize : offset+inotifyEventBaseSize+int(event.Len)]
			name = string(bytes.TrimRight(nameBytes, "\x00"))
		}
		w.mu.RLock()
		dirPath, ok := w.watchMap[int(event.Wd)]
		w.mu.RUnlock()
		if !ok {
			offset += inotifyEventBaseSize + int(event.Len)
			continue
		}
		fullPath := filepath.Join(dirPath, name)
		w.handleEvent(event, fullPath)
		offset += inotifyEventBaseSize + int(event.Len)
	}
	return nil
}

func (w *Watcher) handleEvent(ev systemInotifyEvent, fullPath string) {
	switch {
	case ev.Mask&unix.IN_CREATE != 0:
		if fi, err := os.Stat(fullPath); err == nil && fi.IsDir() {
			_ = w.watchDir(fullPath)
			w.send(InotifyEvent{Path: fullPath, Event: FolderCreate})
		} else {
			w.send(InotifyEvent{Path: fullPath, Event: FileCreate})
		}
	case ev.Mask&unix.IN_DELETE != 0:
		w.send(InotifyEvent{Path: fullPath, Event: Delete})
	case ev.Mask&unix.IN_MODIFY != 0:
		w.send(InotifyEvent{Path: fullPath, Event: Modified})
	case ev.Mask&unix.IN_MOVED_FROM != 0:
		w.send(InotifyEvent{Path: fullPath, Event: MovedFrom})
	case ev.Mask&unix.IN_MOVED_TO != 0:
		w.send(InotifyEvent{Path: fullPath, Event: MovedTo})
	}
}

func (w *Watcher) send(ev InotifyEvent) {
	select {
	case w.Events <- ev:
	default:
		// Drop if buffer full; client will reconcile via re-listing.
	}
}
