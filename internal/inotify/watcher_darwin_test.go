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
