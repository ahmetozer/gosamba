package inotify

import "testing"

func TestEventTypeConstantsDistinct(t *testing.T) {
	all := []EventType{FolderCreate, FileCreate, Delete, Modified, MovedFrom, MovedTo, WatchStop}
	seen := map[EventType]bool{}
	for _, e := range all {
		if seen[e] {
			t.Fatalf("duplicate EventType value %d", e)
		}
		seen[e] = true
	}
	ev := InotifyEvent{Path: "/x", Event: Modified}
	if ev.Path != "/x" || ev.Event != Modified {
		t.Fatalf("InotifyEvent round-trip failed: %+v", ev)
	}
}
