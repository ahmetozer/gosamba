package inotify

import (
	"reflect"
	"sort"
	"testing"
)

func names(evs []InotifyEvent) []string {
	out := make([]string, len(evs))
	for i, e := range evs {
		out[i] = e.Path + ":" + itoa(e.Event)
	}
	sort.Strings(out)
	return out
}

func TestDiffSnapshotCreateDeleteModify(t *testing.T) {
	before := map[string]dirEntry{
		"a.txt": {ino: 1, mtime: 100, isDir: false},
		"keep":  {ino: 2, mtime: 100, isDir: true},
	}
	after := map[string]dirEntry{
		"keep":  {ino: 2, mtime: 100, isDir: true},
		"b.txt": {ino: 3, mtime: 200, isDir: false}, // created
	}
	// a.txt removed, b.txt created
	got := diffSnapshot("/root", before, after)
	want := []string{"/root/a.txt:" + itoa(Delete), "/root/b.txt:" + itoa(FileCreate)}
	if g := names(got); !reflect.DeepEqual(g, want) {
		t.Fatalf("got %v want %v", g, want)
	}
}

func TestDiffSnapshotRenameByInode(t *testing.T) {
	before := map[string]dirEntry{"old.txt": {ino: 7, mtime: 100}}
	after := map[string]dirEntry{"new.txt": {ino: 7, mtime: 100}}
	got := diffSnapshot("/root", before, after)
	want := []string{"/root/new.txt:" + itoa(MovedTo), "/root/old.txt:" + itoa(MovedFrom)}
	if g := names(got); !reflect.DeepEqual(g, want) {
		t.Fatalf("got %v want %v", g, want)
	}
}

func TestDiffSnapshotModify(t *testing.T) {
	before := map[string]dirEntry{"f": {ino: 5, mtime: 100}}
	after := map[string]dirEntry{"f": {ino: 5, mtime: 250}}
	got := diffSnapshot("/root", before, after)
	want := []string{"/root/f:" + itoa(Modified)}
	if g := names(got); !reflect.DeepEqual(g, want) {
		t.Fatalf("got %v want %v", g, want)
	}
}
