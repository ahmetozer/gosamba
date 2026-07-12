//go:build darwin

package parent

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBirthTimeDarwin(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f.txt")
	if err := os.WriteFile(p, []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	bt, ok := birthTime(p)
	if !ok {
		t.Fatal("expected a valid birth time on APFS/HFS+")
	}
	if time.Since(bt) > time.Minute || bt.After(time.Now().Add(time.Minute)) {
		t.Fatalf("birth time %v is not near now", bt)
	}
	if _, ok := birthTime(filepath.Join(dir, "nope")); ok {
		t.Fatal("expected ok=false for missing file")
	}
}
