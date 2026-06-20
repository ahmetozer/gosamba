//go:build smbclient_e2e

package parent

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ahmetozer/gosamba/internal/config"
	"github.com/ahmetozer/gosamba/internal/userdb"
)

// TestE2E_Xattr_StreamVisibleAndOnDisk verifies that a persisted ADS stream is
// (1) visible to smbclient via `allinfo` as :<name>:$DATA and (2) stored on
// disk as a user.gosamba.ads.<name> xattr readable by getfattr.
//
// smbclient's `put localfile remote:stream` syntax is unreliable across
// versions (it often strips the stream component client-side), so we write the
// stream content directly through the server's xattr layer (the same code path
// the CLOSE handler flushes through) and use smbclient + getfattr purely for
// verification — exactly the documented fallback.
func TestE2E_Xattr_StreamVisibleAndOnDisk(t *testing.T) {
	shareDir := t.TempDir()

	base := filepath.Join(shareDir, "target.txt")
	if err := os.WriteFile(base, []byte("hello base file\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if !xattrSupportedE2E(t, base) {
		t.Skip("filesystem does not support user xattrs")
	}

	streamContent := []byte("resource fork / metadata payload")
	if err := writeStreamXattr(base, "mystream", streamContent); err != nil {
		t.Fatalf("writeStreamXattr: %v", err)
	}

	users := []config.UserConfig{{
		Name:        "alice",
		NTHash:      userdb.NTHash("test123"),
		SystemUser:  "root",
		SystemUID:   0,
		SystemGID:   0,
		AllowShares: []string{"*"},
	}}
	shares := []config.ShareConfig{{Name: "share", Path: shareDir}}

	_, port := startTestServer(t, users, shares, ConnOptions{
		RequireSigning: true, MaxIOSize: 1 << 20,
	})
	time.Sleep(50 * time.Millisecond)

	// --- smbclient allinfo must list the stream ---
	out := smbcli(t, port, "share", "alice%test123", "allinfo target.txt")
	t.Logf("allinfo output:\n%s", out)
	if !strings.Contains(out, ":mystream:$DATA") {
		t.Errorf("allinfo did not list :mystream:$DATA stream; output:\n%s", out)
	}

	// --- getfattr must show the on-disk xattr with matching content ---
	// (Optional verification: when getfattr is absent we still have the allinfo
	// assertion above; do not skip the whole test.)
	if _, err := exec.LookPath("getfattr"); err != nil {
		t.Log("getfattr not found; on-disk verification skipped (allinfo assertion already passed)")
		return
	}
	gf := exec.Command("getfattr", "-n", "user.gosamba.ads.mystream", "--only-values", base)
	gfOut, err := gf.CombinedOutput()
	if err != nil {
		t.Fatalf("getfattr: %v\noutput:\n%s", err, gfOut)
	}
	if string(gfOut) != string(streamContent) {
		t.Errorf("getfattr value = %q, want %q", gfOut, streamContent)
	}
	t.Log("ADS stream visible via smbclient allinfo and persisted on disk as user.gosamba.ads.mystream")
}

// xattrSupportedE2E mirrors xattrSupported but is defined here so the e2e build
// tag file is self-contained.
func xattrSupportedE2E(t *testing.T, path string) bool {
	t.Helper()
	if err := writeStreamXattr(path, "__probe__", []byte("x")); err != nil {
		return false
	}
	_ = removeStreamXattr(path, "__probe__")
	return true
}
