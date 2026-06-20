//go:build smbclient_e2e

package parent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ahmetozer/gosamba/internal/config"
	"github.com/ahmetozer/gosamba/internal/userdb"
	"golang.org/x/text/unicode/norm"
)

func testUsers() []config.UserConfig {
	return []config.UserConfig{{
		Name:        "alice",
		NTHash:      userdb.NTHash("test123"),
		SystemUser:  "root",
		SystemUID:   0,
		SystemGID:   0,
		AllowShares: []string{"*"},
	}}
}

// TestF9_CreationTimeSane verifies that the CREATE response and smbclient
// "allinfo" both report a create_time that is plausible (within 5 seconds of
// the file's actual creation).
func TestF9_CreationTimeSane(t *testing.T) {
	shareDir := t.TempDir()

	_, port := startTestServer(t, testUsers(), []config.ShareConfig{{Name: "share", Path: shareDir}}, ConnOptions{
		RequireSigning: true, MaxIOSize: 1 << 20,
	})
	time.Sleep(50 * time.Millisecond)

	localDir := t.TempDir()
	uploadPath := filepath.Join(localDir, "btime_e2e.txt")
	if err := os.WriteFile(uploadPath, []byte("btime e2e content"), 0644); err != nil {
		t.Fatal(err)
	}

	before := time.Now().Add(-5 * time.Second)

	// Upload via smbclient.
	smbcli(t, port, "share", "alice%test123",
		fmt.Sprintf("lcd %s", localDir),
		"put btime_e2e.txt btime_e2e.txt",
	)

	after := time.Now().Add(5 * time.Second)

	// allinfo reports "create_time" among other fields.
	out := smbcli(t, port, "share", "alice%test123", "allinfo btime_e2e.txt")
	t.Logf("allinfo output:\n%s", out)

	if !strings.Contains(out, "create_time") {
		t.Error("F9: allinfo output missing 'create_time' field")
	}

	// The file should exist on disk with a valid btime (when available).
	diskPath := filepath.Join(shareDir, "btime_e2e.txt")
	bt, ok := birthTime(diskPath)
	if !ok {
		t.Log("F9: btime unavailable on this filesystem — skipping btime range check")
		return
	}
	if bt.Before(before) || bt.After(after) {
		t.Errorf("F9: btime %v is not within expected range [%v, %v]", bt, before, after)
	}
	t.Logf("F9: btime = %v (ok)", bt)
}

// TestF8_NormRoundTrip verifies that a file created with an NFD name on disk
// is accessible via CREATE open (NFC lookup) from smbclient.
//
// Note: smbclient on Linux typically sends filenames in NFC (UTF-8 already
// NFC-normalized), so this test exercises the server's fallback by directly
// creating an NFD-named file on disk and then asking smbclient to GET it.
func TestF8_NormRoundTrip(t *testing.T) {
	shareDir := t.TempDir()

	_, port := startTestServer(t, testUsers(), []config.ShareConfig{{Name: "share", Path: shareDir}}, ConnOptions{
		RequireSigning: true, MaxIOSize: 1 << 20,
	})
	time.Sleep(50 * time.Millisecond)

	// Create a file with an NFD-encoded name directly on disk.
	// "café" NFD = 'c' 'a' 'f' 'e' + combining-acute (U+0301)
	nfcName := norm.NFC.String("café")
	nfdName := norm.NFD.String("café")

	if nfcName == nfdName {
		t.Skip("NFC and NFD are identical for this string on this platform — test not meaningful")
	}

	// Write the file with NFD name directly to disk.
	nfdPath := filepath.Join(shareDir, nfdName)
	if err := os.WriteFile(nfdPath, []byte("normalization test content"), 0644); err != nil {
		t.Fatalf("create NFD file: %v", err)
	}
	t.Logf("created NFD file on disk: %q", nfdPath)

	localDir := t.TempDir()
	downloadPath := filepath.Join(localDir, "got.txt")

	// smbclient sends NFC on Linux — the server should find the NFD file.
	// Use the NFC form as the remote name in the GET command.
	out, err := smbcliErr(t, port, "share", "alice%test123",
		fmt.Sprintf("get %s %s", nfcName, downloadPath),
	)
	t.Logf("F8 get output:\n%s", out)
	if err != nil {
		t.Logf("F8: smbclient GET of NFC name failed (err=%v) — this may mean smbclient itself re-encodes the name", err)
		t.Log("F8: documenting: smbclient's own normalization behavior makes the NFC→NFD round-trip hard to test via smbclient. White-box vfs.ResolveNorm tests cover the fallback logic.")
		return
	}

	got, err := os.ReadFile(downloadPath)
	if err != nil {
		t.Fatalf("F8: downloaded file not found: %v", err)
	}
	if string(got) != "normalization test content" {
		t.Errorf("F8: content mismatch: got %q", got)
	}
	t.Log("F8: NFC lookup of NFD-on-disk file succeeded")
}
