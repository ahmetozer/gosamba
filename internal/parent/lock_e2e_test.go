//go:build smbclient_e2e

package parent

// SMB2 byte-range locking end-to-end test.
//
// smbclient lock-command notes (Samba 4.17):
//
//   smbclient's interactive "lock <fnum> [r|w] <hex-start> <hex-len>" command
//   calls cli_posix_lock(), which uses the POSIX extension flow (TRANS2
//   QFILEPATHINFO) rather than the standard SMB2 LOCK command (0x000A). That
//   path requires the server to advertise Unix extensions, which gosamba does
//   not implement. Attempting it here would fail at the "posix" handshake, not
//   at the LOCK layer — an unhelpful signal.
//
//   The standard SMB2 LOCK command (CommandLock, 0x000A) is used by Windows
//   clients directly (e.g. SQLite WAL mode, Microsoft Office). smbclient does
//   not expose a command-line switch that forces a raw SMB2 LOCK PDU without
//   the POSIX extension preamble.
//
//   What we CAN verify end-to-end via smbclient:
//
//   (a) The baseline file operations (put/get/ls/mkdir/rename/del) still work
//       after the dispatch.go change — no regression from wiring CommandLock.
//   (b) A file can be opened and closed without the server returning
//       STATUS_NOT_SUPPORTED for any surrounding LOCK frame sent by the client.
//       (smbclient does NOT send SMB2 LOCK for a plain "open" flow.)
//
//   Robust SMB2 LOCK e2e coverage requires a Windows SMB2 client library or a
//   purpose-built Go SMB2 client (not available per project constraints). The
//   white-box OFD tests in lock_test.go cover the handler mechanics directly.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ahmetozer/gosamba/internal/config"
	"github.com/ahmetozer/gosamba/internal/userdb"
)

// TestLock_Baseline_NoRegression verifies that the baseline file-operations
// still work after CommandLock was routed to handleLock instead of returning
// STATUS_NOT_SUPPORTED. A regression here means the dispatch.go change broke
// something in the connection flow.
func TestLock_Baseline_NoRegression(t *testing.T) {
	shareDir := t.TempDir()

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
		RequireSigning: true,
		MaxIOSize:      1 << 20,
	})
	time.Sleep(50 * time.Millisecond)

	// Ensure a file exists in the share for read/write tests.
	existingContent := []byte("lock e2e baseline content\n")
	if err := os.WriteFile(filepath.Join(shareDir, "existing.txt"), existingContent, 0644); err != nil {
		t.Fatal(err)
	}

	// ls — confirm file is visible.
	lsOut := smbcli(t, port, "share", "alice%test123", "ls")
	t.Logf("ls: %s", lsOut)
	if !strings.Contains(lsOut, "existing.txt") {
		t.Errorf("ls: existing.txt not found in:\n%s", lsOut)
	}

	// get — download the file.
	localDir := t.TempDir()
	downloadPath := filepath.Join(localDir, "got.txt")
	getOut := smbcli(t, port, "share", "alice%test123",
		fmt.Sprintf("get existing.txt %s", downloadPath),
	)
	t.Logf("get: %s", getOut)
	got, err := os.ReadFile(downloadPath)
	if err != nil {
		t.Fatalf("downloaded file missing: %v", err)
	}
	if string(got) != string(existingContent) {
		t.Errorf("content mismatch: got %q want %q", got, existingContent)
	}

	// put — upload a new file.
	uploadPath := filepath.Join(localDir, "new.txt")
	if err := os.WriteFile(uploadPath, []byte("new content\n"), 0644); err != nil {
		t.Fatal(err)
	}
	putOut := smbcli(t, port, "share", "alice%test123",
		fmt.Sprintf("lcd %s", localDir),
		"put new.txt new.txt",
	)
	t.Logf("put: %s", putOut)
	if _, err := os.Stat(filepath.Join(shareDir, "new.txt")); err != nil {
		t.Errorf("put: new.txt not on disk: %v", err)
	}

	t.Log("lock e2e baseline passed: no regression after CommandLock dispatch change")
}

// TestLock_SmbclientPosixLockDocumented demonstrates the smbclient lock command
// syntax and documents why it cannot directly exercise the SMB2 LOCK handler.
//
// smbclient syntax: open <filename>  →  returns fnum N
//                   posix            →  enables POSIX extensions (requires server support)
//                   lock N [r|w] <hex-offset> <hex-len>
//                   unlock N <hex-offset> <hex-len>
//                   close N
//
// This test runs the "open" command only (which uses SMB2 CREATE, not LOCK) and
// verifies it succeeds. It does NOT attempt "posix" + "lock" because gosamba
// does not implement POSIX Unix extensions — that would test the wrong layer.
func TestLock_SmbclientOpenClose(t *testing.T) {
	shareDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(shareDir, "lockme.txt"), []byte("hello\n"), 0644); err != nil {
		t.Fatal(err)
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
		RequireSigning: true,
		MaxIOSize:      1 << 20,
	})
	time.Sleep(50 * time.Millisecond)

	// "open" issues CREATE (no SMB2 LOCK). Verify it succeeds and returns a fnum.
	out := smbcli(t, port, "share", "alice%test123", "open lockme.txt")
	t.Logf("open output: %s", out)
	// smbclient prints "open file lockme.txt: for read/write fnum N"
	if !strings.Contains(out, "fnum") {
		t.Errorf("expected 'fnum' in smbclient open output, got: %s", out)
	}
	if strings.Contains(out, "NT_STATUS_NOT_SUPPORTED") {
		t.Error("got NT_STATUS_NOT_SUPPORTED — LOCK dispatch still broken")
	}
	if strings.Contains(out, "NT_STATUS") && !strings.Contains(out, "NT_STATUS_OK") {
		t.Errorf("unexpected NT_STATUS in output: %s", out)
	}
	t.Log("smbclient open/close: no NT_STATUS_NOT_SUPPORTED observed")
}
