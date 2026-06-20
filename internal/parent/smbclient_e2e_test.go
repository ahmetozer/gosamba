//go:build smbclient_e2e

package parent

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ahmetozer/gosamba/internal/config"
	"github.com/ahmetozer/gosamba/internal/userdb"
)

// smbcli executes smbclient against 127.0.0.1:<port>/<share> authenticated
// with auth (format "user%pass", or "" for guest with -N). The cmds are joined
// with "; " and passed as the -c argument. Combined stdout+stderr is returned.
// The test is skipped if smbclient is not on PATH; it fails if smbclient exits
// non-zero.
func smbcli(t *testing.T, port int, share, auth string, cmds ...string) string {
	t.Helper()

	if _, err := exec.LookPath("smbclient"); err != nil {
		t.Skip("smbclient not found in PATH")
	}

	args := []string{
		fmt.Sprintf("//127.0.0.1/%s", share),
		"-p", fmt.Sprintf("%d", port),
	}
	if auth == "" {
		args = append(args, "-N")
	} else {
		args = append(args, "-U", auth)
	}
	args = append(args, "-c", strings.Join(cmds, "; "))

	cmd := exec.Command("smbclient", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("smbclient %v: %v\noutput:\n%s", args, err, out)
	}
	return string(out)
}

// smbcliErr is like smbcli but does not call t.Fatal on a non-zero exit.
// It returns combined stdout+stderr and the error (nil on exit 0).
// The test is still skipped if smbclient is absent.
func smbcliErr(t *testing.T, port int, share, auth string, cmds ...string) (string, error) {
	t.Helper()

	if _, err := exec.LookPath("smbclient"); err != nil {
		t.Skip("smbclient not found in PATH")
	}

	args := []string{
		fmt.Sprintf("//127.0.0.1/%s", share),
		"-p", fmt.Sprintf("%d", port),
	}
	if auth == "" {
		args = append(args, "-N")
	} else {
		args = append(args, "-U", auth)
	}
	args = append(args, "-c", strings.Join(cmds, "; "))

	cmd := exec.Command("smbclient", args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestSmbclient_Baseline(t *testing.T) {
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

	// Give the server a moment to start accepting.
	time.Sleep(50 * time.Millisecond)

	// --- put: upload a local file to the share ---
	localDir := t.TempDir()
	uploadContent := []byte("smbclient e2e baseline test content\n")
	uploadPath := filepath.Join(localDir, "upload.txt")
	if err := os.WriteFile(uploadPath, uploadContent, 0644); err != nil {
		t.Fatal(err)
	}

	putOut := smbcli(t, port, "share", "alice%test123",
		fmt.Sprintf("lcd %s", localDir),
		"put upload.txt upload.txt",
	)
	t.Logf("put output:\n%s", putOut)
	if !strings.Contains(putOut, "upload.txt") {
		t.Errorf("put: expected filename in output, got: %s", putOut)
	}

	// --- ls: confirm the file appears in the share ---
	lsOut := smbcli(t, port, "share", "alice%test123", "ls")
	t.Logf("ls output:\n%s", lsOut)
	if !strings.Contains(lsOut, "upload.txt") {
		t.Errorf("ls: upload.txt not found in listing:\n%s", lsOut)
	}

	// --- get: download the file and verify byte-identical content ---
	downloadPath := filepath.Join(localDir, "download.txt")
	getOut := smbcli(t, port, "share", "alice%test123",
		fmt.Sprintf("get upload.txt %s", downloadPath),
	)
	t.Logf("get output:\n%s", getOut)

	gotBytes, err := os.ReadFile(downloadPath)
	if err != nil {
		t.Fatalf("get: downloaded file not found: %v", err)
	}
	if !bytes.Equal(gotBytes, uploadContent) {
		t.Errorf("get: content mismatch: got %q, want %q", gotBytes, uploadContent)
	}

	// --- mkdir: create a directory ---
	mkdirOut := smbcli(t, port, "share", "alice%test123", "mkdir testdir")
	t.Logf("mkdir output:\n%s", mkdirOut)
	if st, err := os.Stat(filepath.Join(shareDir, "testdir")); err != nil || !st.IsDir() {
		t.Errorf("mkdir: testdir not created on disk: err=%v", err)
	}

	// --- rename: rename the uploaded file ---
	renameOut := smbcli(t, port, "share", "alice%test123", "rename upload.txt renamed.txt")
	t.Logf("rename output:\n%s", renameOut)
	if _, err := os.Stat(filepath.Join(shareDir, "upload.txt")); err == nil {
		t.Error("rename: upload.txt should be gone after rename")
	}
	if _, err := os.Stat(filepath.Join(shareDir, "renamed.txt")); err != nil {
		t.Errorf("rename: renamed.txt not present on disk: %v", err)
	}

	// --- del: delete the renamed file ---
	delOut := smbcli(t, port, "share", "alice%test123", "del renamed.txt")
	t.Logf("del output:\n%s", delOut)
	if _, err := os.Stat(filepath.Join(shareDir, "renamed.txt")); err == nil {
		t.Error("del: renamed.txt should be gone after del")
	}

	// --- rmdir: remove the directory ---
	rmdirOut := smbcli(t, port, "share", "alice%test123", "rmdir testdir")
	t.Logf("rmdir output:\n%s", rmdirOut)
	if _, err := os.Stat(filepath.Join(shareDir, "testdir")); err == nil {
		t.Error("rmdir: testdir should be gone after rmdir")
	}

	t.Log("smbclient baseline E2E succeeded")
}
