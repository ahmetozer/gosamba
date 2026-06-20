//go:build smbclient_e2e

package parent

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ahmetozer/gosamba/internal/config"
	"github.com/ahmetozer/gosamba/internal/userdb"
)

func TestE2E_ReadOnly_BrowseAndRead(t *testing.T) {
	// Set up a share with a known directory tree.
	shareDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(shareDir, "hello.txt"), []byte("hello world\n"), 0644); err != nil {
		t.Fatal(err)
	}
	subdir := filepath.Join(shareDir, "subdir")
	if err := os.Mkdir(subdir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subdir, "nested.bin"), []byte{0xDE, 0xAD, 0xBE, 0xEF}, 0644); err != nil {
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
	shares := []config.ShareConfig{{
		Name: "share",
		Path: shareDir,
	}}

	_, port := startTestServer(t, users, shares, ConnOptions{
		RequireEncryption: false,
		RequireSigning:    true,
		MaxIOSize:         1 << 20,
	})

	time.Sleep(50 * time.Millisecond)

	localDir := t.TempDir()

	// --- ls: root listing must include hello.txt and subdir ---
	lsOut := smbcli(t, port, "share", "alice%test123", "ls")
	t.Logf("ls output:\n%s", lsOut)
	if !strings.Contains(lsOut, "hello.txt") {
		t.Errorf("ls: hello.txt not found:\n%s", lsOut)
	}
	if !strings.Contains(lsOut, "subdir") {
		t.Errorf("ls: subdir not found:\n%s", lsOut)
	}

	// --- get hello.txt and verify content ---
	helloLocal := filepath.Join(localDir, "hello.txt")
	getOut := smbcli(t, port, "share", "alice%test123",
		fmt.Sprintf("get hello.txt %s", helloLocal),
	)
	t.Logf("get hello.txt output:\n%s", getOut)

	helloBytes, err := os.ReadFile(helloLocal)
	if err != nil {
		t.Fatalf("hello.txt not downloaded: %v", err)
	}
	if string(helloBytes) != "hello world\n" {
		t.Errorf("hello.txt = %q", helloBytes)
	}

	// --- ls subdir: must include nested.bin ---
	// Use "cd subdir; ls" because "ls subdir" lists the dir entry itself,
	// not its contents.
	lsSubOut := smbcli(t, port, "share", "alice%test123", "cd subdir", "ls")
	t.Logf("ls subdir output:\n%s", lsSubOut)
	if !strings.Contains(lsSubOut, "nested.bin") {
		t.Errorf("ls subdir: nested.bin not found:\n%s", lsSubOut)
	}

	// --- get nested.bin and verify binary content ---
	nestedLocal := filepath.Join(localDir, "nested.bin")
	getNestedOut := smbcli(t, port, "share", "alice%test123",
		fmt.Sprintf("get subdir/nested.bin %s", nestedLocal),
	)
	t.Logf("get nested.bin output:\n%s", getNestedOut)

	nestedBytes, err := os.ReadFile(nestedLocal)
	if err != nil {
		t.Fatalf("nested.bin not downloaded: %v", err)
	}
	wantNested := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	if !bytes.Equal(nestedBytes, wantNested) {
		t.Errorf("nested.bin = %x, want %x", nestedBytes, wantNested)
	}

	t.Log("read-only browse and read E2E succeeded")
}

// TestE2E_ReadOnly_EnforceAccessDenied verifies that a share configured with
// ReadOnly:true rejects write operations (put/del/rename/mkdir) with
// NT_STATUS_ACCESS_DENIED while still allowing read operations (ls/get).
func TestE2E_ReadOnly_EnforceAccessDenied(t *testing.T) {
	shareDir := t.TempDir()
	// Pre-populate a file that can be read and (must not be) deleted or renamed.
	if err := os.WriteFile(filepath.Join(shareDir, "existing.txt"), []byte("read-only content\n"), 0644); err != nil {
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
	shares := []config.ShareConfig{{
		Name:     "roshare",
		Path:     shareDir,
		ReadOnly: true,
	}}

	_, port := startTestServer(t, users, shares, ConnOptions{
		RequireEncryption: false,
		RequireSigning:    true,
		MaxIOSize:         1 << 20,
	})
	time.Sleep(50 * time.Millisecond)

	localDir := t.TempDir()
	uploadPath := filepath.Join(localDir, "upload.txt")
	if err := os.WriteFile(uploadPath, []byte("should not land\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// --- ls must succeed ---
	lsOut := smbcli(t, port, "roshare", "alice%test123", "ls")
	t.Logf("ls output:\n%s", lsOut)
	if !strings.Contains(lsOut, "existing.txt") {
		t.Errorf("ls: existing.txt not found in read-only share listing:\n%s", lsOut)
	}

	// --- get must succeed ---
	downloadPath := filepath.Join(localDir, "downloaded.txt")
	getOut := smbcli(t, port, "roshare", "alice%test123",
		fmt.Sprintf("get existing.txt %s", downloadPath),
	)
	t.Logf("get output:\n%s", getOut)
	got, err := os.ReadFile(downloadPath)
	if err != nil {
		t.Fatalf("get: file not downloaded from read-only share: %v", err)
	}
	if string(got) != "read-only content\n" {
		t.Errorf("get: content mismatch: got %q", got)
	}

	// --- put must be DENIED ---
	putOut, putErr := smbcliErr(t, port, "roshare", "alice%test123",
		fmt.Sprintf("lcd %s", localDir),
		"put upload.txt upload.txt",
	)
	t.Logf("put output:\n%s", putOut)
	if putErr == nil {
		t.Error("put: expected failure on read-only share but smbclient exited 0")
	}
	if !strings.Contains(strings.ToUpper(putOut), "ACCESS_DENIED") &&
		!strings.Contains(strings.ToUpper(putOut), "NT_STATUS_ACCESS_DENIED") {
		t.Errorf("put: expected ACCESS_DENIED in output, got:\n%s", putOut)
	}
	if _, statErr := os.Stat(filepath.Join(shareDir, "upload.txt")); statErr == nil {
		t.Error("put: upload.txt must not appear on disk after denied write")
	}

	// --- del must be DENIED ---
	// Note: smbclient may exit 0 for del even when the server rejects it;
	// check the output for ACCESS_DENIED and verify the file still exists.
	delOut, _ := smbcliErr(t, port, "roshare", "alice%test123", "del existing.txt")
	t.Logf("del output:\n%s", delOut)
	if !strings.Contains(strings.ToUpper(delOut), "ACCESS_DENIED") &&
		!strings.Contains(strings.ToUpper(delOut), "NT_STATUS_ACCESS_DENIED") {
		t.Errorf("del: expected ACCESS_DENIED in output, got:\n%s", delOut)
	}
	if _, statErr := os.Stat(filepath.Join(shareDir, "existing.txt")); statErr != nil {
		t.Error("del: existing.txt was removed despite read-only share")
	}

	// --- rename must be DENIED ---
	renOut, renErr := smbcliErr(t, port, "roshare", "alice%test123", "rename existing.txt renamed.txt")
	t.Logf("rename output:\n%s", renOut)
	if renErr == nil {
		t.Error("rename: expected failure on read-only share but smbclient exited 0")
	}
	if !strings.Contains(strings.ToUpper(renOut), "ACCESS_DENIED") &&
		!strings.Contains(strings.ToUpper(renOut), "NT_STATUS_ACCESS_DENIED") {
		t.Errorf("rename: expected ACCESS_DENIED in output, got:\n%s", renOut)
	}
	if _, statErr := os.Stat(filepath.Join(shareDir, "existing.txt")); statErr != nil {
		t.Error("rename: existing.txt was moved despite read-only share")
	}

	// --- mkdir must be DENIED ---
	// Note: smbclient may exit 0 for mkdir even when the server rejects it;
	// check the output for ACCESS_DENIED and verify no directory was created.
	mkdirOut, _ := smbcliErr(t, port, "roshare", "alice%test123", "mkdir newdir")
	t.Logf("mkdir output:\n%s", mkdirOut)
	if !strings.Contains(strings.ToUpper(mkdirOut), "ACCESS_DENIED") &&
		!strings.Contains(strings.ToUpper(mkdirOut), "NT_STATUS_ACCESS_DENIED") {
		t.Errorf("mkdir: expected ACCESS_DENIED in output, got:\n%s", mkdirOut)
	}
	if _, statErr := os.Stat(filepath.Join(shareDir, "newdir")); statErr == nil {
		t.Error("mkdir: newdir was created despite read-only share")
	}

	t.Log("read-only enforcement E2E succeeded")
}
