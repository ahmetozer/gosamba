//go:build smbclient_e2e

package parent

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ahmetozer/gosamba/internal/config"
	"github.com/ahmetozer/gosamba/internal/userdb"
)

// TestSmbclient_LargeFile tests a >=64 MiB put+get round-trip via smbclient.
// This exercises multi-credit I/O: smbclient splits the transfer into multiple
// large WRITE/READ ops, each consuming CreditCharge > 1. The server must grant
// a growing credit window or the transfer will stall / fail.
func TestSmbclient_LargeFile(t *testing.T) {
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
		MaxIOSize:      8 << 20, // 8 MiB
	})

	// Give the server a moment to start accepting.
	time.Sleep(50 * time.Millisecond)

	const fileSize = 64 << 20 // 64 MiB
	localDir := t.TempDir()
	uploadPath := filepath.Join(localDir, "large64.bin")

	// Generate 64 MiB of random data.
	data := make([]byte, fileSize)
	if _, err := rand.Read(data); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	if err := os.WriteFile(uploadPath, data, 0644); err != nil {
		t.Fatalf("WriteFile local: %v", err)
	}

	// Upload.
	putOut := smbcli(t, port, "share", "alice%test123",
		fmt.Sprintf("lcd %s", localDir),
		"put large64.bin large64.bin",
	)
	t.Logf("put output:\n%s", putOut)

	// Verify on disk.
	diskBytes, err := os.ReadFile(filepath.Join(shareDir, "large64.bin"))
	if err != nil {
		t.Fatalf("on-disk read: %v", err)
	}
	if len(diskBytes) != fileSize {
		t.Fatalf("on-disk size: got %d, want %d", len(diskBytes), fileSize)
	}
	if !bytes.Equal(diskBytes, data) {
		t.Error("on-disk content mismatch after put")
	}

	// Download back to a different name and verify byte-identical.
	downloadPath := filepath.Join(localDir, "large64_got.bin")
	getOut := smbcli(t, port, "share", "alice%test123",
		fmt.Sprintf("get large64.bin %s", downloadPath),
	)
	t.Logf("get output:\n%s", getOut)

	gotBytes, err := os.ReadFile(downloadPath)
	if err != nil {
		t.Fatalf("get: downloaded file not found: %v", err)
	}
	if len(gotBytes) != fileSize {
		t.Fatalf("get: got %d bytes, want %d", len(gotBytes), fileSize)
	}
	if !bytes.Equal(gotBytes, data) {
		t.Error("get: content mismatch after large file round-trip")
	}

	t.Logf("smbclient large-file (64 MiB) put+get round-trip succeeded")
}
