//go:build smbclient_e2e

package parent

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ahmetozer/gosamba/internal/config"
	"github.com/ahmetozer/gosamba/internal/userdb"
)

// TestE2E_Durable_NoRegression confirms that with the durable-handle table
// enabled (the test server always provides one), a real smbclient — which
// requests durable + lease create contexts on its opens — completes the
// baseline put/get/del cycle without error. True durable reconnect-reclaim
// (drop the TCP conn, reconnect, reclaim the handle) cannot be driven by
// smbclient; it is covered white-box in TestHandleCreate_DurableGrantAndReconnect.
func TestE2E_Durable_NoRegression(t *testing.T) {
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

	// Explicit short DurableTimeout to exercise the clamp path.
	_, port := startTestServer(t, users, shares, ConnOptions{
		RequireSigning: true, MaxIOSize: 1 << 20,
		Durable:        NewDurableTable(),
		DurableTimeout: 30 * time.Second,
	})

	time.Sleep(50 * time.Millisecond)

	localDir := t.TempDir()
	want := []byte("durable path payload\n")
	if err := os.WriteFile(filepath.Join(localDir, "d.txt"), want, 0644); err != nil {
		t.Fatal(err)
	}

	out := smbcli(t, port, "share", "alice%test123",
		fmt.Sprintf("lcd %s", localDir),
		"put d.txt d.txt",
		"get d.txt back.txt",
		"del d.txt",
	)
	t.Logf("durable e2e output:\n%s", out)

	got, err := os.ReadFile(filepath.Join(localDir, "back.txt"))
	if err != nil || !bytes.Equal(got, want) {
		t.Errorf("round-trip: %q err=%v", got, err)
	}
	if _, err := os.Stat(filepath.Join(shareDir, "d.txt")); !os.IsNotExist(err) {
		t.Errorf("file not deleted: err=%v", err)
	}
}
