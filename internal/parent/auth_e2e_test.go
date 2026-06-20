//go:build smbclient_e2e

package parent

import (
	"strings"
	"testing"
	"time"

	"github.com/ahmetozer/gosamba/internal/config"
	"github.com/ahmetozer/gosamba/internal/userdb"
)

func TestE2E_AuthSucceeds(t *testing.T) {
	users := []config.UserConfig{{
		Name:        "alice",
		NTHash:      userdb.NTHash("test123"),
		SystemUser:  "root",
		SystemUID:   0,
		SystemGID:   0,
		AllowShares: []string{"*"},
	}}
	shares := []config.ShareConfig{{Name: "share", Path: t.TempDir()}}

	_, port := startTestServer(t, users, shares, ConnOptions{
		RequireEncryption: false,
		RequireSigning:    true,
		MaxIOSize:         1 << 20,
	})

	time.Sleep(50 * time.Millisecond)

	out := smbcli(t, port, "share", "alice%test123", "ls")
	t.Logf("auth output:\n%s", out)
	t.Log("auth succeeded")
}

func TestE2E_AuthFails_WrongPassword(t *testing.T) {
	users := []config.UserConfig{{
		Name:        "alice",
		NTHash:      userdb.NTHash("test123"),
		SystemUser:  "root",
		SystemUID:   0,
		SystemGID:   0,
		AllowShares: []string{"*"},
	}}
	shares := []config.ShareConfig{{Name: "share", Path: t.TempDir()}}

	_, port := startTestServer(t, users, shares, ConnOptions{
		RequireEncryption: false,
		RequireSigning:    true,
		MaxIOSize:         1 << 20,
	})

	time.Sleep(50 * time.Millisecond)

	out, err := smbcliErr(t, port, "share", "alice%wrongpassword", "ls")
	t.Logf("auth-fail output:\n%s", out)
	if err == nil {
		t.Fatal("expected smbclient to fail with wrong password, but it succeeded")
	}
	combined := strings.ToUpper(out)
	if !strings.Contains(combined, "NT_STATUS_LOGON_FAILURE") {
		t.Errorf("expected NT_STATUS_LOGON_FAILURE in output, got: %s", out)
	}
	t.Log("auth-failure correctly rejected")
}

func TestE2E_AuthFails_GuestRejected(t *testing.T) {
	users := []config.UserConfig{{
		Name:        "alice",
		NTHash:      userdb.NTHash("test123"),
		SystemUser:  "root",
		SystemUID:   0,
		SystemGID:   0,
		AllowShares: []string{"*"},
	}}
	shares := []config.ShareConfig{{Name: "share", Path: t.TempDir()}}

	_, port := startTestServer(t, users, shares, ConnOptions{
		RequireEncryption: false,
		RequireSigning:    true,
		MaxIOSize:         1 << 20,
	})

	time.Sleep(50 * time.Millisecond)

	// Guest (-N) should be rejected because no guest user is configured.
	out, err := smbcliErr(t, port, "share", "", "ls")
	t.Logf("guest output:\n%s", out)
	if err == nil {
		t.Fatal("expected guest login to fail, but it succeeded")
	}
	t.Log("guest access correctly rejected")
}
