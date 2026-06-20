package config

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func currentUser(t *testing.T) (name string, uid, gid int) {
	t.Helper()
	u, err := user.Current()
	if err != nil {
		t.Skip("user.Current unavailable")
	}
	ui, err := strconv.Atoi(u.Uid)
	if err != nil {
		t.Skip("non-numeric uid")
	}
	gi, err := strconv.Atoi(u.Gid)
	if err != nil {
		t.Skip("non-numeric gid")
	}
	return u.Username, ui, gi
}

func TestValidate_Happy(t *testing.T) {
	dir := t.TempDir()
	uname, _, _ := currentUser(t)

	cfg := Defaults()
	cfg.Server.Listen = ":0"
	cfg.Server.StateDir = filepath.Join(dir, "state")
	cfg.Shares = []ShareConfig{{Name: "a", Path: dir}}
	cfg.Users = []UserConfig{{
		Name: "u", NTHash: [16]byte{1}, SystemUser: uname, AllowShares: []string{"*"},
	}}
	if err := Validate(&cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Users[0].SystemUID < 0 {
		t.Errorf("uid should be filled in")
	}
}

func TestValidate_ShareMissing(t *testing.T) {
	cfg := Defaults()
	cfg.Shares = []ShareConfig{{Name: "x", Path: "/nonexistent/gosamba/test"}}
	err := Validate(&cfg)
	if err == nil || !strings.Contains(err.Error(), "share") {
		t.Fatalf("expected share-missing error, got %v", err)
	}
}

func TestValidate_ShareNotDir(t *testing.T) {
	tmp, _ := os.CreateTemp("", "gosambatest")
	defer os.Remove(tmp.Name())
	tmp.Close()
	cfg := Defaults()
	cfg.Shares = []ShareConfig{{Name: "x", Path: tmp.Name()}}
	err := Validate(&cfg)
	if err == nil || !strings.Contains(err.Error(), "directory") {
		t.Fatalf("expected not-a-directory error, got %v", err)
	}
}

func TestValidate_DuplicateShareName(t *testing.T) {
	dir := t.TempDir()
	cfg := Defaults()
	cfg.Shares = []ShareConfig{{Name: "x", Path: dir}, {Name: "x", Path: dir}}
	if err := Validate(&cfg); err == nil {
		t.Fatal("expected duplicate-share error")
	}
}

func TestValidate_UnknownSystemUser(t *testing.T) {
	dir := t.TempDir()
	cfg := Defaults()
	cfg.Shares = []ShareConfig{{Name: "x", Path: dir}}
	cfg.Users = []UserConfig{{Name: "u", NTHash: [16]byte{1}, SystemUser: "nosuchuser_gosamba_test_xyz"}}
	if err := Validate(&cfg); err == nil {
		t.Fatal("expected unknown-system-user error")
	}
}

func TestValidate_BadEncryption(t *testing.T) {
	cfg := Defaults()
	cfg.Server.Encryption = "wibble"
	cfg.Shares = []ShareConfig{{Name: "x", Path: t.TempDir()}}
	if err := Validate(&cfg); err == nil {
		t.Fatal("expected bad-encryption error")
	}
}
