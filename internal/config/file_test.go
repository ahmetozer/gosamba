package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTemp(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "gosamba.toml")
	if err := os.WriteFile(p, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestParseFile_Empty(t *testing.T) {
	p := writeTemp(t, ``)
	got, err := ParseFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if got.Server.Listen != nil || len(got.Shares) != 0 || len(got.Users) != 0 {
		t.Errorf("expected zero values, got %+v", got)
	}
}

func TestParseFile_Full(t *testing.T) {
	p := writeTemp(t, `
[server]
listen = ":1445"
netbios = true
encryption = "preferred"

[log]
level = "debug"
format = "json"

[[share]]
name = "media"
path = "/srv/media"
read_only = false

[[share]]
name = "scratch"
path = "/srv/scratch"
guest_ok = true

[[user]]
name = "alice"
nt_hash = "a4f49c406510bdcab6824ee7c30fd852"
system_user = "alice"
allow_shares = ["media"]
`)
	got, err := ParseFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if *got.Server.Listen != ":1445" {
		t.Errorf("listen: %v", got.Server.Listen)
	}
	if !*got.Server.Netbios {
		t.Errorf("netbios should be true")
	}
	if string(*got.Server.Encryption) != "preferred" {
		t.Errorf("encryption: %v", got.Server.Encryption)
	}
	if len(got.Shares) != 2 {
		t.Fatalf("expected 2 shares, got %d", len(got.Shares))
	}
	if got.Shares[0].Name != "media" || got.Shares[1].Name != "scratch" {
		t.Errorf("share names: %+v", got.Shares)
	}
	if !got.Shares[1].GuestOK {
		t.Errorf("scratch should be guest_ok")
	}
	if len(got.Users) != 1 {
		t.Fatalf("expected 1 user")
	}
	u := got.Users[0]
	if u.Name != "alice" || u.SystemUser != "alice" {
		t.Errorf("user: %+v", u)
	}
	want := [16]byte{0xa4, 0xf4, 0x9c, 0x40, 0x65, 0x10, 0xbd, 0xca, 0xb6, 0x82, 0x4e, 0xe7, 0xc3, 0x0f, 0xd8, 0x52}
	if u.NTHash != want {
		t.Errorf("nt_hash: %x", u.NTHash)
	}
}

func TestParseFile_BadHash(t *testing.T) {
	p := writeTemp(t, `
[[user]]
name = "u"
nt_hash = "not-hex"
system_user = "s"
`)
	_, err := ParseFile(p)
	if err == nil {
		t.Fatal("expected error on bad hex")
	}
}

func TestParseFile_PermissionsTooOpen(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "gosamba.toml")
	if err := os.WriteFile(p, []byte(``), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := ParseFile(p)
	if err == nil {
		t.Fatal("expected error: world-readable config")
	}
}
