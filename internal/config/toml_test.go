package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTOMLTemp(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "test.toml")
	if err := os.WriteFile(p, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDecodeTOML_Full(t *testing.T) {
	p := writeTOMLTemp(t, `
# top-level comment

[server]
listen = ":1445"
netbios = true
mdns = false
encryption = "preferred"
signing = "required"
durable_timeout = "30s"
state_dir = "/tmp/gos"
per_user_privdrop = false

[log]
level = "debug"
format = "json"

[[share]]
name = "media"
path = "/srv/media"
read_only = true
guest_ok = false

[[share]]
name = "scratch"
path = "/srv/scratch"
read_only = false
guest_ok = true

[[user]]
name = "alice"
nt_hash = "a4f49c406510bdcab6824ee7c30fd852"
system_user = "alice"
allow_shares = ["media", "scratch"]

[[user]]
name = "guest"
system_user = "nobody"
allow_shares = []
`)
	var f File
	if err := decodeTOMLFile(p, &f); err != nil {
		t.Fatal(err)
	}

	// Server
	if f.Server.Listen == nil || *f.Server.Listen != ":1445" {
		t.Errorf("listen: %v", f.Server.Listen)
	}
	if f.Server.Netbios == nil || !*f.Server.Netbios {
		t.Errorf("netbios should be true")
	}
	if f.Server.MDNS == nil || *f.Server.MDNS {
		t.Errorf("mdns should be false")
	}
	if f.Server.Encryption == nil || string(*f.Server.Encryption) != "preferred" {
		t.Errorf("encryption: %v", f.Server.Encryption)
	}
	if f.Server.Signing == nil || string(*f.Server.Signing) != "required" {
		t.Errorf("signing: %v", f.Server.Signing)
	}
	if f.Server.DurableTimeout == nil || *f.Server.DurableTimeout != "30s" {
		t.Errorf("durable_timeout: %v", f.Server.DurableTimeout)
	}
	if f.Server.StateDir == nil || *f.Server.StateDir != "/tmp/gos" {
		t.Errorf("state_dir: %v", f.Server.StateDir)
	}
	if f.Server.PerUserPrivdrop == nil || *f.Server.PerUserPrivdrop {
		t.Errorf("per_user_privdrop should be false")
	}

	// Log
	if f.Log.Level == nil || *f.Log.Level != "debug" {
		t.Errorf("log level: %v", f.Log.Level)
	}
	if f.Log.Format == nil || *f.Log.Format != "json" {
		t.Errorf("log format: %v", f.Log.Format)
	}

	// Shares
	if len(f.Shares) != 2 {
		t.Fatalf("expected 2 shares, got %d", len(f.Shares))
	}
	if f.Shares[0].Name != "media" || f.Shares[0].Path != "/srv/media" {
		t.Errorf("share[0]: %+v", f.Shares[0])
	}
	if !f.Shares[0].ReadOnly || f.Shares[0].GuestOK {
		t.Errorf("share[0] flags: %+v", f.Shares[0])
	}
	if f.Shares[1].Name != "scratch" || !f.Shares[1].GuestOK {
		t.Errorf("share[1]: %+v", f.Shares[1])
	}

	// Users
	if len(f.Users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(f.Users))
	}
	u0 := f.Users[0]
	if u0.Name != "alice" || u0.SystemUser != "alice" {
		t.Errorf("user[0]: %+v", u0)
	}
	if u0.NTHashHex != "a4f49c406510bdcab6824ee7c30fd852" {
		t.Errorf("nt_hash: %s", u0.NTHashHex)
	}
	if len(u0.AllowShares) != 2 || u0.AllowShares[0] != "media" || u0.AllowShares[1] != "scratch" {
		t.Errorf("allow_shares: %v", u0.AllowShares)
	}
	u1 := f.Users[1]
	if u1.Name != "guest" || u1.SystemUser != "nobody" {
		t.Errorf("user[1]: %+v", u1)
	}
	if len(u1.AllowShares) != 0 {
		t.Errorf("user[1] allow_shares should be empty: %v", u1.AllowShares)
	}
}

func TestDecodeTOML_Comments(t *testing.T) {
	p := writeTOMLTemp(t, `
# This is a comment
[server]
listen = ":445" # inline comment
# another comment
netbios = false
`)
	var f File
	if err := decodeTOMLFile(p, &f); err != nil {
		t.Fatal(err)
	}
	if f.Server.Listen == nil || *f.Server.Listen != ":445" {
		t.Errorf("listen: %v", f.Server.Listen)
	}
	if f.Server.Netbios == nil || *f.Server.Netbios {
		t.Errorf("netbios should be false")
	}
}

func TestDecodeTOML_StringEscapes(t *testing.T) {
	p := writeTOMLTemp(t, `[server]
listen = "hello\"world\\"
`)
	var f File
	if err := decodeTOMLFile(p, &f); err != nil {
		t.Fatal(err)
	}
	want := `hello"world\`
	if f.Server.Listen == nil || *f.Server.Listen != want {
		t.Errorf("got %q want %q", *f.Server.Listen, want)
	}
}

func TestDecodeTOML_Bools(t *testing.T) {
	p := writeTOMLTemp(t, `[server]
netbios = true
mdns = false
`)
	var f File
	if err := decodeTOMLFile(p, &f); err != nil {
		t.Fatal(err)
	}
	if f.Server.Netbios == nil || !*f.Server.Netbios {
		t.Errorf("netbios should be true")
	}
	if f.Server.MDNS == nil || *f.Server.MDNS {
		t.Errorf("mdns should be false")
	}
}

func TestDecodeTOML_Empty(t *testing.T) {
	p := writeTOMLTemp(t, ``)
	var f File
	if err := decodeTOMLFile(p, &f); err != nil {
		t.Fatal(err)
	}
	if f.Server.Listen != nil || len(f.Shares) != 0 || len(f.Users) != 0 {
		t.Errorf("expected zero value, got %+v", f)
	}
}

func TestDecodeTOML_UnterminatedString(t *testing.T) {
	p := writeTOMLTemp(t, `[server]
listen = "not closed
`)
	var f File
	err := decodeTOMLFile(p, &f)
	if err == nil {
		t.Fatal("expected error on unterminated string")
	}
}

func TestDecodeTOML_JunkLine(t *testing.T) {
	p := writeTOMLTemp(t, `[server]
this is not valid toml
`)
	var f File
	err := decodeTOMLFile(p, &f)
	if err == nil {
		t.Fatal("expected error on junk line")
	}
}

func TestDecodeTOML_UnknownKeys(t *testing.T) {
	// Unknown keys must be silently ignored
	p := writeTOMLTemp(t, `[server]
listen = ":445"
unknown_future_key = "whatever"
`)
	var f File
	if err := decodeTOMLFile(p, &f); err != nil {
		t.Fatalf("unknown key should be ignored, got: %v", err)
	}
	if f.Server.Listen == nil || *f.Server.Listen != ":445" {
		t.Errorf("listen: %v", f.Server.Listen)
	}
}

func TestDecodeTOML_HashInString(t *testing.T) {
	// '#' inside a quoted string must NOT be treated as a comment
	p := writeTOMLTemp(t, `[server]
listen = "host#port"
`)
	var f File
	if err := decodeTOMLFile(p, &f); err != nil {
		t.Fatal(err)
	}
	if f.Server.Listen == nil || *f.Server.Listen != "host#port" {
		t.Errorf("listen: %v", f.Server.Listen)
	}
}

func TestDecodeTOML_EmptyKeyErrors(t *testing.T) {
	p := writeTOMLTemp(t, "[server]\n= \"x\"\n")
	var f File
	if err := decodeTOMLFile(p, &f); err == nil {
		t.Fatal("expected error for empty key before '=', got nil")
	}
}
