package config

import (
	"strings"
	"testing"
)

// validatableConfig returns a Config that passes Validate, so each test below
// can break exactly one thing and be sure that is what the error is about.
func validatableConfig(t *testing.T) Config {
	t.Helper()
	cfg := Defaults()
	cfg.Server.Listen = ":0"
	cfg.Shares = []ShareConfig{{Name: "media", Path: t.TempDir()}}
	cfg.Users = []UserConfig{{Name: "alice", NTHash: [16]byte{1}, AllowShares: []string{"*"}}}
	return cfg
}

// --- credential must be real (all-zero NT hash is the absence of one) ---

// A [[user]] with no nt_hash used to sail through: file.go skips the hex
// decode, NTHash stays [16]byte{}, and NTLMv2 then verifies for anyone who
// computes the response against 16 zero bytes.
func TestValidate_RejectsUserWithNoNTHash(t *testing.T) {
	p := writeTemp(t, `
[[user]]
name = "alice"
system_user = ""
`)
	file, err := ParseFile(p)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := Merge(CLI{}, file)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Shares = []ShareConfig{{Name: "media", Path: t.TempDir()}}

	err = Validate(&cfg)
	if err == nil {
		t.Fatal("a user with no nt_hash must be rejected: an all-zero NT hash authenticates anyone")
	}
	if !strings.Contains(err.Error(), "alice") || !strings.Contains(err.Error(), "credential") {
		t.Errorf("error should name the user and the missing credential, got: %v", err)
	}
}

// The same hole, reached by pasting zeros rather than by omission.
func TestValidate_RejectsExplicitlyZeroNTHash(t *testing.T) {
	p := writeTemp(t, `
[[user]]
name = "alice"
nt_hash = "00000000000000000000000000000000"
`)
	file, err := ParseFile(p)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := Merge(CLI{}, file)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Shares = []ShareConfig{{Name: "media", Path: t.TempDir()}}

	if err := Validate(&cfg); err == nil {
		t.Fatal("an all-zero nt_hash must be rejected")
	}
}

// Guard rail for the fix above: -u derives the hash from the password, so the
// CLI path must keep validating. A zero-hash check that also rejected this
// would break every -u deployment.
func TestValidate_CLIUserWithPasswordStillValidates(t *testing.T) {
	cli, err := ParseCLI([]string{"-u", "alice:secret"})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := Merge(cli, File{})
	if err != nil {
		t.Fatal(err)
	}
	cfg.Shares = []ShareConfig{{Name: "media", Path: t.TempDir()}}

	if err := Validate(&cfg); err != nil {
		t.Fatalf("-u user:password must remain valid: %v", err)
	}
	var zero [16]byte
	if cfg.Users[0].NTHash == zero {
		t.Error("CLI password should have produced a real hash")
	}
}

// "-u alice:" is a typo, not a credential: it would hash the empty string into
// a valid, universally computable NT hash.
func TestParseCLI_RejectsEmptyPassword(t *testing.T) {
	if _, err := ParseCLI([]string{"-u", "alice:"}); err == nil {
		t.Fatal("expected an error for an empty password")
	}
	if _, err := ParseCLI([]string{"-u", "alice::1000"}); err == nil {
		t.Fatal("expected an error for an empty password in the 3-field form")
	}
}

// --- allow_shares must fail closed ---

// Absent allow_shares keeps meaning "every share" — configs written before the
// key existed must keep working.
func TestMerge_AllowSharesAbsentGrantsAllShares(t *testing.T) {
	p := writeTemp(t, `
[[user]]
name = "alice"
nt_hash = "a4f49c406510bdcab6824ee7c30fd852"
`)
	file, err := ParseFile(p)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := Merge(CLI{}, file)
	if err != nil {
		t.Fatal(err)
	}
	got := cfg.Users[0].AllowShares
	if len(got) != 1 || got[0] != "*" {
		t.Errorf("absent allow_shares should grant every share, got %v", got)
	}
}

// An explicit empty list is a revocation. It used to be indistinguishable from
// "absent" (both hit len(shares) == 0) and so silently granted every share --
// shareAllowed in parent/dispatch.go treats "*" as all shares.
func TestMerge_AllowSharesExplicitlyEmptyGrantsNothing(t *testing.T) {
	p := writeTemp(t, `
[[user]]
name = "alice"
nt_hash = "a4f49c406510bdcab6824ee7c30fd852"
allow_shares = []
`)
	file, err := ParseFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if file.Users[0].AllowShares == nil {
		t.Fatal("parseStringArray must return a non-nil slice for []; the nil/empty distinction is the signal Merge reads")
	}
	cfg, err := Merge(CLI{}, file)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Users[0].AllowShares; len(got) != 0 {
		t.Errorf("allow_shares = [] must grant nothing, got %v", got)
	}
}

// A misspelled key inside [[user]] leaves allow_shares unset, which reads as
// "every share". That is a fail-open an operator cannot see, so unknown keys
// in [[user]] are an error even though they are ignored everywhere else.
func TestDecodeTOML_RejectsUnknownUserKey(t *testing.T) {
	p := writeTemp(t, `
[[user]]
name = "alice"
nt_hash = "a4f49c406510bdcab6824ee7c30fd852"
allow_share = ["media"]
`)
	_, err := ParseFile(p)
	if err == nil {
		t.Fatal("a misspelled key in [[user]] must be rejected, not silently ignored")
	}
	if !strings.Contains(err.Error(), "allow_share") {
		t.Errorf("error should name the offending key, got: %v", err)
	}
}

// Unknown keys outside [[user]] stay ignored: only the security-relevant table
// is strict.
func TestDecodeTOML_IgnoresUnknownKeysOutsideUserTable(t *testing.T) {
	p := writeTemp(t, `
[server]
listen = ":1445"
future_option = "whatever"

[[share]]
name = "media"
path = "/srv/media"
unknown_share_key = true
`)
	if _, err := ParseFile(p); err != nil {
		t.Fatalf("unknown keys outside [[user]] should still be ignored: %v", err)
	}
}

// --- duplicate names ---

// TREE_CONNECT matches share names with strings.EqualFold, so "Work" and
// "work" are one share to a client: the second entry was unreachable but
// accepted without complaint.
func TestValidate_RejectsDuplicateShareNamesCaseInsensitively(t *testing.T) {
	dir := t.TempDir()
	cfg := validatableConfig(t)
	cfg.Shares = []ShareConfig{{Name: "Work", Path: dir}, {Name: "work", Path: dir}}

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("shares differing only in case must be rejected: only one is ever reachable")
	}
	if !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("expected a duplicate-name error, got: %v", err)
	}
}

// SESSION_SETUP resolves account names with strings.EqualFold and takes the
// first match, so a second user with the same name never authenticates -- its
// password and allow_shares silently do nothing.
func TestValidate_RejectsDuplicateUserNames(t *testing.T) {
	for _, names := range [][2]string{
		{"alice", "alice"},
		{"Alice", "alice"},
	} {
		cfg := validatableConfig(t)
		cfg.Users = []UserConfig{
			{Name: names[0], NTHash: [16]byte{1}, AllowShares: []string{"*"}},
			{Name: names[1], NTHash: [16]byte{2}, AllowShares: []string{"*"}},
		}
		err := Validate(&cfg)
		if err == nil {
			t.Fatalf("users %q and %q must be rejected as duplicates", names[0], names[1])
		}
		if !strings.Contains(err.Error(), "duplicate") {
			t.Errorf("%v: expected a duplicate-name error, got: %v", names, err)
		}
	}
}

// --- unimplemented knobs ---

// Nothing binds :139. Accepting --netbios would tell the operator legacy
// clients are served when they are not.
func TestValidate_RejectsNetbios(t *testing.T) {
	cfg := validatableConfig(t)
	cfg.Server.Netbios = true

	err := Validate(&cfg)
	if err == nil {
		t.Fatal("netbios is not implemented and must be rejected rather than silently ignored")
	}
	if !strings.Contains(err.Error(), "netbios") {
		t.Errorf("error should name the option, got: %v", err)
	}
}

// state_dir is equally unimplemented but harmless, so it must not break an
// existing config that still sets it.
func TestValidate_AcceptsStateDir(t *testing.T) {
	cfg := validatableConfig(t)
	cfg.Server.StateDir = "/var/run/gosamba"

	if err := Validate(&cfg); err != nil {
		t.Fatalf("state_dir is unused but must stay accepted: %v", err)
	}
}
