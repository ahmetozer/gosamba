package userdb

import (
	"strings"
	"testing"
)

func TestDB_AddAndLookup(t *testing.T) {
	db := New()
	if err := db.AddPlaintext("alice", "secret", "alice", []string{"*"}); err != nil {
		t.Fatal(err)
	}
	u, ok := db.Lookup("alice")
	if !ok {
		t.Fatal("expected user 'alice' to be found")
	}
	if u.Name != "alice" || u.SystemUser != "alice" {
		t.Errorf("got %+v", u)
	}
	if u.NTHash != NTHash("secret") {
		t.Errorf("NT hash mismatch")
	}
}

func TestDB_LookupCaseInsensitive(t *testing.T) {
	db := New()
	_ = db.AddPlaintext("Alice", "x", "alice", []string{"*"})
	if _, ok := db.Lookup("ALICE"); !ok {
		t.Errorf("lookup should be case-insensitive")
	}
	if _, ok := db.Lookup("alice"); !ok {
		t.Errorf("lookup should be case-insensitive")
	}
}

func TestDB_Duplicate(t *testing.T) {
	db := New()
	_ = db.AddPlaintext("u", "p", "s", []string{"*"})
	err := db.AddPlaintext("u", "p2", "s", []string{"*"})
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected duplicate error, got %v", err)
	}
}

func TestDB_AddHash(t *testing.T) {
	db := New()
	var h [16]byte
	for i := range h {
		h[i] = byte(i)
	}
	if err := db.AddHash("u", h, "sys", []string{"*"}); err != nil {
		t.Fatal(err)
	}
	u, _ := db.Lookup("u")
	if u.NTHash != h {
		t.Errorf("hash mismatch")
	}
}
