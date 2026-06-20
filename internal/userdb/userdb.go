package userdb

import (
	"fmt"
	"strings"
)

type User struct {
	Name        string
	NTHash      [16]byte
	SystemUser  string
	AllowShares []string
}

type DB struct {
	users map[string]User
}

func New() *DB {
	return &DB{users: make(map[string]User)}
}

func (db *DB) AddPlaintext(name, password, systemUser string, shares []string) error {
	hash := NTHash(password)
	return db.AddHash(name, hash, systemUser, shares)
}

func (db *DB) AddHash(name string, hash [16]byte, systemUser string, shares []string) error {
	key := strings.ToLower(name)
	if _, dup := db.users[key]; dup {
		return fmt.Errorf("duplicate user %q", name)
	}
	if len(shares) == 0 {
		shares = []string{"*"}
	}
	db.users[key] = User{
		Name:        name,
		NTHash:      hash,
		SystemUser:  systemUser,
		AllowShares: append([]string(nil), shares...),
	}
	return nil
}

func (db *DB) Lookup(name string) (User, bool) {
	u, ok := db.users[strings.ToLower(name)]
	return u, ok
}

func (db *DB) Len() int { return len(db.users) }
