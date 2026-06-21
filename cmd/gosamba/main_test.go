package main

import (
	"strings"
	"testing"
)

func TestNTHashFromReader(t *testing.T) {
	// Reference value computed by internal/userdb.NTHash for "s3cret".
	const want = "d4c619cb16d4632b275658316a7e657e"

	cases := map[string]string{
		"trailing newline": "s3cret\n",
		"no newline":       "s3cret",
		"crlf":             "s3cret\r\n",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := nthashFromReader(strings.NewReader(in))
			if err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Errorf("got %q, want %q", got, want)
			}
		})
	}
}

func TestNTHashFromReader_Empty(t *testing.T) {
	if _, err := nthashFromReader(strings.NewReader("\n")); err == nil {
		t.Fatal("expected error for empty password")
	}
}
