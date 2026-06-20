package logging

import (
	"bytes"
	"strings"
	"testing"
)

func TestNew_TextDebug(t *testing.T) {
	var buf bytes.Buffer
	lg, err := New(&buf, "debug", "text")
	if err != nil {
		t.Fatal(err)
	}
	lg.Debug("hello", "k", "v")
	out := buf.String()
	if !strings.Contains(out, "hello") || !strings.Contains(out, "k=v") {
		t.Errorf("unexpected text output: %s", out)
	}
}

func TestNew_JSONInfo(t *testing.T) {
	var buf bytes.Buffer
	lg, err := New(&buf, "info", "json")
	if err != nil {
		t.Fatal(err)
	}
	lg.Info("hi")
	out := buf.String()
	if !strings.HasPrefix(strings.TrimSpace(out), "{") {
		t.Errorf("expected JSON, got: %s", out)
	}
}

func TestNew_LevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	lg, _ := New(&buf, "warn", "text")
	lg.Info("should not appear")
	if buf.Len() != 0 {
		t.Errorf("info should be filtered: %s", buf.String())
	}
}

func TestNew_BadLevel(t *testing.T) {
	if _, err := New(nil, "trace", "text"); err == nil {
		t.Fatal("expected error for unknown level")
	}
}

func TestNew_BadFormat(t *testing.T) {
	if _, err := New(nil, "info", "yaml"); err == nil {
		t.Fatal("expected error for unknown format")
	}
}
