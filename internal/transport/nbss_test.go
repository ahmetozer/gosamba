package transport

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestReadFrame_Happy(t *testing.T) {
	buf := bytes.NewReader([]byte{0x00, 0x00, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o'})
	payload, err := ReadFrame(buf, MaxFrameSize)
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != "hello" {
		t.Errorf("payload: %q", payload)
	}
}

func TestReadFrame_Empty(t *testing.T) {
	buf := bytes.NewReader([]byte{0x00, 0x00, 0x00, 0x00})
	payload, err := ReadFrame(buf, MaxFrameSize)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) != 0 {
		t.Errorf("expected empty payload, got %d bytes", len(payload))
	}
}

func TestReadFrame_BadType(t *testing.T) {
	buf := bytes.NewReader([]byte{0x85, 0x00, 0x00, 0x00})
	_, err := ReadFrame(buf, MaxFrameSize)
	if !errors.Is(err, ErrUnsupportedFrameType) {
		t.Errorf("expected ErrUnsupportedFrameType, got %v", err)
	}
}

func TestReadFrame_TooLarge(t *testing.T) {
	buf := bytes.NewReader([]byte{0x00, 0x10, 0x00, 0x00})
	_, err := ReadFrame(buf, 1024)
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Errorf("expected ErrFrameTooLarge, got %v", err)
	}
}

func TestReadFrame_TruncatedHeader(t *testing.T) {
	buf := bytes.NewReader([]byte{0x00, 0x00})
	_, err := ReadFrame(buf, MaxFrameSize)
	if !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		t.Errorf("expected EOF/ErrUnexpectedEOF, got %v", err)
	}
}

func TestReadFrame_TruncatedPayload(t *testing.T) {
	buf := bytes.NewReader([]byte{0x00, 0x00, 0x00, 0x05, 'h', 'i'})
	_, err := ReadFrame(buf, MaxFrameSize)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("expected ErrUnexpectedEOF, got %v", err)
	}
}

func TestWriteFrame_RoundTrip(t *testing.T) {
	var buf bytes.Buffer
	payload := []byte("smb2 message goes here")
	if err := WriteFrame(&buf, payload); err != nil {
		t.Fatal(err)
	}
	got, err := ReadFrame(&buf, MaxFrameSize)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("payload mismatch")
	}
}

func TestWriteFrame_TooLarge(t *testing.T) {
	var buf bytes.Buffer
	huge := make([]byte, 1<<25)
	if err := WriteFrame(&buf, huge); !errors.Is(err, ErrFrameTooLarge) {
		t.Errorf("expected ErrFrameTooLarge, got %v", err)
	}
}
