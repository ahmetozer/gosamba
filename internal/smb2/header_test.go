package smb2

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

const negotiateHeaderHex = "fe534d42" +
	"4000" +
	"0000" +
	"00000000" +
	"0000" +
	"0000" +
	"00000000" +
	"00000000" +
	"0100000000000000" +
	"00000000" +
	"00000000" +
	"0000000000000000" +
	"00000000000000000000000000000000"

func TestDecodeHeader_Negotiate(t *testing.T) {
	raw, _ := hex.DecodeString(negotiateHeaderHex)
	h, err := DecodeHeader(raw)
	if err != nil {
		t.Fatal(err)
	}
	if h.Command != CommandNegotiate {
		t.Errorf("Command: %s", h.Command)
	}
	if h.MessageID != 1 {
		t.Errorf("MessageID: %d", h.MessageID)
	}
	if h.SessionID != 0 {
		t.Errorf("SessionID: %d", h.SessionID)
	}
}

func TestDecodeHeader_BadProtocolID(t *testing.T) {
	bad := make([]byte, HeaderSize)
	bad[0] = 0xFF
	_, err := DecodeHeader(bad)
	if !errors.Is(err, ErrBadProtocolID) {
		t.Errorf("expected ErrBadProtocolID, got %v", err)
	}
}

func TestDecodeHeader_BadStructureSize(t *testing.T) {
	raw, _ := hex.DecodeString(negotiateHeaderHex)
	raw[4] = 0x41
	_, err := DecodeHeader(raw)
	if !errors.Is(err, ErrBadStructureSize) {
		t.Errorf("expected ErrBadStructureSize, got %v", err)
	}
}

func TestDecodeHeader_TooShort(t *testing.T) {
	_, err := DecodeHeader(make([]byte, 32))
	if !errors.Is(err, ErrShortBuffer) {
		t.Errorf("expected ErrShortBuffer, got %v", err)
	}
}

func TestEncodeHeader_RoundTrip(t *testing.T) {
	src := Header{
		CreditCharge:   1,
		Status:         0,
		Command:        CommandNegotiate,
		CreditResponse: 1,
		Flags:          FlagServerToRedir,
		MessageID:      0xCAFEBABE,
		TreeID:         0,
		SessionID:      0xDEADBEEF,
	}
	out := make([]byte, HeaderSize)
	if err := EncodeHeader(out, src); err != nil {
		t.Fatal(err)
	}
	got, err := DecodeHeader(out)
	if err != nil {
		t.Fatal(err)
	}
	if got != src {
		t.Errorf("round-trip mismatch: %+v vs %+v", got, src)
	}
}

func TestEncodeHeader_ProtocolID(t *testing.T) {
	out := make([]byte, HeaderSize)
	_ = EncodeHeader(out, Header{Command: CommandNegotiate})
	want := []byte{0xFE, 'S', 'M', 'B'}
	if !bytes.Equal(out[:4], want) {
		t.Errorf("ProtocolId = %x, want %x", out[:4], want)
	}
}
