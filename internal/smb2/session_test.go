package smb2

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestSessionSetup_RequestRoundtrip(t *testing.T) {
	body := make([]byte, 24)
	body[0] = 25
	body[2] = 0x01
	body[3] = 0x01
	binary.LittleEndian.PutUint16(body[12:], 64+24)
	binary.LittleEndian.PutUint16(body[14:], 5)
	body = append(body, []byte("hello")...)

	r, err := DecodeSessionSetupRequest(body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(r.SecurityBuffer, []byte("hello")) {
		t.Errorf("buf: %q", r.SecurityBuffer)
	}
}

func TestSessionSetup_ResponseRoundtrip(t *testing.T) {
	out := EncodeSessionSetupResponse(SessionSetupResponse{
		SessionFlags:   0,
		SecurityBuffer: []byte("worldworld"),
	})
	if out[0] != 9 {
		t.Errorf("StructureSize: %d", out[0])
	}
	off := binary.LittleEndian.Uint16(out[4:])
	length := binary.LittleEndian.Uint16(out[6:])
	if length != 10 {
		t.Errorf("len: %d", length)
	}
	if off != 64+8 {
		t.Errorf("off: %d", off)
	}
	if !bytes.Equal(out[8:], []byte("worldworld")) {
		t.Errorf("buf: %q", out[8:])
	}
}
