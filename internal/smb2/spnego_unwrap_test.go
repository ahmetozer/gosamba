package smb2

import (
	"bytes"
	"testing"
)

func TestUnwrapNTLM_FindsSignature(t *testing.T) {
	ntlm := append([]byte("NTLMSSP\x00"), []byte("\x01\x00\x00\x00rest")...)
	wrapped := append([]byte{0x60, 0x10, 0xAA, 0xBB}, ntlm...)
	out, err := UnwrapNTLM(wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(out, []byte("NTLMSSP\x00")) {
		t.Error("did not find NTLMSSP")
	}
}

func TestWrapNTLMResp_Roundtrip(t *testing.T) {
	ntlm := []byte("NTLMSSP\x00fake-payload")
	w := WrapNTLMResp(SPNEGOAcceptIncomplete, ntlm)
	if w[0] != 0xa1 {
		t.Errorf("expected outer tag 0xa1, got %x", w[0])
	}
	got, err := UnwrapNTLM(w)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:len(ntlm)], ntlm) {
		t.Errorf("ntlm payload mismatch")
	}
}

func TestWrapNTLMResp_AcceptedNoToken(t *testing.T) {
	w := WrapNTLMResp(SPNEGOAcceptCompleted, nil)
	if w[0] != 0xa1 {
		t.Errorf("expected outer tag 0xa1, got %x", w[0])
	}
}
