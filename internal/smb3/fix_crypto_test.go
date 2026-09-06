package smb3

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// TestCipherKeyBits pins the KDF output length per cipher: 256 bits for the
// AES-256 ciphers, 128 for everything else (MS-SMB2 §3.1.4.2).
func TestCipherKeyBits(t *testing.T) {
	cases := []struct {
		cipher uint16
		want   uint32
	}{
		{CipherAES128CCM, 128},
		{CipherAES128GCM, 128},
		{CipherAES256CCM, 256},
		{CipherAES256GCM, 256},
		{0, 128}, // encryption not negotiated
	}
	for _, c := range cases {
		if got := CipherKeyBits(c.cipher); got != c.want {
			t.Errorf("CipherKeyBits(0x%04x) = %d, want %d", c.cipher, got, c.want)
		}
	}
}

// TestTransformRoundTrip_AES256 covers the ciphers a current Windows client
// prefers. A 16-byte key here is rejected outright by newAEAD, which is what
// made every AES-256 session fail before the key-length fix.
func TestTransformRoundTrip_AES256(t *testing.T) {
	for _, cipher := range []uint16{CipherAES256GCM, CipherAES256CCM} {
		key := bytes.Repeat([]byte{0x5A}, 32)
		plain := []byte("AES-256 transform payload")
		frame, err := EncryptTransform(cipher, key, 0x0123456789ABCDEF, plain)
		if err != nil {
			t.Fatalf("cipher 0x%04x: encrypt: %v", cipher, err)
		}
		got, sid, err := DecryptTransform(cipher, key, frame)
		if err != nil {
			t.Fatalf("cipher 0x%04x: decrypt: %v", cipher, err)
		}
		if sid != 0x0123456789ABCDEF {
			t.Errorf("cipher 0x%04x: session id %x", cipher, sid)
		}
		if !bytes.Equal(got, plain) {
			t.Errorf("cipher 0x%04x: plaintext %q, want %q", cipher, got, plain)
		}
	}
}

// TestTransformRejectsShortKey documents the failure the 128-bit derivation
// produced: an AES-256 cipher with a 16-byte key can't encrypt anything.
func TestTransformRejectsShortKey(t *testing.T) {
	short := bytes.Repeat([]byte{0x11}, 16)
	if _, err := EncryptTransform(CipherAES256GCM, short, 1, []byte("x")); err == nil {
		t.Fatal("AES-256-GCM accepted a 16-byte key")
	}
}

// TestTransformNoncesUnique is the regression test for nonce reuse. Two
// successive encryptions — the interim STATUS_PENDING and the final response of
// an async command, say — must never share a nonce: with GCM or CCM a repeat is
// a total loss of confidentiality and integrity for both frames.
func TestTransformNoncesUnique(t *testing.T) {
	key := bytes.Repeat([]byte{0x77}, 32)

	first, err := EncryptTransform(CipherAES256GCM, key, 7, []byte("interim"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := EncryptTransform(CipherAES256GCM, key, 7, []byte("final"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first[20:32], second[20:32]) {
		t.Fatalf("two successive encryptions reused nonce %x", first[20:32])
	}

	// And across many frames, mixed ciphers and keys, every nonce is distinct.
	seen := make(map[string]struct{}, 4096)
	for i := 0; i < 2048; i++ {
		for _, c := range []uint16{CipherAES128GCM, CipherAES128CCM} {
			frame, err := EncryptTransform(c, key[:16], uint64(i), []byte("payload"))
			if err != nil {
				t.Fatal(err)
			}
			// Nonce field is 16 bytes wide, zero-padded past nonceLen.
			n := string(frame[20:36])
			if _, dup := seen[n]; dup {
				t.Fatalf("nonce %x repeated after %d frames", frame[20:36], i)
			}
			seen[n] = struct{}{}
		}
	}
}

// TestTransformNonceMonotonic checks the counter really advances (a stuck
// counter would still pass a two-sample uniqueness check by luck of the random
// prefix, but not this).
func TestTransformNonceMonotonic(t *testing.T) {
	key := bytes.Repeat([]byte{0x22}, 16)
	var prev uint64
	for i := 0; i < 8; i++ {
		frame, err := EncryptTransform(CipherAES128GCM, key, 1, []byte("z"))
		if err != nil {
			t.Fatal(err)
		}
		ctr := binary.LittleEndian.Uint64(frame[20:28])
		if i > 0 && ctr != prev+1 {
			t.Fatalf("nonce counter jumped: %d then %d", prev, ctr)
		}
		prev = ctr
	}
}

// TestVerifyMessageRejectsNearMiss guards the constant-time comparison: a
// signature that matches in all but the last byte must be rejected exactly like
// one that matches in none of them.
func TestVerifyMessageRejectsNearMiss(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 16)
	msg := make([]byte, 128)
	copy(msg, []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint64(msg[24:], 42)

	SignMessage(SignAlgoAESCMAC, key, msg)
	if !VerifyMessage(SignAlgoAESCMAC, key, msg) {
		t.Fatal("freshly signed message failed verification")
	}
	// Verification must not have disturbed the message.
	if !VerifyMessage(SignAlgoAESCMAC, key, msg) {
		t.Fatal("second verification failed; VerifyMessage mutated the buffer")
	}

	msg[63] ^= 0x01 // last byte of the signature only
	if VerifyMessage(SignAlgoAESCMAC, key, msg) {
		t.Error("accepted a signature differing in the final byte")
	}
	msg[63] ^= 0x01
	msg[48] ^= 0x01 // first byte of the signature only
	if VerifyMessage(SignAlgoAESCMAC, key, msg) {
		t.Error("accepted a signature differing in the first byte")
	}
}
