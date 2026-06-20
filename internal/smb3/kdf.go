// Package smb3 implements SMB 3.x crypto primitives: SP800-108 KDF, AES-CMAC.
package smb3

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
)

// KDF computes SP800-108 counter-mode HMAC-SHA256 KDF as used by SMB3.
// L is the output length in BITS (per spec PRF input).
func KDF(key []byte, label, context []byte, L uint32) []byte {
	out := make([]byte, 0, (L+255)/256*32)
	var i uint32 = 1
	for uint32(len(out))*8 < L {
		mac := hmac.New(sha256.New, key)
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], i)
		mac.Write(buf[:])
		mac.Write(label)
		mac.Write([]byte{0x00})
		mac.Write(context)
		var lbuf [4]byte
		binary.BigEndian.PutUint32(lbuf[:], L)
		mac.Write(lbuf[:])
		out = append(out, mac.Sum(nil)...)
		i++
	}
	return out[:L/8]
}
