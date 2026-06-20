package userdb

import (
	"encoding/binary"
	"unicode/utf16"

	"golang.org/x/crypto/md4"
)

// NTHash returns the NTLM NT hash of the password: MD4(UTF-16LE(password)).
func NTHash(password string) [16]byte {
	codeUnits := utf16.Encode([]rune(password))
	buf := make([]byte, len(codeUnits)*2)
	for i, c := range codeUnits {
		binary.LittleEndian.PutUint16(buf[i*2:], c)
	}
	h := md4.New()
	_, _ = h.Write(buf)
	var out [16]byte
	copy(out[:], h.Sum(nil))
	for i := range buf {
		buf[i] = 0
	}
	return out
}
