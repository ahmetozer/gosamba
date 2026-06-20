package ntlm

import (
	"encoding/binary"
	"fmt"
)

// AVPair is one entry in an AV_PAIR list.
type AVPair struct {
	ID    AVID
	Value []byte
}

// EncodeAVList serializes a list, appending a terminating EOL pair.
func EncodeAVList(pairs []AVPair) []byte {
	out := make([]byte, 0, 64)
	for _, p := range pairs {
		hdr := [4]byte{}
		binary.LittleEndian.PutUint16(hdr[0:], uint16(p.ID))
		binary.LittleEndian.PutUint16(hdr[2:], uint16(len(p.Value)))
		out = append(out, hdr[:]...)
		out = append(out, p.Value...)
	}
	out = append(out, 0, 0, 0, 0)
	return out
}

// DecodeAVList parses an AV-pair list, stopping at EOL.
func DecodeAVList(b []byte) ([]AVPair, error) {
	var out []AVPair
	for {
		if len(b) < 4 {
			return nil, fmt.Errorf("ntlm: AV list truncated")
		}
		id := AVID(binary.LittleEndian.Uint16(b[0:]))
		l := int(binary.LittleEndian.Uint16(b[2:]))
		if id == AVEOL {
			return out, nil
		}
		if 4+l > len(b) {
			return nil, fmt.Errorf("ntlm: AV pair value truncated")
		}
		out = append(out, AVPair{ID: id, Value: append([]byte(nil), b[4:4+l]...)})
		b = b[4+l:]
	}
}

// UTF16LE encodes s as UTF-16LE.
func UTF16LE(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for _, r := range s {
		if r > 0xFFFF {
			r -= 0x10000
			hi := 0xD800 + uint16(r>>10)
			lo := 0xDC00 + uint16(r&0x3FF)
			out = append(out, byte(hi), byte(hi>>8), byte(lo), byte(lo>>8))
		} else {
			out = append(out, byte(r), byte(r>>8))
		}
	}
	return out
}
