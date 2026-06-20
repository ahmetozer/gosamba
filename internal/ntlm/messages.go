package ntlm

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

var ErrShortMessage = errors.New("ntlm: message truncated")

// NegotiateMessage is type 1 (client → server).
type NegotiateMessage struct {
	Flags uint32
}

func DecodeNegotiate(b []byte) (NegotiateMessage, error) {
	if len(b) < 32 {
		return NegotiateMessage{}, fmt.Errorf("%w: type 1 needs 32 bytes", ErrShortMessage)
	}
	if !bytes.Equal(b[0:8], Signature[:]) {
		return NegotiateMessage{}, errors.New("ntlm: bad signature")
	}
	if binary.LittleEndian.Uint32(b[8:]) != MessageTypeNegotiate {
		return NegotiateMessage{}, errors.New("ntlm: not a NEGOTIATE message")
	}
	return NegotiateMessage{
		Flags: binary.LittleEndian.Uint32(b[12:]),
	}, nil
}

// ChallengeMessage is type 2 (server → client).
type ChallengeMessage struct {
	TargetName string
	Flags      uint32
	Challenge  [8]byte
	TargetInfo []AVPair
}

// EncodeChallenge serializes a Type 2 NTLMSSP message.
func EncodeChallenge(m ChallengeMessage) []byte {
	targetName := UTF16LE(m.TargetName)
	avBytes := EncodeAVList(m.TargetInfo)

	const fixedSize = 56
	out := make([]byte, fixedSize+len(targetName)+len(avBytes))
	copy(out[0:8], Signature[:])
	binary.LittleEndian.PutUint32(out[8:], MessageTypeChallenge)

	binary.LittleEndian.PutUint16(out[12:], uint16(len(targetName)))
	binary.LittleEndian.PutUint16(out[14:], uint16(len(targetName)))
	binary.LittleEndian.PutUint32(out[16:], uint32(fixedSize))

	binary.LittleEndian.PutUint32(out[20:], m.Flags)
	copy(out[24:32], m.Challenge[:])

	binary.LittleEndian.PutUint16(out[40:], uint16(len(avBytes)))
	binary.LittleEndian.PutUint16(out[42:], uint16(len(avBytes)))
	binary.LittleEndian.PutUint32(out[44:], uint32(fixedSize+len(targetName)))

	out[48] = 10
	out[49] = 0
	binary.LittleEndian.PutUint16(out[50:], 22000)
	out[55] = 15

	copy(out[fixedSize:], targetName)
	copy(out[fixedSize+len(targetName):], avBytes)
	return out
}

// AuthenticateMessage is type 3 (client → server).
type AuthenticateMessage struct {
	LmResponse                []byte
	NtResponse                []byte
	DomainName                string
	UserName                  string
	Workstation               string
	EncryptedRandomSessionKey []byte
	Flags                     uint32
	MIC                       [16]byte
	HasMIC                    bool
}

func DecodeAuthenticate(b []byte) (AuthenticateMessage, error) {
	if len(b) < 64 {
		return AuthenticateMessage{}, fmt.Errorf("%w: type 3 needs 64 bytes", ErrShortMessage)
	}
	if !bytes.Equal(b[0:8], Signature[:]) {
		return AuthenticateMessage{}, errors.New("ntlm: bad signature")
	}
	if binary.LittleEndian.Uint32(b[8:]) != MessageTypeAuthenticate {
		return AuthenticateMessage{}, errors.New("ntlm: not AUTHENTICATE")
	}

	read := func(off int) ([]byte, error) {
		l := int(binary.LittleEndian.Uint16(b[off:]))
		o := int(binary.LittleEndian.Uint32(b[off+4:]))
		if l == 0 {
			return nil, nil
		}
		if o+l > len(b) {
			return nil, fmt.Errorf("%w: field at off=%d (l=%d, o=%d)", ErrShortMessage, off, l, o)
		}
		return b[o : o+l], nil
	}

	var m AuthenticateMessage
	var err error
	if m.LmResponse, err = read(12); err != nil {
		return AuthenticateMessage{}, err
	}
	if m.NtResponse, err = read(20); err != nil {
		return AuthenticateMessage{}, err
	}
	dom, err := read(28)
	if err != nil {
		return AuthenticateMessage{}, err
	}
	usr, err := read(36)
	if err != nil {
		return AuthenticateMessage{}, err
	}
	wks, err := read(44)
	if err != nil {
		return AuthenticateMessage{}, err
	}
	if m.EncryptedRandomSessionKey, err = read(52); err != nil {
		return AuthenticateMessage{}, err
	}
	m.Flags = binary.LittleEndian.Uint32(b[60:])

	if m.Flags&NegotiateUnicode != 0 {
		m.DomainName = decodeUTF16LE(dom)
		m.UserName = decodeUTF16LE(usr)
		m.Workstation = decodeUTF16LE(wks)
	} else {
		m.DomainName = string(dom)
		m.UserName = string(usr)
		m.Workstation = string(wks)
	}

	const micOffset = 72
	if len(b) >= micOffset+16 {
		minPayload := smallestPayloadOffset(b)
		if minPayload >= micOffset+16 {
			copy(m.MIC[:], b[micOffset:micOffset+16])
			m.HasMIC = true
		}
	}
	return m, nil
}

func smallestPayloadOffset(b []byte) int {
	min := int(^uint(0) >> 1)
	for _, off := range []int{16, 24, 32, 40, 48, 56} {
		l := int(binary.LittleEndian.Uint16(b[off:]))
		o := int(binary.LittleEndian.Uint32(b[off+4:]))
		if l > 0 && o < min {
			min = o
		}
	}
	return min
}

func decodeUTF16LE(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	r := make([]rune, 0, len(b)/2)
	for i := 0; i < len(b); i += 2 {
		r = append(r, rune(uint16(b[i])|uint16(b[i+1])<<8))
	}
	return string(r)
}
