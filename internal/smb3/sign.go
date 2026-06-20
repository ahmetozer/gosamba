package smb3

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
)

// Signing algorithm IDs (matching MS-SMB2 SMB2_SIGNING_CAPABILITIES values).
const (
	SignAlgoHMACSHA256 uint16 = 0x0000
	SignAlgoAESCMAC    uint16 = 0x0001
	SignAlgoAESGMAC    uint16 = 0x0002
)

// SignMessage signs an SMB2 message in-place. The 16-byte Signature field at
// offset 48 is zeroed, FlagSigned (0x08) is set, and the chosen MAC is written.
func SignMessage(algo uint16, signingKey []byte, msg []byte) {
	if len(msg) < 64 {
		return
	}
	for i := 48; i < 64; i++ {
		msg[i] = 0
	}
	msg[16] |= 0x08
	sig := computeMAC(algo, signingKey, msg)
	copy(msg[48:64], sig[:])
}

// VerifyMessage returns true iff msg is correctly signed with key.
func VerifyMessage(algo uint16, signingKey []byte, msg []byte) bool {
	if len(msg) < 64 {
		return false
	}
	var saved [16]byte
	copy(saved[:], msg[48:64])
	for i := 48; i < 64; i++ {
		msg[i] = 0
	}
	mac := computeMAC(algo, signingKey, msg)
	copy(msg[48:64], saved[:])
	for i := 0; i < 16; i++ {
		if mac[i] != saved[i] {
			return false
		}
	}
	return true
}

func computeMAC(algo uint16, key, msg []byte) [16]byte {
	switch algo {
	case SignAlgoAESGMAC:
		return gmacSign(key, msg)
	case SignAlgoHMACSHA256:
		return hmacSHA256Sign(key, msg)
	default:
		return CMAC(key, msg)
	}
}

// hmacSHA256Sign returns the leftmost 16 bytes of HMAC-SHA256(key, msg). This
// is the SMB 2.0.2 / 2.1 signing algorithm (MS-SMB2 §3.1.4.1.1).
func hmacSHA256Sign(key, msg []byte) [16]byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	sum := mac.Sum(nil)
	var out [16]byte
	copy(out[:], sum[:16])
	return out
}

// gmacSign computes AES-128-GMAC per MS-SMB2 §3.1.4.1 / Samba
// libcli/smb/smb2_signing.c. The 12-byte nonce is:
//
//	nonce[0:8]  = MessageId (little-endian)
//	nonce[8:12] = low 4 bytes of (header.Flags & FLAG_REDIRECT). On server
//	              responses bit 0 is set, making byte 8 = 0x01. On requests
//	              all four bytes are zero. CANCEL requests additionally OR in
//	              FLAG_ASYNC (0x02), which we don't generate.
func gmacSign(key, msg []byte) [16]byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		return [16]byte{}
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return [16]byte{}
	}
	var nonce [12]byte
	msgID := binary.LittleEndian.Uint64(msg[24:32])
	binary.LittleEndian.PutUint64(nonce[0:8], msgID)
	flags := binary.LittleEndian.Uint32(msg[16:20])
	const flagServerToRedir = 0x00000001
	const flagAsyncCommand = 0x00000002
	highBits := flags & (flagServerToRedir | flagAsyncCommand)
	binary.LittleEndian.PutUint32(nonce[8:12], highBits)
	tag := aead.Seal(nil, nonce[:], nil, msg)
	var out [16]byte
	copy(out[:], tag)
	return out
}
