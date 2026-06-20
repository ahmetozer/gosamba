package smb3

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
)

// SMB3 Transform Header (MS-SMB2 §2.2.41).
//
// Layout (52 bytes):
//
//	0  ProtocolId            4   = 0xFD 'S' 'M' 'B'
//	4  Signature            16   = AEAD tag
//	20 Nonce                16   = 11 bytes (CCM) or 12 bytes (GCM), zero-padded
//	36 OriginalMessageSize   4
//	40 Reserved              2
//	42 Flags/EncryptionAlgo  2   = 0x0001 = encrypted
//	44 SessionId             8
const (
	TransformHeaderSize    = 52
	TransformFlagEncrypted = 0x0001
	transformAADStart      = 20 // bytes 20..52 are the additional-authenticated-data
	transformAADLen        = 32
)

var (
	transformProtocolID = [4]byte{0xFD, 'S', 'M', 'B'}

	ErrShortTransform     = errors.New("smb3: transform header too short")
	ErrBadTransformID     = errors.New("smb3: bad transform ProtocolId")
	ErrUnknownCipher      = errors.New("smb3: unknown cipher")
	ErrTransformDecrypt   = errors.New("smb3: transform decrypt failed")
	ErrShortTransformBody = errors.New("smb3: transform body shorter than OriginalMessageSize")
)

// Cipher IDs (matching MS-SMB2 SMB2_ENCRYPTION_CAPABILITIES values).
const (
	CipherAES128CCM uint16 = 0x0001
	CipherAES128GCM uint16 = 0x0002
	CipherAES256CCM uint16 = 0x0003
	CipherAES256GCM uint16 = 0x0004
)

// IsTransform reports whether buf begins with the SMB3 transform protocol ID.
func IsTransform(buf []byte) bool {
	return len(buf) >= 4 &&
		buf[0] == transformProtocolID[0] && buf[1] == transformProtocolID[1] &&
		buf[2] == transformProtocolID[2] && buf[3] == transformProtocolID[3]
}

// DecryptTransform decrypts a frame whose first 4 bytes are 0xFD 'S' 'M' 'B'.
// Returns the cleartext SMB2 message, the SessionId, and an error.
func DecryptTransform(cipherID uint16, key, frame []byte) ([]byte, uint64, error) {
	if len(frame) < TransformHeaderSize {
		return nil, 0, ErrShortTransform
	}
	if !IsTransform(frame) {
		return nil, 0, ErrBadTransformID
	}
	origSize := binary.LittleEndian.Uint32(frame[36:])
	flags := binary.LittleEndian.Uint16(frame[42:])
	sessID := binary.LittleEndian.Uint64(frame[44:])
	if flags&TransformFlagEncrypted == 0 {
		return nil, 0, fmt.Errorf("smb3: transform flags=0x%04x (not encrypted)", flags)
	}
	ciphertext := frame[TransformHeaderSize:]
	if len(ciphertext) < int(origSize) {
		return nil, 0, ErrShortTransformBody
	}

	aead, nonceLen, err := newAEAD(cipherID, key)
	if err != nil {
		return nil, 0, err
	}
	nonce := frame[20 : 20+nonceLen]

	// Reconstruct: ciphertext-with-tag = ciphertext || signature(16).
	tag := frame[4:20]
	ct := make([]byte, len(ciphertext)+16)
	copy(ct, ciphertext)
	copy(ct[len(ciphertext):], tag)

	aad := frame[transformAADStart : transformAADStart+transformAADLen]
	pt, err := aead.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %v", ErrTransformDecrypt, err)
	}
	return pt, sessID, nil
}

// EncryptTransform produces a transform-wrapped frame for plaintext using key.
// sessID is written into the header so the peer can locate the session.
func EncryptTransform(cipherID uint16, key []byte, sessID uint64, plaintext []byte) ([]byte, error) {
	aead, nonceLen, err := newAEAD(cipherID, key)
	if err != nil {
		return nil, err
	}
	if nonceLen > 16 {
		return nil, fmt.Errorf("smb3: nonce length %d exceeds 16", nonceLen)
	}
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	out := make([]byte, TransformHeaderSize+len(plaintext)+16)
	copy(out[:4], transformProtocolID[:])
	// signature filled in after seal
	copy(out[20:20+nonceLen], nonce)
	binary.LittleEndian.PutUint32(out[36:], uint32(len(plaintext)))
	binary.LittleEndian.PutUint16(out[42:], TransformFlagEncrypted)
	binary.LittleEndian.PutUint64(out[44:], sessID)

	aad := out[transformAADStart : transformAADStart+transformAADLen]
	sealed := aead.Seal(nil, nonce, plaintext, aad)
	// sealed = ciphertext || tag(16)
	copy(out[TransformHeaderSize:], sealed[:len(plaintext)])
	copy(out[4:20], sealed[len(plaintext):])
	return out[:TransformHeaderSize+len(plaintext)], nil
}

func newAEAD(cipherID uint16, rawKey []byte) (cipher.AEAD, int, error) {
	switch cipherID {
	case CipherAES128GCM, CipherAES128CCM:
		if len(rawKey) < 16 {
			return nil, 0, fmt.Errorf("smb3: cipher 0x%04x needs 16-byte key, got %d", cipherID, len(rawKey))
		}
		block, err := aes.NewCipher(rawKey[:16])
		if err != nil {
			return nil, 0, err
		}
		if cipherID == CipherAES128GCM {
			a, err := cipher.NewGCM(block)
			return a, 12, err
		}
		a, err := newCCM(block)
		return a, 11, err
	case CipherAES256GCM, CipherAES256CCM:
		if len(rawKey) < 32 {
			return nil, 0, fmt.Errorf("smb3: cipher 0x%04x needs 32-byte key, got %d", cipherID, len(rawKey))
		}
		block, err := aes.NewCipher(rawKey[:32])
		if err != nil {
			return nil, 0, err
		}
		if cipherID == CipherAES256GCM {
			a, err := cipher.NewGCM(block)
			return a, 12, err
		}
		a, err := newCCM(block)
		return a, 11, err
	}
	return nil, 0, fmt.Errorf("%w: 0x%04x", ErrUnknownCipher, cipherID)
}
