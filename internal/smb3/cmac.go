package smb3

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
)

// CMAC computes AES-CMAC of msg with the given AES key (RFC 4493).
// The prefix (everything but the last block) is processed via
// crypto/cipher.NewCBCEncrypter, which uses Go's AES-NI/ARM-AES fast path,
// avoiding per-block interface dispatch overhead.
func CMAC(key, msg []byte) [16]byte {
	c, _ := aes.NewCipher(key)
	k1, k2 := cmacSubkeys(c)

	const bs = 16
	var lastBlock [bs]byte

	complete := len(msg) > 0 && len(msg)%bs == 0
	var prefixLen int
	if complete {
		prefixLen = len(msg) - bs
		copy(lastBlock[:], msg[prefixLen:])
		subtle.XORBytes(lastBlock[:], lastBlock[:], k1[:])
	} else {
		prefixLen = (len(msg) / bs) * bs
		rem := msg[prefixLen:]
		copy(lastBlock[:], rem)
		lastBlock[len(rem)] = 0x80
		subtle.XORBytes(lastBlock[:], lastBlock[:], k2[:])
	}

	var x [bs]byte
	if prefixLen > 0 {
		// CBC-encrypt the prefix; the final ciphertext block is the CBC-MAC
		// of the prefix and serves as the IV for the last block.
		iv := make([]byte, bs)
		cbc := cipher.NewCBCEncrypter(c, iv)
		buf := make([]byte, prefixLen)
		cbc.CryptBlocks(buf, msg[:prefixLen])
		copy(x[:], buf[prefixLen-bs:])
	}

	subtle.XORBytes(lastBlock[:], lastBlock[:], x[:])
	var out [16]byte
	c.Encrypt(out[:], lastBlock[:])
	return out
}

func cmacSubkeys(c cipher.Block) (k1, k2 [16]byte) {
	const bs = 16
	var L [bs]byte
	c.Encrypt(L[:], L[:])
	k1 = leftShift(L)
	if L[0]&0x80 != 0 {
		k1[15] ^= 0x87
	}
	k2 = leftShift(k1)
	if k1[0]&0x80 != 0 {
		k2[15] ^= 0x87
	}
	return
}

func leftShift(in [16]byte) [16]byte {
	var out [16]byte
	overflow := byte(0)
	for i := 15; i >= 0; i-- {
		out[i] = (in[i] << 1) | overflow
		if in[i]&0x80 != 0 {
			overflow = 1
		} else {
			overflow = 0
		}
	}
	return out
}
