package smb3

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
)

// SMB3 uses AES-CCM with a fixed 16-byte tag, 11-byte nonce, and L=4
// (NIST SP 800-38C). Go's standard library doesn't ship CCM, so we implement
// the variant that SMB3 needs.

const (
	ccmNonceSize = 11
	ccmTagSize   = 16
	ccmL         = 4 // length-of-length field (so q = 4 bytes -> max plaintext 2^32-1)
)

type ccm struct {
	block cipher.Block
}

func newCCM(b cipher.Block) (cipher.AEAD, error) {
	if b.BlockSize() != 16 {
		return nil, errors.New("smb3: CCM requires 16-byte block")
	}
	return &ccm{block: b}, nil
}

func (c *ccm) NonceSize() int { return ccmNonceSize }
func (c *ccm) Overhead() int  { return ccmTagSize }

func (c *ccm) Seal(dst, nonce, plaintext, aad []byte) []byte {
	if len(nonce) != ccmNonceSize {
		panic("smb3/ccm: bad nonce length")
	}
	tag := c.computeTag(nonce, plaintext, aad)
	out := make([]byte, len(plaintext)+ccmTagSize)
	c.ctrXor(nonce, plaintext, out[:len(plaintext)])
	encTag := make([]byte, 16)
	c.ctrEncryptTag(nonce, tag, encTag)
	copy(out[len(plaintext):], encTag[:ccmTagSize])
	return append(dst, out...)
}

func (c *ccm) Open(dst, nonce, ciphertext, aad []byte) ([]byte, error) {
	if len(nonce) != ccmNonceSize {
		return nil, errors.New("smb3/ccm: bad nonce length")
	}
	if len(ciphertext) < ccmTagSize {
		return nil, errors.New("smb3/ccm: ciphertext too short")
	}
	ctLen := len(ciphertext) - ccmTagSize
	ct := ciphertext[:ctLen]
	gotTag := ciphertext[ctLen:]

	pt := make([]byte, ctLen)
	c.ctrXor(nonce, ct, pt)
	expTag := c.computeTag(nonce, pt, aad)
	encExpTag := make([]byte, 16)
	c.ctrEncryptTag(nonce, expTag, encExpTag)
	if !ctEq(gotTag, encExpTag[:ccmTagSize]) {
		return nil, errors.New("smb3/ccm: authentication failed")
	}
	return append(dst, pt...), nil
}

func ctEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// computeTag implements the CBC-MAC over B0 || formatted-AAD || plaintext.
func (c *ccm) computeTag(nonce, plaintext, aad []byte) []byte {
	q := uint32(len(plaintext))
	flags := byte(0)
	if len(aad) > 0 {
		flags |= 0x40
	}
	// (M-2)/2 where M=tag length=16 -> (16-2)/2 = 7
	flags |= byte((ccmTagSize-2)/2) << 3
	// L-1 where L=4 -> 3
	flags |= byte(ccmL - 1)

	b0 := make([]byte, 16)
	b0[0] = flags
	copy(b0[1:1+ccmNonceSize], nonce)
	binary.BigEndian.PutUint32(b0[12:], q)

	mac := make([]byte, 16)
	c.block.Encrypt(mac, b0)

	if len(aad) > 0 {
		// Encode AAD length: SMB3 uses short AAD (<2^16-2^8), 2-byte big-endian.
		var lbuf []byte
		al := len(aad)
		if al < 0xFF00 {
			lbuf = []byte{byte(al >> 8), byte(al)}
		} else {
			lbuf = []byte{0xFF, 0xFE,
				byte(al >> 24), byte(al >> 16), byte(al >> 8), byte(al)}
		}
		stream := append(append([]byte{}, lbuf...), aad...)
		for len(stream)%16 != 0 {
			stream = append(stream, 0)
		}
		for off := 0; off < len(stream); off += 16 {
			for i := 0; i < 16; i++ {
				mac[i] ^= stream[off+i]
			}
			c.block.Encrypt(mac, mac)
		}
	}

	if len(plaintext) > 0 {
		full := (len(plaintext) / 16) * 16
		for off := 0; off < full; off += 16 {
			for i := 0; i < 16; i++ {
				mac[i] ^= plaintext[off+i]
			}
			c.block.Encrypt(mac, mac)
		}
		if rem := len(plaintext) - full; rem > 0 {
			var blk [16]byte
			copy(blk[:], plaintext[full:])
			for i := 0; i < 16; i++ {
				mac[i] ^= blk[i]
			}
			c.block.Encrypt(mac, mac)
		}
	}
	return mac
}

// ctrXor encrypts/decrypts plaintext with CTR (counter starts at 1, counter at 0
// is reserved for the tag).
func (c *ccm) ctrXor(nonce, in, out []byte) {
	var ctr [16]byte
	ctr[0] = byte(ccmL - 1) // flags: only L-1 in low bits
	copy(ctr[1:1+ccmNonceSize], nonce)
	// counter at bytes 12..15 (big-endian); start at 1.
	var ks [16]byte
	for off := 0; off < len(in); off += 16 {
		counter := uint32(off/16) + 1
		binary.BigEndian.PutUint32(ctr[12:], counter)
		c.block.Encrypt(ks[:], ctr[:])
		end := off + 16
		if end > len(in) {
			end = len(in)
		}
		for i := off; i < end; i++ {
			out[i] = in[i] ^ ks[i-off]
		}
	}
}

// ctrEncryptTag encrypts the CBC-MAC tag with counter=0.
func (c *ccm) ctrEncryptTag(nonce, tag, out []byte) {
	var ctr [16]byte
	ctr[0] = byte(ccmL - 1)
	copy(ctr[1:1+ccmNonceSize], nonce)
	binary.BigEndian.PutUint32(ctr[12:], 0)
	var ks [16]byte
	c.block.Encrypt(ks[:], ctr[:])
	for i := 0; i < 16; i++ {
		out[i] = tag[i] ^ ks[i]
	}
}
