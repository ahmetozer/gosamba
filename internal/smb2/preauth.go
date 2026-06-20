package smb2

import "crypto/sha512"

// PreauthHash maintains the SMB 3.1.1 preauth integrity rolling hash.
// Per MS-SMB2 §3.1.4.4.1: H_n = SHA-512(H_{n-1} || msg_n), with H_0 = 64 zero bytes.
type PreauthHash struct {
	state [64]byte
}

// NewPreauthHash returns a tracker initialized to all-zero state.
func NewPreauthHash() *PreauthHash {
	return &PreauthHash{}
}

// Update folds one full SMB2 message (header + body) into the hash.
func (p *PreauthHash) Update(msg []byte) {
	h := sha512.New()
	h.Write(p.state[:])
	h.Write(msg)
	sum := h.Sum(nil)
	copy(p.state[:], sum)
}

// Sum returns a copy of the current 64-byte hash state.
func (p *PreauthHash) Sum() [64]byte {
	var out [64]byte
	copy(out[:], p.state[:])
	return out
}
