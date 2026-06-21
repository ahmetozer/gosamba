package smb2

import (
	"encoding/binary"
	"fmt"
)

// Lock flag bits (MS-SMB2 §2.2.26.1 SMB2_LOCK_ELEMENT Flags).
const (
	LockFlagSharedLock      uint32 = 0x00000001 // SMB2_LOCKFLAG_SHARED_LOCK
	LockFlagExclusiveLock   uint32 = 0x00000002 // SMB2_LOCKFLAG_EXCLUSIVE_LOCK
	LockFlagUnlock          uint32 = 0x00000004 // SMB2_LOCKFLAG_UNLOCK
	LockFlagFailImmediately uint32 = 0x00000010 // SMB2_LOCKFLAG_FAIL_IMMEDIATELY
)

// LockElement is one entry in an SMB2 LOCK_REQUEST (MS-SMB2 §2.2.26.1).
// Each element is 24 bytes: Offset(8)+Length(8)+Flags(4)+Reserved(4).
type LockElement struct {
	Offset uint64
	Length uint64
	Flags  uint32
}

// LockRequest is the decoded SMB2 LOCK_REQUEST (MS-SMB2 §2.2.26).
// StructureSize=48, LockCount(2), LockSequenceNumber/Index(4), FileId(16),
// followed by LockCount×LockElement.
type LockRequest struct {
	LockSequenceIndex uint32 // LockSequenceNumber (bits 31:4) | LockSequenceIndex (bits 3:0)
	FileID            [16]byte
	Locks             []LockElement
}

// DecodeLockRequest parses the body of an SMB2 LOCK request.
// The body starts immediately after the 64-byte SMB2 header.
func DecodeLockRequest(body []byte) (LockRequest, error) {
	// Fixed portion is 48 bytes (StructureSize=2, LockCount=2,
	// LockSequenceNumber/Index=4, FileId=16; remaining 24 bytes align the
	// structure to 48 total per MS-SMB2 §2.2.26).
	if len(body) < 48 {
		return LockRequest{}, fmt.Errorf("%w: LOCK body min 48 bytes, got %d", ErrShortBuffer, len(body))
	}
	ss := binary.LittleEndian.Uint16(body[0:])
	if ss != 48 {
		return LockRequest{}, fmt.Errorf("%w: LOCK StructureSize %d", ErrBadStructureSize, ss)
	}

	lockCount := int(binary.LittleEndian.Uint16(body[2:]))
	seqNumIdx := binary.LittleEndian.Uint32(body[4:])
	var fileID [16]byte
	copy(fileID[:], body[8:24])

	// MS-SMB2 §3.3.5.14: LockCount MUST be >= 1.
	if lockCount == 0 {
		return LockRequest{}, fmt.Errorf("%w: LOCK LockCount must be >= 1", ErrInvalidParameter)
	}

	// Each LockElement is 24 bytes; the array starts at offset 24 (immediately
	// after StructureSize(2)+LockCount(2)+LockSequenceNumber/Index(4)+FileId(16)).
	need := 24 + lockCount*24
	if len(body) < need {
		return LockRequest{}, fmt.Errorf("%w: LOCK body too short for %d elements (need %d, got %d)",
			ErrShortBuffer, lockCount, need, len(body))
	}

	locks := make([]LockElement, lockCount)
	for i := 0; i < lockCount; i++ {
		base := 24 + i*24
		locks[i] = LockElement{
			Offset: binary.LittleEndian.Uint64(body[base:]),
			Length: binary.LittleEndian.Uint64(body[base+8:]),
			Flags:  binary.LittleEndian.Uint32(body[base+16:]),
		}
	}

	return LockRequest{
		LockSequenceIndex: seqNumIdx,
		FileID:            fileID,
		Locks:             locks,
	}, nil
}

// EncodeLockResponse encodes an SMB2 LOCK_RESPONSE (MS-SMB2 §2.2.27).
// The response is fixed: StructureSize(2)=4, Reserved(2)=0.
func EncodeLockResponse() []byte {
	out := make([]byte, 4)
	binary.LittleEndian.PutUint16(out[0:], 4) // StructureSize
	// Reserved at [2:4] is implicitly zero
	return out
}
