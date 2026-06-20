package smb2

import (
	"encoding/binary"
	"testing"
)

// buildLockBody crafts a LOCK_REQUEST body (MS-SMB2 §2.2.26) for testing.
// StructureSize=48, LockCount, LockSequenceNumber/Index, FileId(16),
// then LockCount × SMB2_LOCK_ELEMENT{Offset(8),Length(8),Flags(4),Reserved(4)}.
func buildLockBody(lockCount uint16, fileID [16]byte, elements []LockElement) []byte {
	// The fixed portion of the LOCK body (MS-SMB2 §2.2.26) is 24 bytes:
	//   StructureSize(2) + LockCount(2) + LockSequenceNumber/Index(4) + FileId(16) = 24
	// Lock elements begin immediately at offset 24; each element is 24 bytes.
	buf := make([]byte, 24+len(elements)*24)
	binary.LittleEndian.PutUint16(buf[0:], 48) // StructureSize (always 48 per spec)
	binary.LittleEndian.PutUint16(buf[2:], lockCount)
	binary.LittleEndian.PutUint32(buf[4:], 0) // LockSequenceNumber/Index
	copy(buf[8:], fileID[:])                  // FileId (16 bytes at offset 8)
	for i, el := range elements {
		base := 24 + i*24
		binary.LittleEndian.PutUint64(buf[base:], el.Offset)
		binary.LittleEndian.PutUint64(buf[base+8:], el.Length)
		binary.LittleEndian.PutUint32(buf[base+16:], el.Flags)
		// Reserved at base+20 is zero
	}
	return buf
}

func TestDecodeLockRequest_SingleExclusiveLock(t *testing.T) {
	fid := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	elements := []LockElement{
		{Offset: 0x1000, Length: 0x200, Flags: LockFlagExclusiveLock},
	}
	body := buildLockBody(1, fid, elements)

	req, err := DecodeLockRequest(body)
	if err != nil {
		t.Fatalf("DecodeLockRequest: unexpected error: %v", err)
	}
	if req.FileID != fid {
		t.Errorf("FileID mismatch: got %v, want %v", req.FileID, fid)
	}
	if len(req.Locks) != 1 {
		t.Fatalf("expected 1 lock element, got %d", len(req.Locks))
	}
	el := req.Locks[0]
	if el.Offset != 0x1000 {
		t.Errorf("Offset: got 0x%x, want 0x1000", el.Offset)
	}
	if el.Length != 0x200 {
		t.Errorf("Length: got 0x%x, want 0x200", el.Length)
	}
	if el.Flags != LockFlagExclusiveLock {
		t.Errorf("Flags: got 0x%x, want 0x%x", el.Flags, LockFlagExclusiveLock)
	}
}

func TestDecodeLockRequest_MultipleElements(t *testing.T) {
	fid := [16]byte{0xAA}
	elements := []LockElement{
		{Offset: 0, Length: 100, Flags: LockFlagSharedLock},
		{Offset: 200, Length: 50, Flags: LockFlagUnlock},
		{Offset: 300, Length: 10, Flags: LockFlagExclusiveLock | LockFlagFailImmediately},
	}
	body := buildLockBody(3, fid, elements)

	req, err := DecodeLockRequest(body)
	if err != nil {
		t.Fatalf("DecodeLockRequest: unexpected error: %v", err)
	}
	if len(req.Locks) != 3 {
		t.Fatalf("expected 3 lock elements, got %d", len(req.Locks))
	}
	if req.Locks[0].Flags != LockFlagSharedLock {
		t.Errorf("element 0 flags: got 0x%x, want SharedLock", req.Locks[0].Flags)
	}
	if req.Locks[1].Flags != LockFlagUnlock {
		t.Errorf("element 1 flags: got 0x%x, want Unlock", req.Locks[1].Flags)
	}
	want2 := LockFlagExclusiveLock | LockFlagFailImmediately
	if req.Locks[2].Flags != want2 {
		t.Errorf("element 2 flags: got 0x%x, want 0x%x", req.Locks[2].Flags, want2)
	}
}

func TestDecodeLockRequest_TooShort(t *testing.T) {
	_, err := DecodeLockRequest([]byte{0x30, 0x00, 0x01}) // truncated
	if err == nil {
		t.Fatal("expected error for too-short body, got nil")
	}
}

func TestDecodeLockRequest_BadStructureSize(t *testing.T) {
	fid := [16]byte{}
	body := buildLockBody(1, fid, []LockElement{{Offset: 0, Length: 10, Flags: LockFlagExclusiveLock}})
	binary.LittleEndian.PutUint16(body[0:], 99) // wrong StructureSize
	_, err := DecodeLockRequest(body)
	if err == nil {
		t.Fatal("expected error for bad StructureSize, got nil")
	}
}

func TestDecodeLockRequest_LockCountZero(t *testing.T) {
	fid := [16]byte{}
	// Build a valid 24-byte header but with LockCount=0 — decoder must reject it.
	body := buildLockBody(1, fid, []LockElement{{Offset: 0, Length: 10, Flags: LockFlagExclusiveLock}})
	binary.LittleEndian.PutUint16(body[2:], 0) // overwrite LockCount → 0
	_, err := DecodeLockRequest(body)
	if err == nil {
		t.Fatal("expected error for LockCount==0, got nil")
	}
}

// TestDecodeLockRequest_HardcodedBytes verifies the decode offset using a
// hand-crafted 48-byte wire buffer.  This test is independent of the encoder:
// it catches any mismatch between where the encoder writes and where the
// decoder reads (both previously agreed on the WRONG offset 48 instead of 24).
//
// Wire layout (all little-endian, per MS-SMB2 §2.2.26):
//
//	[0:2]   StructureSize = 48   → 0x30 0x00
//	[2:4]   LockCount = 1        → 0x01 0x00
//	[4:8]   LockSeqNum/Idx = 0   → 0x00 0x00 0x00 0x00
//	[8:24]  FileId               → 0xAA 0xBB 0x00 … (16 bytes)
//	[24:32] LockElement.Offset   → 0x00 0x10 0x00 … = 0x1000
//	[32:40] LockElement.Length   → 0x00 0x02 0x00 … = 0x0200
//	[40:44] LockElement.Flags    → 0x02 0x00 0x00 0x00 = ExclusiveLock
//	[44:48] LockElement.Reserved → 0x00 0x00 0x00 0x00
func TestDecodeLockRequest_HardcodedBytes(t *testing.T) {
	wire := [48]byte{
		// [0:2] StructureSize = 48 (0x0030)
		0x30, 0x00,
		// [2:4] LockCount = 1
		0x01, 0x00,
		// [4:8] LockSequenceNumber/Index = 0
		0x00, 0x00, 0x00, 0x00,
		// [8:24] FileId — first byte 0xAA, second 0xBB, rest zero
		0xAA, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// [24:32] LockElement.Offset = 0x0000_0000_0000_1000
		0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// [32:40] LockElement.Length = 0x0000_0000_0000_0200
		0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// [40:44] LockElement.Flags = SMB2_LOCKFLAG_EXCLUSIVE_LOCK (0x00000002)
		0x02, 0x00, 0x00, 0x00,
		// [44:48] LockElement.Reserved = 0
		0x00, 0x00, 0x00, 0x00,
	}

	req, err := DecodeLockRequest(wire[:])
	if err != nil {
		t.Fatalf("DecodeLockRequest hardcoded: unexpected error: %v", err)
	}

	// Verify FileId.
	if req.FileID[0] != 0xAA || req.FileID[1] != 0xBB {
		t.Errorf("FileID: got %v, want [0xAA 0xBB ...]", req.FileID)
	}

	// Verify exactly one element was decoded.
	if len(req.Locks) != 1 {
		t.Fatalf("Locks: got %d elements, want 1", len(req.Locks))
	}

	el := req.Locks[0]
	if el.Offset != 0x1000 {
		t.Errorf("LockElement.Offset: got 0x%x, want 0x1000", el.Offset)
	}
	if el.Length != 0x200 {
		t.Errorf("LockElement.Length: got 0x%x, want 0x200", el.Length)
	}
	if el.Flags != LockFlagExclusiveLock {
		t.Errorf("LockElement.Flags: got 0x%x, want 0x%x (ExclusiveLock)", el.Flags, LockFlagExclusiveLock)
	}
}

func TestEncodeLockResponse(t *testing.T) {
	resp := EncodeLockResponse()
	// MS-SMB2 §2.2.27: StructureSize=4, Reserved=2 — total 4 bytes.
	if len(resp) != 4 {
		t.Fatalf("EncodeLockResponse: expected 4 bytes, got %d", len(resp))
	}
	if ss := binary.LittleEndian.Uint16(resp[0:]); ss != 4 {
		t.Errorf("StructureSize: got %d, want 4", ss)
	}
	if binary.LittleEndian.Uint16(resp[2:]) != 0 {
		t.Errorf("Reserved: got %d, want 0", binary.LittleEndian.Uint16(resp[2:]))
	}
}
