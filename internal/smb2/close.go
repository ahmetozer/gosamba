package smb2

import (
	"encoding/binary"
	"fmt"
)

const CloseFlagPostQueryAttrib uint16 = 0x0001

type CloseRequest struct {
	Flags  uint16
	FileID [16]byte
}

func DecodeCloseRequest(body []byte) (CloseRequest, error) {
	if len(body) < 24 {
		return CloseRequest{}, fmt.Errorf("%w: CLOSE body min 24", ErrShortBuffer)
	}
	if ss := binary.LittleEndian.Uint16(body[0:]); ss != 24 {
		return CloseRequest{}, fmt.Errorf("%w: CLOSE StructureSize %d", ErrBadStructureSize, ss)
	}
	r := CloseRequest{Flags: binary.LittleEndian.Uint16(body[2:])}
	copy(r.FileID[:], body[8:24])
	return r, nil
}

type CloseResponse struct {
	Flags          uint16
	CreationTime   uint64
	LastAccessTime uint64
	LastWriteTime  uint64
	ChangeTime     uint64
	AllocationSize uint64
	EndOfFile      uint64
	FileAttributes uint32
}

func EncodeCloseResponse(r CloseResponse) []byte {
	out := make([]byte, 60)
	binary.LittleEndian.PutUint16(out[0:], 60) // StructureSize
	binary.LittleEndian.PutUint16(out[2:], r.Flags)
	binary.LittleEndian.PutUint64(out[8:], r.CreationTime)
	binary.LittleEndian.PutUint64(out[16:], r.LastAccessTime)
	binary.LittleEndian.PutUint64(out[24:], r.LastWriteTime)
	binary.LittleEndian.PutUint64(out[32:], r.ChangeTime)
	binary.LittleEndian.PutUint64(out[40:], r.AllocationSize)
	binary.LittleEndian.PutUint64(out[48:], r.EndOfFile)
	binary.LittleEndian.PutUint32(out[56:], r.FileAttributes)
	return out
}
