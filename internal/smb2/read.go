package smb2

import (
	"encoding/binary"
	"fmt"
)

type ReadRequest struct {
	Length        uint32
	Offset        uint64
	FileID        [16]byte
	MinimumCount  uint32
}

func DecodeReadRequest(body []byte) (ReadRequest, error) {
	if len(body) < 48 {
		return ReadRequest{}, fmt.Errorf("%w: READ body min 48", ErrShortBuffer)
	}
	if ss := binary.LittleEndian.Uint16(body[0:]); ss != 49 {
		return ReadRequest{}, fmt.Errorf("%w: READ StructureSize %d", ErrBadStructureSize, ss)
	}
	r := ReadRequest{
		Length:       binary.LittleEndian.Uint32(body[4:]),
		Offset:       binary.LittleEndian.Uint64(body[8:]),
		MinimumCount: binary.LittleEndian.Uint32(body[32:]),
	}
	copy(r.FileID[:], body[16:32])
	return r, nil
}

type ReadResponse struct {
	Data []byte
}

// EncodeReadResponse builds the body. DataOffset = 80 (header 64 + body fixed 16).
func EncodeReadResponse(r ReadResponse) []byte {
	const fixed = 16
	out := make([]byte, fixed+len(r.Data))
	binary.LittleEndian.PutUint16(out[0:], 17) // StructureSize
	const headerSize = 64
	out[2] = byte(headerSize + fixed)          // DataOffset (1 byte) — abs from header start
	binary.LittleEndian.PutUint32(out[4:], uint32(len(r.Data)))
	copy(out[fixed:], r.Data)
	return out
}
