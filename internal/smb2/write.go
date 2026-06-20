package smb2

import (
	"encoding/binary"
	"fmt"
)

type WriteRequest struct {
	Length uint32
	Offset uint64
	FileID [16]byte
	Flags  uint32
	Data   []byte
}

func DecodeWriteRequest(body []byte) (WriteRequest, error) {
	if len(body) < 48 {
		return WriteRequest{}, fmt.Errorf("%w: WRITE body min 48", ErrShortBuffer)
	}
	if ss := binary.LittleEndian.Uint16(body[0:]); ss != 49 {
		return WriteRequest{}, fmt.Errorf("%w: WRITE StructureSize %d", ErrBadStructureSize, ss)
	}
	const headerSize = 64
	dataOffAbs := binary.LittleEndian.Uint16(body[2:])
	r := WriteRequest{
		Length: binary.LittleEndian.Uint32(body[4:]),
		Offset: binary.LittleEndian.Uint64(body[8:]),
		Flags:  binary.LittleEndian.Uint32(body[44:]),
	}
	copy(r.FileID[:], body[16:32])
	if r.Length > 0 {
		off := int(dataOffAbs) - headerSize
		if off < 0 || off+int(r.Length) > len(body) {
			return WriteRequest{}, fmt.Errorf("%w: WRITE Buffer out of bounds", ErrShortBuffer)
		}
		r.Data = body[off : off+int(r.Length)]
	}
	return r, nil
}

type WriteResponse struct {
	Count uint32
}

func EncodeWriteResponse(r WriteResponse) []byte {
	out := make([]byte, 16)
	binary.LittleEndian.PutUint16(out[0:], 17)
	binary.LittleEndian.PutUint32(out[4:], r.Count)
	return out
}
