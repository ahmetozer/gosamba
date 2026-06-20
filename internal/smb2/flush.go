package smb2

import (
	"encoding/binary"
	"fmt"
)

type FlushRequest struct {
	FileID [16]byte
}

func DecodeFlushRequest(body []byte) (FlushRequest, error) {
	if len(body) < 24 {
		return FlushRequest{}, fmt.Errorf("%w: FLUSH body min 24", ErrShortBuffer)
	}
	if ss := binary.LittleEndian.Uint16(body[0:]); ss != 24 {
		return FlushRequest{}, fmt.Errorf("%w: FLUSH StructureSize %d", ErrBadStructureSize, ss)
	}
	var r FlushRequest
	copy(r.FileID[:], body[8:24])
	return r, nil
}

func EncodeFlushResponse() []byte {
	out := make([]byte, 4)
	binary.LittleEndian.PutUint16(out[0:], 4)
	return out
}
