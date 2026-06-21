package smb2

import (
	"encoding/binary"
	"fmt"
)

// File information classes used in SET_INFO requests.
const (
	FileBasicInformationSet        uint8 = 0x04
	FileRenameInformation          uint8 = 0x0A
	FileDispositionInformation     uint8 = 0x0D
	FileAllocationInformation      uint8 = 0x13
	FileEndOfFileInformation       uint8 = 0x14
	FileValidDataLengthInformation uint8 = 0x27
)

type SetInfoRequest struct {
	InfoType       uint8
	FileInfoClass  uint8
	BufferLength   uint32
	AdditionalInfo uint32
	FileID         [16]byte
	Buffer         []byte
}

func DecodeSetInfoRequest(body []byte) (SetInfoRequest, error) {
	if len(body) < 32 {
		return SetInfoRequest{}, fmt.Errorf("%w: SET_INFO body min 32", ErrShortBuffer)
	}
	if ss := binary.LittleEndian.Uint16(body[0:]); ss != 33 {
		return SetInfoRequest{}, fmt.Errorf("%w: SET_INFO StructureSize %d", ErrBadStructureSize, ss)
	}
	const headerSize = 64
	r := SetInfoRequest{
		InfoType:       body[2],
		FileInfoClass:  body[3],
		BufferLength:   binary.LittleEndian.Uint32(body[4:]),
		AdditionalInfo: binary.LittleEndian.Uint32(body[12:]),
	}
	bufOffAbs := binary.LittleEndian.Uint16(body[8:])
	copy(r.FileID[:], body[16:32])
	if r.BufferLength > 0 {
		off := int(bufOffAbs) - headerSize
		if off < 0 || off+int(r.BufferLength) > len(body) {
			return SetInfoRequest{}, fmt.Errorf("%w: SET_INFO buffer out of bounds", ErrShortBuffer)
		}
		r.Buffer = append([]byte(nil), body[off:off+int(r.BufferLength)]...)
	}
	return r, nil
}

func EncodeSetInfoResponse() []byte {
	out := make([]byte, 2)
	binary.LittleEndian.PutUint16(out[0:], 2)
	return out
}
