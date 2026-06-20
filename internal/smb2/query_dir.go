package smb2

import (
	"encoding/binary"
	"fmt"
)

// FileInformationClass values for QUERY_DIRECTORY.
const (
	InfoFileDirectoryInformation       uint8 = 0x01
	InfoFileFullDirectoryInformation   uint8 = 0x02
	InfoFileBothDirectoryInformation   uint8 = 0x03
	InfoFileNamesInformation           uint8 = 0x0C
	InfoFileIdBothDirectoryInformation uint8 = 0x25
	InfoFileIdFullDirectoryInformation uint8 = 0x26
)

// QueryDirectoryFlags.
const (
	QueryDirRestartScans      uint8 = 0x01
	QueryDirReturnSingleEntry uint8 = 0x02
	QueryDirIndexSpecified    uint8 = 0x04
	QueryDirReopen            uint8 = 0x10
)

type QueryDirectoryRequest struct {
	FileInformationClass uint8
	Flags                uint8
	FileIndex            uint32
	FileID               [16]byte
	OutputBufferLength   uint32
	FileName             string
}

func DecodeQueryDirectoryRequest(body []byte) (QueryDirectoryRequest, error) {
	if len(body) < 32 {
		return QueryDirectoryRequest{}, fmt.Errorf("%w: QUERY_DIRECTORY body min 32", ErrShortBuffer)
	}
	if ss := binary.LittleEndian.Uint16(body[0:]); ss != 33 {
		return QueryDirectoryRequest{}, fmt.Errorf("%w: QUERY_DIRECTORY StructureSize %d", ErrBadStructureSize, ss)
	}
	const headerSize = 64
	r := QueryDirectoryRequest{
		FileInformationClass: body[2],
		Flags:                body[3],
		FileIndex:            binary.LittleEndian.Uint32(body[4:]),
		OutputBufferLength:   binary.LittleEndian.Uint32(body[28:]),
	}
	copy(r.FileID[:], body[8:24])

	nameOffAbs := binary.LittleEndian.Uint16(body[24:])
	nameLen := binary.LittleEndian.Uint16(body[26:])
	if nameLen > 0 {
		off := int(nameOffAbs) - headerSize
		if off < 0 || off+int(nameLen) > len(body) {
			return QueryDirectoryRequest{}, fmt.Errorf("%w: QUERY_DIRECTORY filename out of bounds", ErrShortBuffer)
		}
		r.FileName = decodeUTF16LE(body[off : off+int(nameLen)])
	}
	return r, nil
}

type QueryDirectoryResponse struct {
	Buffer []byte // pre-encoded info-class records
}

func EncodeQueryDirectoryResponse(r QueryDirectoryResponse) []byte {
	const fixed = 8
	out := make([]byte, fixed+len(r.Buffer))
	binary.LittleEndian.PutUint16(out[0:], 9) // StructureSize
	const headerSize = 64
	if len(r.Buffer) > 0 {
		binary.LittleEndian.PutUint16(out[2:], uint16(headerSize+fixed))
		binary.LittleEndian.PutUint32(out[4:], uint32(len(r.Buffer)))
		copy(out[fixed:], r.Buffer)
	}
	return out
}
