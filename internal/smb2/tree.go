package smb2

import (
	"encoding/binary"
	"fmt"
)

// Share types.
const (
	ShareTypeDisk uint8 = 0x01
	ShareTypePipe uint8 = 0x02
)

// TreeConnectRequest is the body of TREE_CONNECT request.
type TreeConnectRequest struct {
	Flags uint16 // SMB 3.1.1 only
	Path  string
}

func DecodeTreeConnectRequest(body []byte) (TreeConnectRequest, error) {
	if len(body) < 8 {
		return TreeConnectRequest{}, fmt.Errorf("%w: TREE_CONNECT body min 8", ErrShortBuffer)
	}
	if ss := binary.LittleEndian.Uint16(body[0:]); ss != 9 {
		return TreeConnectRequest{}, fmt.Errorf("%w: TREE_CONNECT StructureSize %d", ErrBadStructureSize, ss)
	}
	const headerSize = 64
	flags := binary.LittleEndian.Uint16(body[2:])
	pathOffAbs := binary.LittleEndian.Uint16(body[4:])
	pathLen := binary.LittleEndian.Uint16(body[6:])
	bodyOff := int(pathOffAbs) - headerSize
	if pathLen == 0 {
		return TreeConnectRequest{Flags: flags}, nil
	}
	if bodyOff < 0 || bodyOff+int(pathLen) > len(body) {
		return TreeConnectRequest{}, fmt.Errorf("%w: TREE_CONNECT path out of bounds", ErrShortBuffer)
	}
	pathBytes := body[bodyOff : bodyOff+int(pathLen)]
	return TreeConnectRequest{Flags: flags, Path: decodeUTF16LE(pathBytes)}, nil
}

func decodeUTF16LE(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	r := make([]rune, 0, len(b)/2)
	for i := 0; i < len(b); i += 2 {
		r = append(r, rune(uint16(b[i])|uint16(b[i+1])<<8))
	}
	return string(r)
}

// TreeConnectResponse body.
type TreeConnectResponse struct {
	ShareType     uint8
	ShareFlags    uint32
	Capabilities  uint32
	MaximalAccess uint32
}

func EncodeTreeConnectResponse(r TreeConnectResponse) []byte {
	out := make([]byte, 16)
	binary.LittleEndian.PutUint16(out[0:], 16)
	out[2] = r.ShareType
	binary.LittleEndian.PutUint32(out[4:], r.ShareFlags)
	binary.LittleEndian.PutUint32(out[8:], r.Capabilities)
	binary.LittleEndian.PutUint32(out[12:], r.MaximalAccess)
	return out
}

// TreeDisconnectRequest body.
type TreeDisconnectRequest struct{}

func DecodeTreeDisconnectRequest(body []byte) (TreeDisconnectRequest, error) {
	if len(body) < 4 {
		return TreeDisconnectRequest{}, fmt.Errorf("%w: TREE_DISCONNECT body min 4", ErrShortBuffer)
	}
	if ss := binary.LittleEndian.Uint16(body[0:]); ss != 4 {
		return TreeDisconnectRequest{}, fmt.Errorf("%w: TREE_DISCONNECT StructureSize %d", ErrBadStructureSize, ss)
	}
	return TreeDisconnectRequest{}, nil
}

func EncodeTreeDisconnectResponse() []byte {
	return []byte{0x04, 0x00, 0x00, 0x00}
}
