package smb2

import (
	"encoding/binary"
	"fmt"
)

const (
	FsctlValidateNegotiateInfo uint32 = 0x00140204
	FsctlPipeTransceive        uint32 = 0x0011C017
	FsctlPipeWait              uint32 = 0x00110018
	FsctlDfsGetReferrals       uint32 = 0x00060194
	FsctlQueryNetworkIfaceInfo uint32 = 0x001401FC
	FsctlSrvCopyChunk          uint32 = 0x001440F2
	FsctlSrvRequestResumeKey   uint32 = 0x00140078
)

const IoctlIsFsctl uint32 = 0x00000001

type IoctlRequest struct {
	CtlCode     uint32
	FileID      [16]byte
	InputBuffer []byte
	Flags       uint32
}

func DecodeIoctlRequest(body []byte) (IoctlRequest, error) {
	if len(body) < 56 {
		return IoctlRequest{}, fmt.Errorf("%w: IOCTL body min 56", ErrShortBuffer)
	}
	if ss := binary.LittleEndian.Uint16(body[0:]); ss != 57 {
		return IoctlRequest{}, fmt.Errorf("%w: IOCTL StructureSize %d", ErrBadStructureSize, ss)
	}
	const headerSize = 64
	r := IoctlRequest{CtlCode: binary.LittleEndian.Uint32(body[4:])}
	copy(r.FileID[:], body[8:24])
	inOffAbs := binary.LittleEndian.Uint32(body[24:])
	inLen := binary.LittleEndian.Uint32(body[28:])
	r.Flags = binary.LittleEndian.Uint32(body[48:])
	if inLen > 0 {
		off := int(inOffAbs) - headerSize
		if off >= 0 && off+int(inLen) <= len(body) {
			r.InputBuffer = append([]byte(nil), body[off:off+int(inLen)]...)
		}
	}
	return r, nil
}

type IoctlResponse struct {
	CtlCode      uint32
	FileID       [16]byte
	OutputBuffer []byte
	Flags        uint32
}

func EncodeIoctlResponse(r IoctlResponse) []byte {
	const fixed = 48
	out := make([]byte, fixed+len(r.OutputBuffer))
	binary.LittleEndian.PutUint16(out[0:], 49) // StructureSize
	binary.LittleEndian.PutUint32(out[4:], r.CtlCode)
	copy(out[8:24], r.FileID[:])
	const headerSize = 64
	binary.LittleEndian.PutUint32(out[24:], uint32(headerSize+fixed)) // input offset
	// input length is 0 (we never echo input)
	binary.LittleEndian.PutUint32(out[32:], uint32(headerSize+fixed)) // output offset
	binary.LittleEndian.PutUint32(out[36:], uint32(len(r.OutputBuffer)))
	binary.LittleEndian.PutUint32(out[40:], r.Flags)
	copy(out[fixed:], r.OutputBuffer)
	return out
}
