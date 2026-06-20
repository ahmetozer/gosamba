package smb2

import (
	"encoding/binary"
	"fmt"
)

// SessionSetupRequest is a decoded SESSION_SETUP request body.
type SessionSetupRequest struct {
	Flags             uint8
	SecurityMode      uint8
	Capabilities      uint32
	Channel           uint32
	PreviousSessionID uint64
	SecurityBuffer    []byte
}

func DecodeSessionSetupRequest(body []byte) (SessionSetupRequest, error) {
	if len(body) < 24 {
		return SessionSetupRequest{}, fmt.Errorf("%w: SESSION_SETUP body min 24", ErrShortBuffer)
	}
	if ss := binary.LittleEndian.Uint16(body[0:]); ss != 25 {
		return SessionSetupRequest{}, fmt.Errorf("%w: SESSION_SETUP StructureSize %d", ErrBadStructureSize, ss)
	}
	const headerSize = 64
	var r SessionSetupRequest
	r.Flags = body[2]
	r.SecurityMode = body[3]
	r.Capabilities = binary.LittleEndian.Uint32(body[4:])
	r.Channel = binary.LittleEndian.Uint32(body[8:])
	secOffAbs := binary.LittleEndian.Uint16(body[12:])
	secLen := binary.LittleEndian.Uint16(body[14:])
	r.PreviousSessionID = binary.LittleEndian.Uint64(body[16:])
	if secLen > 0 {
		bodyOff := int(secOffAbs) - headerSize
		if bodyOff < 0 || bodyOff+int(secLen) > len(body) {
			return SessionSetupRequest{}, fmt.Errorf("%w: SecurityBuffer out of bounds", ErrShortBuffer)
		}
		r.SecurityBuffer = append([]byte(nil), body[bodyOff:bodyOff+int(secLen)]...)
	}
	return r, nil
}

// SessionSetupResponse is the encoder input.
type SessionSetupResponse struct {
	SessionFlags   uint16
	SecurityBuffer []byte
}

// EncodeSessionSetupResponse builds the response body bytes (no SMB2 header).
func EncodeSessionSetupResponse(r SessionSetupResponse) []byte {
	const fixed = 8
	out := make([]byte, fixed+len(r.SecurityBuffer))
	out[0] = 9
	binary.LittleEndian.PutUint16(out[2:], r.SessionFlags)
	const headerSize = 64
	if len(r.SecurityBuffer) > 0 {
		binary.LittleEndian.PutUint16(out[4:], uint16(headerSize+fixed))
		binary.LittleEndian.PutUint16(out[6:], uint16(len(r.SecurityBuffer)))
		copy(out[fixed:], r.SecurityBuffer)
	}
	return out
}
