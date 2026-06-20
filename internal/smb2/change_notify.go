package smb2

import (
	"encoding/binary"
	"fmt"
)

// CHANGE_NOTIFY filter flags (CompletionFilter).
const (
	NotifyFileName       uint32 = 0x00000001
	NotifyDirName        uint32 = 0x00000002
	NotifyAttributes     uint32 = 0x00000004
	NotifySize           uint32 = 0x00000008
	NotifyLastWrite      uint32 = 0x00000010
	NotifyLastAccess     uint32 = 0x00000020
	NotifyCreation       uint32 = 0x00000040
	NotifyEa             uint32 = 0x00000080
	NotifySecurity       uint32 = 0x00000100
	NotifyStreamName     uint32 = 0x00000200
	NotifyStreamSize     uint32 = 0x00000400
	NotifyStreamWrite    uint32 = 0x00000800
)

// FileNotifyAction values for FILE_NOTIFY_INFORMATION records.
const (
	FileActionAdded            uint32 = 0x00000001
	FileActionRemoved          uint32 = 0x00000002
	FileActionModified         uint32 = 0x00000003
	FileActionRenamedOldName   uint32 = 0x00000004
	FileActionRenamedNewName   uint32 = 0x00000005
)

// ChangeNotifyFlags request flags.
const NotifyWatchTree uint16 = 0x0001

type ChangeNotifyRequest struct {
	Flags              uint16
	OutputBufferLength uint32
	FileID             [16]byte
	CompletionFilter   uint32
}

func DecodeChangeNotifyRequest(body []byte) (ChangeNotifyRequest, error) {
	if len(body) < 32 {
		return ChangeNotifyRequest{}, fmt.Errorf("%w: CHANGE_NOTIFY body min 32", ErrShortBuffer)
	}
	if ss := binary.LittleEndian.Uint16(body[0:]); ss != 32 {
		return ChangeNotifyRequest{}, fmt.Errorf("%w: CHANGE_NOTIFY StructureSize %d", ErrBadStructureSize, ss)
	}
	var r ChangeNotifyRequest
	r.Flags = binary.LittleEndian.Uint16(body[2:])
	r.OutputBufferLength = binary.LittleEndian.Uint32(body[4:])
	copy(r.FileID[:], body[8:24])
	r.CompletionFilter = binary.LittleEndian.Uint32(body[24:])
	return r, nil
}

// ChangeNotifyResponse body. Buffer is a list of FILE_NOTIFY_INFORMATION records.
type ChangeNotifyResponse struct {
	Buffer []byte
}

func EncodeChangeNotifyResponse(r ChangeNotifyResponse) []byte {
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

// EncodeFileNotifyInformation builds a FILE_NOTIFY_INFORMATION buffer from
// (action, path) pairs. Each record: NextEntryOffset(4) + Action(4) +
// FileNameLength(4) + FileName(variable, UTF-16LE).
func EncodeFileNotifyInformation(entries []NotifyEntry) []byte {
	if len(entries) == 0 {
		return nil
	}
	type encoded struct {
		rec []byte
	}
	out := make([]byte, 0, 64*len(entries))
	starts := make([]int, 0, len(entries))
	for _, e := range entries {
		nameU16 := utf16leNotify(e.Name)
		const fixed = 12
		rec := make([]byte, fixed+len(nameU16))
		binary.LittleEndian.PutUint32(rec[4:], e.Action)
		binary.LittleEndian.PutUint32(rec[8:], uint32(len(nameU16)))
		copy(rec[fixed:], nameU16)
		// Pad to 4-byte alignment
		if len(rec)%4 != 0 {
			rec = append(rec, make([]byte, 4-len(rec)%4)...)
		}
		starts = append(starts, len(out))
		out = append(out, rec...)
	}
	// Patch NextEntryOffset on all but last
	for i := 0; i < len(starts)-1; i++ {
		binary.LittleEndian.PutUint32(out[starts[i]:], uint32(starts[i+1]-starts[i]))
	}
	return out
}

type NotifyEntry struct {
	Action uint32
	Name   string // share-relative, backslash-separated
}

func utf16leNotify(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for _, r := range s {
		if r <= 0xFFFF {
			out = append(out, byte(r), byte(r>>8))
		} else {
			r -= 0x10000
			hi := 0xD800 + uint16(r>>10)
			lo := 0xDC00 + uint16(r&0x3FF)
			out = append(out, byte(hi), byte(hi>>8), byte(lo), byte(lo>>8))
		}
	}
	return out
}
