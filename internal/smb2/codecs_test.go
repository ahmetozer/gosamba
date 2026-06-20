package smb2

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestTreeConnect_RequestRoundtrip(t *testing.T) {
	pathU16 := utf16le("\\\\GOSAMBA\\share")
	body := make([]byte, 8)
	binary.LittleEndian.PutUint16(body[0:], 9)
	binary.LittleEndian.PutUint16(body[4:], 64+8)
	binary.LittleEndian.PutUint16(body[6:], uint16(len(pathU16)))
	body = append(body, pathU16...)

	r, err := DecodeTreeConnectRequest(body)
	if err != nil {
		t.Fatal(err)
	}
	if r.Path != "\\\\GOSAMBA\\share" {
		t.Errorf("path: %q", r.Path)
	}
}

func utf16le(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for _, r := range s {
		out = append(out, byte(r), byte(uint32(r)>>8))
	}
	return out
}

func TestClose_Roundtrip(t *testing.T) {
	body := make([]byte, 24)
	binary.LittleEndian.PutUint16(body[0:], 24)
	body[8] = 0xAB
	r, err := DecodeCloseRequest(body)
	if err != nil {
		t.Fatal(err)
	}
	if r.FileID[0] != 0xAB {
		t.Errorf("file id: %x", r.FileID)
	}
	out := EncodeCloseResponse(CloseResponse{EndOfFile: 0xCAFE})
	if out[0] != 60 {
		t.Errorf("StructureSize: %d", out[0])
	}
	if binary.LittleEndian.Uint64(out[48:]) != 0xCAFE {
		t.Errorf("EndOfFile: %x", out[48:56])
	}
}

func TestRead_RequestAndResponse(t *testing.T) {
	body := make([]byte, 49)
	binary.LittleEndian.PutUint16(body[0:], 49)
	binary.LittleEndian.PutUint32(body[4:], 1024)
	binary.LittleEndian.PutUint64(body[8:], 4096)
	body[16] = 0x42
	r, err := DecodeReadRequest(body)
	if err != nil {
		t.Fatal(err)
	}
	if r.Length != 1024 || r.Offset != 4096 || r.FileID[0] != 0x42 {
		t.Errorf("read req decoded wrong: %+v", r)
	}
	resp := EncodeReadResponse(ReadResponse{Data: []byte("hello")})
	if !bytes.Equal(resp[16:21], []byte("hello")) {
		t.Errorf("data: %q", resp[16:21])
	}
	if resp[2] != 80 {
		t.Errorf("DataOffset: %d (want 80)", resp[2])
	}
}

func TestCreate_RequestRoundtrip(t *testing.T) {
	nameU16 := utf16le("foo.txt")
	body := make([]byte, 56)
	binary.LittleEndian.PutUint16(body[0:], 57)
	binary.LittleEndian.PutUint32(body[24:], AccessFileReadData) // DesiredAccess
	binary.LittleEndian.PutUint32(body[36:], CreateDispositionOpen)
	binary.LittleEndian.PutUint16(body[44:], 64+56) // NameOffset
	binary.LittleEndian.PutUint16(body[46:], uint16(len(nameU16)))
	body = append(body, nameU16...)

	r, err := DecodeCreateRequest(body)
	if err != nil {
		t.Fatal(err)
	}
	if r.Name != "foo.txt" {
		t.Errorf("name: %q", r.Name)
	}
	if r.DesiredAccess != AccessFileReadData {
		t.Errorf("access: %x", r.DesiredAccess)
	}
}

func TestQueryDirectory_Roundtrip(t *testing.T) {
	body := make([]byte, 32)
	binary.LittleEndian.PutUint16(body[0:], 33)
	body[2] = InfoFileIdBothDirectoryInformation
	body[3] = QueryDirRestartScans
	body[8] = 0xCC
	binary.LittleEndian.PutUint32(body[28:], 65536)

	r, err := DecodeQueryDirectoryRequest(body)
	if err != nil {
		t.Fatal(err)
	}
	if r.FileInformationClass != InfoFileIdBothDirectoryInformation {
		t.Errorf("info class: %x", r.FileInformationClass)
	}
	if r.OutputBufferLength != 65536 {
		t.Errorf("buf len: %d", r.OutputBufferLength)
	}

	out := EncodeQueryDirectoryResponse(QueryDirectoryResponse{Buffer: []byte("payload")})
	if binary.LittleEndian.Uint32(out[4:]) != 7 {
		t.Errorf("buf len: %d", binary.LittleEndian.Uint32(out[4:]))
	}
}

func TestIoctl_Roundtrip(t *testing.T) {
	body := make([]byte, 56)
	binary.LittleEndian.PutUint16(body[0:], 57)
	binary.LittleEndian.PutUint32(body[4:], FsctlValidateNegotiateInfo)
	binary.LittleEndian.PutUint32(body[48:], IoctlIsFsctl)

	r, err := DecodeIoctlRequest(body)
	if err != nil {
		t.Fatal(err)
	}
	if r.CtlCode != FsctlValidateNegotiateInfo {
		t.Errorf("ctl code: %x", r.CtlCode)
	}
	out := EncodeIoctlResponse(IoctlResponse{
		CtlCode:      FsctlValidateNegotiateInfo,
		OutputBuffer: []byte{0xDE, 0xAD, 0xBE, 0xEF},
	})
	if binary.LittleEndian.Uint32(out[36:]) != 4 {
		t.Errorf("output len: %d", binary.LittleEndian.Uint32(out[36:]))
	}
}
