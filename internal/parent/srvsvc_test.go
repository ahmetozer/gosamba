package parent

import (
	"encoding/binary"
	"testing"

	"github.com/ahmetozer/gosamba/internal/config"
)

// TestDcerpcWrap_NoTrailingPadding pins the DCE/RPC PDU framing to the spec:
// 16-byte common header + body, with frag_length matching the actual PDU
// length (not 8 bytes longer). The 8-byte over-allocation we used to do made
// Apple's bind_ack parser walk past n_results into trailing zeros and drop
// the connection. Linux smbclient tolerated it; iPad and macOS Finder did not.
func TestDcerpcWrap_NoTrailingPadding(t *testing.T) {
	body := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	out := dcerpcWrap(dcerpcPTypeBindAck, 0xCAFE1234, body)

	wantLen := 16 + len(body)
	if len(out) != wantLen {
		t.Fatalf("PDU length: want %d (16 hdr + %d body), got %d", wantLen, len(body), len(out))
	}
	fragLen := binary.LittleEndian.Uint16(out[8:])
	if int(fragLen) != wantLen {
		t.Errorf("frag_length: want %d, got %d (must match actual PDU length)", wantLen, fragLen)
	}
	for i, b := range body {
		if out[16+i] != b {
			t.Errorf("body byte %d: want 0x%02x, got 0x%02x", i, b, out[16+i])
		}
	}
}

// TestBuildNetShareEnumAllResponse_FieldOrder pins the SRVSVC level-1 wire
// layout — Apple's NDR engine validates field order strictly.
func TestBuildNetShareEnumAllResponse_FieldOrder(t *testing.T) {
	shares := []config.ShareConfig{{Name: "test", Path: "/tmp/test"}}
	stub := buildNetShareEnumAllResponse(shares)

	rd := func(off int) uint32 { return binary.LittleEndian.Uint32(stub[off:]) }

	if got := rd(0); got != 1 {
		t.Errorf("Level @ 0: want 1, got %d", got)
	}
	if got := rd(4); got != 1 {
		t.Errorf("Switch (level dup) @ 4: want 1, got %d (NDR non-encapsulated-union discriminator)", got)
	}
	if got := rd(8); got == 0 {
		t.Errorf("Ctr ref ptr @ 8: want non-zero, got 0")
	}
	if got := rd(12); got != 2 {
		t.Errorf("Ctr.Count @ 12: want 2 (test + IPC$), got %d", got)
	}
	if got := rd(16); got == 0 {
		t.Errorf("Ctr.Buffer ref ptr @ 16: want non-zero, got 0")
	}
	if got := rd(20); got != 2 {
		t.Errorf("MaxCount @ 20: want 2, got %d", got)
	}

	end := len(stub)
	if rc := rd(end - 4); rc != 0 {
		t.Errorf("WERROR @ end-4: want 0 (NERR_Success), got 0x%x", rc)
	}
	if rh := rd(end - 8); rh != 0 {
		t.Errorf("ResumeHandle value @ end-8: want 0, got %d", rh)
	}
	if rhRef := rd(end - 12); rhRef == 0 {
		t.Errorf("ResumeHandle ref ptr @ end-12: want non-zero, got 0")
	}
	if total := rd(end - 16); total != 2 {
		t.Errorf("TotalEntries @ end-16: want 2, got %d", total)
	}
}

// TestDcerpcBindAck_RejectsNDR64 builds a synthetic two-context bind PDU
// (NDR + NDR64) and verifies the bind_ack accepts the first and rejects
// the second with provider_rejection / transfer_syntaxes_not_supported.
func TestDcerpcBindAck_RejectsNDR64(t *testing.T) {
	bind := make([]byte, 16)
	bind[0] = 0x05
	bind[2] = 0x0B // ptype = bind
	bind = append(bind,
		0xb8, 0x10, 0xb8, 0x10, 0, 0, 0, 0,
		2, 0, 0, 0,
	)
	// ctx 0: NDR
	bind = append(bind,
		0, 0, 1, 0,
		0xc8, 0x4f, 0x32, 0x4b, 0x70, 0x16, 0xd3, 0x01,
		0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88,
		3, 0, 0, 0,
		0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
		0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
		2, 0, 0, 0,
	)
	// ctx 1: NDR64
	bind = append(bind,
		1, 0, 1, 0,
		0xc8, 0x4f, 0x32, 0x4b, 0x70, 0x16, 0xd3, 0x01,
		0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88,
		3, 0, 0, 0,
		0x33, 0x05, 0x71, 0x71, 0xba, 0xbe, 0x37, 0x49,
		0x83, 0x19, 0xb5, 0xdb, 0xef, 0x9c, 0xcc, 0x36,
		1, 0, 0, 0,
	)

	ack := dcerpcBindAck(0xCAFE, bind)
	if len(ack) < 24 {
		t.Fatalf("bind_ack too short: %d bytes", len(ack))
	}
	body := ack[16:]
	// First result at body offset 28: max_xmit(2)+max_recv(2)+assoc_group(4)
	// = 8, sec_addr_len(2) + sec_addr("\PIPE\srvsvc\x00" = 13) + pad(1) = 16,
	// n_results(1) + 3 pad = 4 → 8+16+4 = 28.
	res0 := binary.LittleEndian.Uint16(body[28:])
	res1 := binary.LittleEndian.Uint16(body[28+24:])
	if res0 != 0 {
		t.Errorf("ctx 0 (NDR): want result=0 (acceptance), got %d", res0)
	}
	if res1 != 2 {
		t.Errorf("ctx 1 (NDR64): want result=2 (provider_rejection), got %d", res1)
	}
}
