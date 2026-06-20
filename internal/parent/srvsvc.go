package parent

import (
	"encoding/binary"
	"strings"

	"github.com/ahmetozer/gosamba/internal/config"
)

// Minimal DCE/RPC + SRVSVC implementation: enough to satisfy iPad / Finder /
// Windows Explorer share-list queries. We support exactly:
//
//   - Bind / AlterContext for the SRVSVC interface (4b324fc8-1670-01d3-1278-5a47bf6ee188 v3.0)
//   - NetShareEnumAll (opnum 15) returning level-1 (NAME + TYPE + REMARK)
//
// Other SRVSVC calls return a fault PDU; clients read that as "this server
// doesn't expose that method" and move on without retrying.

const (
	dcerpcVerMajor = 0x05
	dcerpcVerMinor = 0x00

	dcerpcPTypeRequest        = 0x00
	dcerpcPTypeResponse       = 0x02
	dcerpcPTypeFault          = 0x03
	dcerpcPTypeBind           = 0x0B
	dcerpcPTypeBindAck        = 0x0C
	dcerpcPTypeBindNak        = 0x0D
	dcerpcPTypeAlterContext   = 0x0E
	dcerpcPTypeAlterCtxResp   = 0x0F

	dcerpcPFCFirstFrag = 0x01
	dcerpcPFCLastFrag  = 0x02
	dcerpcPFCFlags     = dcerpcPFCFirstFrag | dcerpcPFCLastFrag

	dcerpcDREPLittle = 0x10

	srvsvcOpNetShareEnumAll = 15
)

// SRVSVC interface UUID (4b324fc8-1670-01d3-1278-5a47bf6ee188), version 3.0,
// little-endian on the wire.
var srvsvcUUID = [16]byte{
	0xC8, 0x4F, 0x32, 0x4B,
	0x70, 0x16,
	0xD3, 0x01,
	0x12, 0x78,
	0x5A, 0x47, 0xBF, 0x6E, 0xE1, 0x88,
}

// dcerpcWrap builds a generic DCE/RPC response/fault/bind-ack PDU framing
// the given body. authLen is always 0; we don't carry auth tokens.
//
// The DCE/RPC common header is exactly 16 bytes (C706 §12.6.3.1: rpc_vers(1)
// + rpc_vers_minor(1) + ptype(1) + pfc_flags(1) + drep(4) + frag_length(2)
// + auth_length(2) + call_id(4)). We previously allocated 24 + len(body)
// which left 8 trailing zero bytes inside the framed PDU — `frag_length`
// reported them as part of the PDU, so Apple's stricter DCE/RPC parser
// walked past `n_results` into junk and dropped the bind_ack. smbclient
// tolerated the slop because it reads `n_results` and stops, but Apple does
// not. Bug surfaced as iPad/macOS Finder closing the TCP connection right
// after our bind_ack reply.
func dcerpcWrap(ptype byte, callID uint32, body []byte) []byte {
	const dcerpcHeaderSize = 16
	out := make([]byte, dcerpcHeaderSize+len(body))
	out[0] = dcerpcVerMajor
	out[1] = dcerpcVerMinor
	out[2] = ptype
	out[3] = dcerpcPFCFlags
	out[4] = dcerpcDREPLittle
	binary.LittleEndian.PutUint16(out[8:], uint16(len(out)))
	binary.LittleEndian.PutUint16(out[10:], 0) // auth_length
	binary.LittleEndian.PutUint32(out[12:], callID)
	copy(out[dcerpcHeaderSize:], body)
	return out
}

// dcerpcHandle dispatches one PIPE_TRANSCEIVE input and returns the output
// stream the client should see. Returns nil if the input is malformed.
func dcerpcHandle(input []byte, shares []config.ShareConfig) []byte {
	if len(input) < 16 {
		return nil
	}
	ptype := input[2]
	callID := binary.LittleEndian.Uint32(input[12:16])

	switch ptype {
	case dcerpcPTypeBind, dcerpcPTypeAlterContext:
		return dcerpcBindAck(callID, input)
	case dcerpcPTypeRequest:
		return dcerpcRequest(callID, input, shares)
	}
	return dcerpcFault(callID, 0x1C010003) // nca_s_fault_unsupported_type
}

// ndrTransferSyntax is the standard NDR transfer-syntax UUID
// (8a885d04-1ceb-11c9-9fe8-08002b104860, version 2). NDR64 has a different
// UUID (71710533-beba-4937-8319-b5dbef9ccc36) and a different on-the-wire
// marshalling — we reject it.
var ndrTransferSyntax = [16]byte{
	0x04, 0x5D, 0x88, 0x8A,
	0xEB, 0x1C,
	0xC9, 0x11,
	0x9F, 0xE8,
	0x08, 0x00, 0x2B, 0x10, 0x48, 0x60,
}

// dcerpcBindAck builds a bind_ack. For each presentation context the client
// offered we ACCEPT iff NDR is among the offered transfer syntaxes; otherwise
// we REJECT with provider_rejection / transfer_syntaxes_not_supported. macOS's
// SMB client offers two contexts on SRVSVC — ctx 0 = NDR, ctx 1 = NDR64; if we
// accept ctx 1 the client marshals NetShareEnumAll in NDR64 which we don't
// speak, and Finder gives up with "couldn't list shares". Rejecting forces it
// onto ctx 0 (NDR), which we do speak.
func dcerpcBindAck(callID uint32, input []byte) []byte {
	const hdrLen = 16
	// Bind body: max_xmit(2) + max_recv(2) + assoc_group(4) + n_ctx(1) + 3 pad
	// = 12 bytes before the first p_cont_elem.
	if len(input) < hdrLen+12 {
		return dcerpcBindNakBytes(callID)
	}
	maxXmit := binary.LittleEndian.Uint16(input[hdrLen+0:])
	maxRecv := binary.LittleEndian.Uint16(input[hdrLen+2:])
	if maxXmit == 0 {
		maxXmit = 4280
	}
	if maxRecv == 0 {
		maxRecv = 4280
	}
	nCtx := int(input[hdrLen+8])

	// Walk each p_cont_elem and decide accept/reject per context.
	accepts := make([]bool, nCtx)
	off := hdrLen + 12 // first p_cont_elem
	for i := 0; i < nCtx; i++ {
		// p_cont_id(2) + n_transfer_syn(1) + reserved(1) + abstract_syntax(20) = 24 bytes,
		// then n_transfer_syn × p_syntax_id_t(20).
		if len(input) < off+24 {
			break
		}
		nTransfer := int(input[off+2])
		tsOff := off + 24
		for j := 0; j < nTransfer; j++ {
			if len(input) < tsOff+20 {
				break
			}
			var ts [16]byte
			copy(ts[:], input[tsOff:tsOff+16])
			if ts == ndrTransferSyntax {
				accepts[i] = true
				break
			}
			tsOff += 20
		}
		off += 24 + nTransfer*20
	}

	// Match samba's lowercase form. Spec says case-insensitive, but minimising
	// the surface that Apple's parser sees as "different" reduces risk.
	secAddr := []byte("\\pipe\\srvsvc\x00")
	body := make([]byte, 0, 64)
	var u16 [2]byte
	binary.LittleEndian.PutUint16(u16[:], maxXmit)
	body = append(body, u16[:]...)
	binary.LittleEndian.PutUint16(u16[:], maxRecv)
	body = append(body, u16[:]...)
	var u32 [4]byte
	binary.LittleEndian.PutUint32(u32[:], 0x12345678) // assoc_group_id
	body = append(body, u32[:]...)
	binary.LittleEndian.PutUint16(u16[:], uint16(len(secAddr)))
	body = append(body, u16[:]...)
	body = append(body, secAddr...)
	for len(body)%4 != 0 {
		body = append(body, 0)
	}
	body = append(body, byte(nCtx), 0, 0, 0) // n_results + 3 pad

	for i := 0; i < nCtx; i++ {
		if accepts[i] {
			// result=0 acceptance, reason=0, transfer_syntax=NDR, version=2
			body = append(body, 0, 0, 0, 0)
			body = append(body, ndrTransferSyntax[:]...)
			binary.LittleEndian.PutUint32(u32[:], 2)
			body = append(body, u32[:]...)
		} else {
			// result=2 provider_rejection, reason=2 transfer_syntaxes_not_supported,
			// transfer_syntax = all-zero, version = 0.
			body = append(body, 0x02, 0x00, 0x02, 0x00)
			body = append(body, make([]byte, 16)...)
			body = append(body, 0, 0, 0, 0)
		}
	}

	ptype := byte(dcerpcPTypeBindAck)
	if input[2] == dcerpcPTypeAlterContext {
		ptype = dcerpcPTypeAlterCtxResp
	}
	return dcerpcWrap(ptype, callID, body)
}

func dcerpcBindNakBytes(callID uint32) []byte {
	body := []byte{
		0x00, 0x00, // reject_reason = reason_not_specified
		0x00, // n_protocols = 0
	}
	return dcerpcWrap(dcerpcPTypeBindNak, callID, body)
}

func dcerpcFault(callID uint32, status uint32) []byte {
	// Response common fields: alloc_hint(4) + p_cont_id(2) + cancel_count(1) + reserved(1) + status(4) + 4 pad
	body := make([]byte, 16)
	binary.LittleEndian.PutUint32(body[0:], 0)
	binary.LittleEndian.PutUint16(body[4:], 0)
	binary.LittleEndian.PutUint32(body[8:], status)
	return dcerpcWrap(dcerpcPTypeFault, callID, body)
}

func dcerpcRequest(callID uint32, input []byte, shares []config.ShareConfig) []byte {
	// Request body (after 16-byte common header):
	// alloc_hint(4) + p_cont_id(2) + opnum(2) + stub
	if len(input) < 16+8 {
		return dcerpcFault(callID, 0x1C010002) // proto_error
	}
	opnum := binary.LittleEndian.Uint16(input[22:24])
	if opnum != srvsvcOpNetShareEnumAll {
		return dcerpcFault(callID, 0x1C010003) // unsupported
	}
	stub := buildNetShareEnumAllResponse(shares)
	// Response common fields: alloc_hint + p_cont_id + cancel_count + reserved + stub
	body := make([]byte, 8+len(stub))
	binary.LittleEndian.PutUint32(body[0:], uint32(len(stub)))
	binary.LittleEndian.PutUint16(body[4:], 0) // p_cont_id
	body[6] = 0
	body[7] = 0
	copy(body[8:], stub)
	return dcerpcWrap(dcerpcPTypeResponse, callID, body)
}

// buildNetShareEnumAllResponse marshals an NDR Level-1 SHARE_ENUM_STRUCT for
// the configured shares, plus the synthetic "IPC$" pipe entry. This is what
// Windows Explorer / iPad Files / Finder consume when listing shares.
func buildNetShareEnumAllResponse(shares []config.ShareConfig) []byte {
	type shareEntry struct {
		name    string
		shType  uint32 // 0=disk, 3=IPC
		comment string
	}
	entries := make([]shareEntry, 0, len(shares)+1)
	for _, s := range shares {
		entries = append(entries, shareEntry{name: s.Name, shType: 0, comment: ""})
	}
	// IPC$ is an administrative pipe share — STYPE_SPECIAL (0x80000000) | STYPE_IPC (0x3).
	// macOS smbfs validates the SPECIAL bit on the IPC entry and rejects the
	// entire NetShareEnumAll reply if it's missing — Linux smbclient ignores
	// the bit and succeeds either way, which is why this hid until iPad and
	// Finder testing exposed it.
	entries = append(entries, shareEntry{name: "IPC$", shType: 0x80000003, comment: "IPC Service"})

	// NDR layout for NetShareEnumAll level 1 response. The non-encapsulated
	// union srvsvc_NetShareCtr is selected by a [switch_is(level)] expression;
	// per MS-RPCE the discriminator is emitted on the wire BEFORE the union
	// arm even though it duplicates the struct's `level` field. Omitting the
	// duplicate is exactly what made Samba's parser report
	// "ndr_pull_srvsvc_NetShareCtr: Bad switch value 131072" — it was reading
	// our Ctr ref-ptr as the discriminator.
	//
	//   Level                    UINT32 = 1
	//   Switch (level dup)       UINT32 = 1
	//   Ctr ref ptr              UINT32
	//   Ctr.Count                UINT32 = N
	//   Ctr.Buffer ref ptr       UINT32
	//   MaxCount                 UINT32 = N
	//   For each share: name ref ptr (next), type, comment ref ptr (next)
	//   Then the conformant strings, in order: name, comment, name, comment...
	//   TotalEntries             UINT32 = N
	//   ResumeHandle ref ptr     UINT32
	//   ResumeHandle             UINT32 = 0
	//   ReturnCode               UINT32 = 0 (NERR_Success)

	var buf []byte
	w32 := func(v uint32) {
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], v)
		buf = append(buf, b[:]...)
	}
	pad4 := func() {
		for len(buf)%4 != 0 {
			buf = append(buf, 0)
		}
	}
	writeConfStr := func(s string) {
		// Conformant+varying UTF-16LE string: max_count(4) + offset(4) + actual_count(4)
		// + chars (UTF-16LE, NUL-terminated).
		runes := []uint16{}
		for _, r := range s {
			if r > 0xFFFF {
				r = 0xFFFD
			}
			runes = append(runes, uint16(r))
		}
		runes = append(runes, 0) // NUL
		count := uint32(len(runes))
		w32(count) // max_count
		w32(0)     // offset
		w32(count) // actual_count
		for _, r := range runes {
			var b [2]byte
			binary.LittleEndian.PutUint16(b[:], r)
			buf = append(buf, b[:]...)
		}
		pad4()
	}

	nextRef := uint32(0x00020000)
	allocRef := func() uint32 {
		r := nextRef
		nextRef += 4
		return r
	}

	w32(1)          // Level
	w32(1)          // Switch (NDR non-encapsulated-union discriminator copy)
	w32(allocRef()) // Ctr ref ptr
	w32(uint32(len(entries))) // Ctr.Count
	w32(allocRef())           // Ctr.Buffer ref ptr
	w32(uint32(len(entries))) // MaxCount

	// Array of share_info_1 structs (deferred-pointer style).
	for _, e := range entries {
		w32(allocRef()) // NetName ref ptr
		w32(e.shType)
		w32(allocRef()) // Remark ref ptr
		_ = e
	}
	// Now the deferred conformant strings for each entry.
	for _, e := range entries {
		writeConfStr(e.name)
		writeConfStr(strings.TrimSpace(e.comment))
	}

	// Per MS-SRVS / srvsvc.idl: srvsvc_NetShareEnumAll [out] params are
	// info_ctr first (handled above), then [out,ref] totalentries, then
	// [in,out,unique] resume_handle, then WERROR. The previous order put
	// ResumeHandle before TotalEntries — Windows tolerated it, macOS
	// demarshalled TotalEntries from the resume-handle slot, read non-zero
	// from the ReturnCode slot, and looped re-binding srvsvc forever.
	w32(uint32(len(entries))) // TotalEntries
	w32(allocRef())           // ResumeHandle ref ptr
	w32(0)                    // ResumeHandle value
	w32(0)                    // ReturnCode (NERR_Success)
	return buf
}
