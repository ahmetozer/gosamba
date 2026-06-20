package parent

import "encoding/binary"

// minimalSelfRelativeSD builds a self-relative SECURITY_DESCRIPTOR with:
//   - Owner SID = LocalSystem (S-1-5-18)
//   - Group SID = LocalSystem
//   - DACL with one ACE: AccessAllowed for Everyone (S-1-1-0), GENERIC_ALL.
//
// This is what most clients (incl. iPad Files / macOS Finder) accept as a
// boring "you can do anything" SD when they ask InfoTypeSecurity.
func minimalSelfRelativeSD() []byte {
	// SIDs.
	systemSID := []byte{
		0x01,             // Revision
		0x01,             // SubAuthorityCount
		0, 0, 0, 0, 0, 5, // IdentifierAuthority NT_AUTHORITY (5)
		18, 0, 0, 0, // SubAuthority[0] = 18
	}
	worldSID := []byte{
		0x01,             // Revision
		0x01,             // SubAuthorityCount
		0, 0, 0, 0, 0, 1, // IdentifierAuthority WORLD (1)
		0, 0, 0, 0, // SubAuthority[0] = 0
	}

	// One ACE: AccessAllowed (0x00), flags 0, size = 8 + len(SID),
	// AccessMask = GENERIC_ALL.
	aceSize := 8 + len(worldSID)
	ace := make([]byte, aceSize)
	ace[0] = 0x00 // ACCESS_ALLOWED_ACE_TYPE
	ace[1] = 0x00
	binary.LittleEndian.PutUint16(ace[2:], uint16(aceSize))
	binary.LittleEndian.PutUint32(ace[4:], 0x10000000) // GENERIC_ALL
	copy(ace[8:], worldSID)

	// DACL: AclRevision=2, Sbz1=0, AclSize=8+len(ACEs), AceCount, Sbz2=0.
	aclSize := 8 + aceSize
	dacl := make([]byte, aclSize)
	dacl[0] = 2
	binary.LittleEndian.PutUint16(dacl[2:], uint16(aclSize))
	binary.LittleEndian.PutUint16(dacl[4:], 1) // AceCount
	copy(dacl[8:], ace)

	// SD header (20 bytes) + Owner + Group + DACL.
	const sdHdr = 20
	sd := make([]byte, sdHdr+len(systemSID)+len(systemSID)+aclSize)
	sd[0] = 0x01           // Revision
	sd[1] = 0x00           // Sbz1
	control := uint16(0x8000 | 0x0004) // SE_SELF_RELATIVE | SE_DACL_PRESENT
	binary.LittleEndian.PutUint16(sd[2:], control)
	off := uint32(sdHdr)
	binary.LittleEndian.PutUint32(sd[4:], off) // Owner
	copy(sd[off:], systemSID)
	off += uint32(len(systemSID))
	binary.LittleEndian.PutUint32(sd[8:], off) // Group
	copy(sd[off:], systemSID)
	off += uint32(len(systemSID))
	binary.LittleEndian.PutUint32(sd[12:], 0)  // SACL
	binary.LittleEndian.PutUint32(sd[16:], off) // DACL
	copy(sd[off:], dacl)
	return sd
}
