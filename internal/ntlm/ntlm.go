// Package ntlm implements the NTLMSSP message types and NTLMv2 verification
// needed for SMB3 SESSION_SETUP. Pure crypto — no I/O, no logging.
package ntlm

// Signature is the 8-byte NTLMSSP message signature: "NTLMSSP\x00".
var Signature = [8]byte{'N', 'T', 'L', 'M', 'S', 'S', 'P', 0x00}

// Message types.
const (
	MessageTypeNegotiate    uint32 = 0x00000001
	MessageTypeChallenge    uint32 = 0x00000002
	MessageTypeAuthenticate uint32 = 0x00000003
)

// Negotiate flags (commonly-used subset).
const (
	NegotiateUnicode                 uint32 = 0x00000001
	NegotiateOEM                     uint32 = 0x00000002
	RequestTarget                    uint32 = 0x00000004
	NegotiateSign                    uint32 = 0x00000010
	NegotiateSeal                    uint32 = 0x00000020
	NegotiateLMKey                   uint32 = 0x00000080
	NegotiateNTLM                    uint32 = 0x00000200
	NegotiateAlwaysSign              uint32 = 0x00008000
	TargetTypeServer                 uint32 = 0x00020000
	NegotiateExtendedSessionSecurity uint32 = 0x00080000
	NegotiateTargetInfo              uint32 = 0x00800000
	NegotiateVersion                 uint32 = 0x02000000
	Negotiate128                     uint32 = 0x20000000
	NegotiateKeyExch                 uint32 = 0x40000000
	Negotiate56                      uint32 = 0x80000000
)

// AVID identifies an AV pair type.
type AVID uint16

const (
	AVEOL             AVID = 0x0000
	AVNbComputerName  AVID = 0x0001
	AVNbDomainName    AVID = 0x0002
	AVDnsComputerName AVID = 0x0003
	AVDnsDomainName   AVID = 0x0004
	AVDnsTreeName     AVID = 0x0005
	AVFlags           AVID = 0x0006
	AVTimestamp       AVID = 0x0007
	AVSingleHost      AVID = 0x0008
	AVTargetName      AVID = 0x0009
	AVChannelBindings AVID = 0x000A
)
