package smb2

import (
	"bytes"
	"errors"
)

// NegotiateSecurityBlob is the SPNEGO NegTokenInit2 advertising NTLMSSP only.
// Hardcoded because we never offer Kerberos and the structure is fixed.
//
// ASN.1 layout (DER):
//
//	[APPLICATION 0] (length 28) {
//	  OID 1.3.6.1.5.5.2 (SPNEGO),
//	  [0] (length 18) NegTokenInit {
//	    SEQUENCE (length 16) {
//	      [0] mechTypes (length 14) SEQUENCE OF OID (length 12) {
//	        OID 1.3.6.1.4.1.311.2.2.10 (NTLMSSP)
//	      }
//	    }
//	  }
//	}
//
// Total: 30 bytes.
var NegotiateSecurityBlob = []byte{
	0x60, 0x1c,
	0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02,
	0xa0, 0x12,
	0x30, 0x10,
	0xa0, 0x0e,
	0x30, 0x0c,
	0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a,
}

// ntlmsspMagic is the start of every NTLMSSP message.
var ntlmsspMagic = []byte{'N', 'T', 'L', 'M', 'S', 'S', 'P', 0x00}

// UnwrapNTLM scans a SPNEGO blob for the embedded NTLMSSP message.
// Pragmatic shortcut: NTLMSSP signatures are unique enough for SESSION_SETUP.
func UnwrapNTLM(blob []byte) ([]byte, error) {
	idx := bytes.Index(blob, ntlmsspMagic)
	if idx < 0 {
		return nil, errors.New("smb2: NTLMSSP message not found in SPNEGO blob")
	}
	return blob[idx:], nil
}

// SPNEGOState identifies negTokenResp.negState.
type SPNEGOState byte

const (
	SPNEGOAcceptCompleted  SPNEGOState = 0x00
	SPNEGOAcceptIncomplete SPNEGOState = 0x01
)

// ntlmsspOID is the DER-encoded NTLMSSP object identifier (1.3.6.1.4.1.311.2.2.10).
var ntlmsspOID = []byte{0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a}

// WrapNTLMResp builds a SPNEGO negTokenResp containing the NTLM payload.
// includeSupportedMech: set to true on the first response (Type 2 / challenge);
// omit on subsequent (acceptCompleted) responses.
func WrapNTLMResp(state SPNEGOState, ntlm []byte) []byte {
	includeSupportedMech := state == SPNEGOAcceptIncomplete

	negStateBytes := wrapTLV(0x0a, []byte{byte(state)})
	seqContents := wrapTLV(0xa0, negStateBytes)
	if includeSupportedMech {
		// supportedMech [1] OID = NTLMSSP
		seqContents = append(seqContents, wrapTLV(0xa1, ntlmsspOID)...)
	}
	if len(ntlm) > 0 {
		innerOctet := wrapTLV(0x04, ntlm)
		respToken := wrapTLV(0xa2, innerOctet)
		seqContents = append(seqContents, respToken...)
	}
	seq := wrapTLV(0x30, seqContents)
	return wrapTLV(0xa1, seq)
}

func wrapTLV(tag byte, content []byte) []byte {
	out := []byte{tag}
	switch {
	case len(content) < 0x80:
		out = append(out, byte(len(content)))
	case len(content) < 0x100:
		out = append(out, 0x81, byte(len(content)))
	case len(content) < 0x10000:
		out = append(out, 0x82, byte(len(content)>>8), byte(len(content)))
	default:
		out = append(out, 0x83, byte(len(content)>>16), byte(len(content)>>8), byte(len(content)))
	}
	out = append(out, content...)
	return out
}
