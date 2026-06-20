package ntlm

import "testing"

func TestEncodeChallenge_BasicShape(t *testing.T) {
	m := ChallengeMessage{
		TargetName: "GOSAMBA",
		Flags:      NegotiateUnicode | NegotiateNTLM | NegotiateExtendedSessionSecurity | NegotiateTargetInfo | NegotiateAlwaysSign | RequestTarget | TargetTypeServer | Negotiate128,
		Challenge:  [8]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88},
		TargetInfo: []AVPair{
			{ID: AVNbComputerName, Value: UTF16LE("GOSAMBA")},
			{ID: AVNbDomainName, Value: UTF16LE("WORKGROUP")},
			{ID: AVTimestamp, Value: []byte{0, 0, 0, 0, 0, 0, 0, 0}},
		},
	}
	out := EncodeChallenge(m)
	if string(out[0:8]) != "NTLMSSP\x00" {
		t.Errorf("bad signature")
	}
	if out[8] != 0x02 {
		t.Errorf("bad type: %x", out[8])
	}
	if out[24] != 0x11 || out[31] != 0x88 {
		t.Errorf("challenge wrong: %x", out[24:32])
	}
}
