package smb2

import "testing"

func TestNegotiateSecurityBlob_Length(t *testing.T) {
	if len(NegotiateSecurityBlob) != 30 {
		t.Errorf("expected 30 bytes, got %d", len(NegotiateSecurityBlob))
	}
}

func TestNegotiateSecurityBlob_StartsWithSpnegoApp0(t *testing.T) {
	// 0x60 = [APPLICATION 0] tag, 0x1c = length 28 (the rest of the blob).
	if NegotiateSecurityBlob[0] != 0x60 || NegotiateSecurityBlob[1] != 0x1c {
		t.Errorf("bad header: %x %x", NegotiateSecurityBlob[0], NegotiateSecurityBlob[1])
	}
}

func TestNegotiateSecurityBlob_ContainsNTLMSSPOid(t *testing.T) {
	want := []byte{0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a}
	found := false
	for i := 0; i+len(want) <= len(NegotiateSecurityBlob); i++ {
		match := true
		for j := range want {
			if NegotiateSecurityBlob[i+j] != want[j] {
				match = false
				break
			}
		}
		if match {
			found = true
			break
		}
	}
	if !found {
		t.Error("NTLMSSP OID not found in blob")
	}
}
