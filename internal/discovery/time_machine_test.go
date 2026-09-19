package discovery

import (
	"golang.org/x/net/dns/dnsmessage"
	"net"
	"reflect"
	"strings"
	"testing"
)

func TestTimeMachineServices(t *testing.T) {
	opts := Options{TimeMachineShares: []string{"Backup Mac", "Бэкапы"}, Model: "MacSamba"}
	for _, q := range []struct {
		name string
		typ  dnsmessage.Type
	}{
		{adiskService, dnsmessage.TypePTR}, {"NAS." + adiskService, dnsmessage.TypeTXT},
		{"NAS." + adiskService, dnsmessage.TypeSRV}, {adiskService, dnsmessage.TypeALL},
		{enumerationService, dnsmessage.TypePTR}, {deviceService, dnsmessage.TypePTR},
	} {
		t.Run(q.name+q.typ.String(), func(t *testing.T) {
			raw, ok := buildResponse(dnsmessage.Message{Questions: []dnsmessage.Question{{Name: mustNewName(strings.ToUpper(q.name)), Type: q.typ, Class: dnsmessage.ClassINET}}}, "NAS", "nas", []net.IP{net.ParseIP("192.0.2.1")}, 1445, opts)
			if !ok {
				t.Fatal("query not matched")
			}
			var msg dnsmessage.Message
			if err := msg.Unpack(raw); err != nil {
				t.Fatal(err)
			}
			found := false
			for _, answer := range msg.Answers {
				if txt, ok := answer.Body.(*dnsmessage.TXTResource); ok && answer.Header.Name.String() == "NAS."+adiskService {
					found = true
					want := []string{"sys=waMa=0,adVF=0x100", "dk0=adVN=Backup Mac,adVF=0x82", "dk1=adVN=Бэкапы,adVF=0x82"}
					if !reflect.DeepEqual(txt.TXT, want) {
						t.Fatalf("TXT = %q", txt.TXT)
					}
				}
				if srv, ok := answer.Body.(*dnsmessage.SRVResource); ok && answer.Header.Name.String() == "NAS."+smbService && srv.Port != 1445 {
					t.Fatal("SMB port lost")
				}
			}
			if !found {
				t.Fatal("missing adisk TXT")
			}
		})
	}
}

func TestNoBackupSharesNoAdisk(t *testing.T) {
	q := dnsmessage.Message{Questions: []dnsmessage.Question{{Name: mustNewName(adiskService), Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET}}}
	if _, ok := buildResponse(q, "NAS", "nas", nil, 445); ok {
		t.Fatal("advertised adisk without backup shares")
	}
	q.Questions[0].Name = mustNewName(smbService)
	if _, ok := buildResponse(q, "NAS", "nas", nil, 445, Options{TimeMachineShares: []string{strings.Repeat("x", 256)}}); ok {
		t.Fatal("accepted overlong TXT")
	}
}
