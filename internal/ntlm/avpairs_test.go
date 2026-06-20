package ntlm

import (
	"bytes"
	"testing"
)

func TestAVList_Roundtrip(t *testing.T) {
	in := []AVPair{
		{ID: AVNbComputerName, Value: UTF16LE("GOSAMBA")},
		{ID: AVNbDomainName, Value: UTF16LE("WORKGROUP")},
		{ID: AVTimestamp, Value: []byte{1, 2, 3, 4, 5, 6, 7, 8}},
	}
	enc := EncodeAVList(in)
	out, err := DecodeAVList(enc)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != len(in) {
		t.Fatalf("got %d pairs, want %d", len(out), len(in))
	}
	for i := range in {
		if out[i].ID != in[i].ID || !bytes.Equal(out[i].Value, in[i].Value) {
			t.Errorf("pair %d mismatch", i)
		}
	}
}

func TestUTF16LE(t *testing.T) {
	got := UTF16LE("ABC")
	want := []byte{'A', 0, 'B', 0, 'C', 0}
	if !bytes.Equal(got, want) {
		t.Errorf("got %x, want %x", got, want)
	}
}
