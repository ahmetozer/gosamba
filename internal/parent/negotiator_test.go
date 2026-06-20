package parent

import (
	"bytes"
	"encoding/binary"
	"io"
	"log/slog"
	"testing"

	"github.com/ahmetozer/gosamba/internal/smb2"
	"github.com/ahmetozer/gosamba/internal/transport"
)

// rwPipe is an io.ReadWriter that reads from one buffer and writes to another.
type rwPipe struct {
	in  *bytes.Buffer
	out *bytes.Buffer
}

func (p *rwPipe) Read(b []byte) (int, error)  { return p.in.Read(b) }
func (p *rwPipe) Write(b []byte) (int, error) { return p.out.Write(b) }

// buildClientNegotiate311 builds an SMB2 NEGOTIATE request frame
// (header + body) advertising 3.1.1 + SHA-512 + AES-256-GCM.
func buildClientNegotiate311() []byte {
	hdr := make([]byte, smb2.HeaderSize)
	_ = smb2.EncodeHeader(hdr, smb2.Header{
		CreditCharge: 1,
		Command:      smb2.CommandNegotiate,
		MessageID:    0,
	})
	body := make([]byte, 0, 256)
	fixed := make([]byte, 36)
	fixed[0] = 36
	fixed[2] = 1
	fixed[4] = byte(smb2.NegotiateSigningEnabled)
	fixed[8] = byte(smb2.CapEncryption)
	for i := 0; i < 16; i++ {
		fixed[12+i] = 0xAA
	}
	binary.LittleEndian.PutUint32(fixed[28:], uint32(smb2.HeaderSize+40))
	binary.LittleEndian.PutUint16(fixed[32:], 2)
	body = append(body, fixed...)
	body = append(body, 0x11, 0x03)
	body = append(body, 0x00, 0x00)

	preauthData := append([]byte{0x01, 0x00, 0x20, 0x00, 0x01, 0x00}, bytes.Repeat([]byte{0xC1}, 32)...)
	preauthHdr := make([]byte, 8)
	binary.LittleEndian.PutUint16(preauthHdr[0:], uint16(smb2.CtxPreauthIntegrityCaps))
	binary.LittleEndian.PutUint16(preauthHdr[2:], uint16(len(preauthData)))
	body = append(body, preauthHdr...)
	body = append(body, preauthData...)
	for len(body)%8 != 0 {
		body = append(body, 0x00)
	}
	encData := []byte{0x01, 0x00, 0x04, 0x00}
	encHdr := make([]byte, 8)
	binary.LittleEndian.PutUint16(encHdr[0:], uint16(smb2.CtxEncryptionCaps))
	binary.LittleEndian.PutUint16(encHdr[2:], uint16(len(encData)))
	body = append(body, encHdr...)
	body = append(body, encData...)

	full := append(hdr, body...)
	return full
}

func TestNegotiate_HappyPath(t *testing.T) {
	in := &bytes.Buffer{}
	if err := transport.WriteFrame(in, buildClientNegotiate311()); err != nil {
		t.Fatal(err)
	}
	out := &bytes.Buffer{}
	pipe := &rwPipe{in: in, out: out}

	lg := slog.New(slog.NewTextHandler(io.Discard, nil))
	conn, err := Negotiate(pipe, NegotiatorOptions{RequireEncryption: true, RequireSigning: true}, lg)
	if err != nil {
		t.Fatalf("Negotiate: %v", err)
	}
	if conn.Selection.Dialect != smb2.Dialect311 {
		t.Errorf("dialect: %x", conn.Selection.Dialect)
	}
	if conn.Selection.Cipher != smb2.CipherAES256GCM {
		t.Errorf("cipher: %x", conn.Selection.Cipher)
	}

	resp, err := transport.ReadFrame(out, transport.MaxFrameSize)
	if err != nil {
		t.Fatal(err)
	}
	hdr, err := smb2.DecodeHeader(resp[:smb2.HeaderSize])
	if err != nil {
		t.Fatal(err)
	}
	if hdr.Command != smb2.CommandNegotiate {
		t.Errorf("response command: %s", hdr.Command)
	}
	if hdr.Flags&smb2.FlagServerToRedir == 0 {
		t.Errorf("response missing server-to-redir flag")
	}
	if hdr.Status != 0 {
		t.Errorf("response status: %x", hdr.Status)
	}
}

func TestNegotiate_NoCommonDialect(t *testing.T) {
	hdr := make([]byte, smb2.HeaderSize)
	_ = smb2.EncodeHeader(hdr, smb2.Header{Command: smb2.CommandNegotiate})
	body := make([]byte, 36)
	body[0] = 36
	body[2] = 1
	// dialect 0x9999 is fictional and not in SupportedDialects.
	body = append(body, 0x99, 0x99)

	frame := append(hdr, body...)
	in := &bytes.Buffer{}
	_ = transport.WriteFrame(in, frame)
	pipe := &rwPipe{in: in, out: &bytes.Buffer{}}

	_, err := Negotiate(pipe, NegotiatorOptions{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err == nil {
		t.Fatal("expected error for unsupported dialect")
	}
}
