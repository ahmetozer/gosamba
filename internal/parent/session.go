package parent

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	osuser "os/user"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/ahmetozer/gosamba/internal/config"
	"github.com/ahmetozer/gosamba/internal/ntlm"
	"github.com/ahmetozer/gosamba/internal/smb2"
	"github.com/ahmetozer/gosamba/internal/smb3"
	"github.com/ahmetozer/gosamba/internal/transport"
)

// Tree is one TREE_CONNECT'd share within a Session.
type Tree struct {
	ID    uint32
	Share config.ShareConfig
}

// Open is a single open file/dir handle within a Session.
type Open struct {
	FileID        [16]byte
	Path          string // OS-absolute path (the base file, even for streams)
	IsDir         bool
	IsPipe        bool     // virtual handle on IPC$ (srvsvc, lsarpc, etc.)
	PipeName      string   // e.g. "srvsvc" — set on IPC$ pipe opens
	File          *os.File // nil for dirs and streams
	Tree          *Tree
	DeleteOnClose bool

	// IsStream marks an ephemeral named-alternate-data-stream handle. macOS
	// uses NTFS stream syntax (foo.txt:com.apple.metadata:_kMDItemUserTags:$DATA)
	// to write extended attributes. Rather than persist a separate file per
	// xattr (which would litter the share with literal `:`-named files), we
	// accept reads/writes on a synthetic in-memory buffer and discard on
	// close — matching the existing "silently accept EA writes" pattern.
	IsStream   bool
	StreamName string
	streamBuf  []byte
	// streamWritten is set once the client WRITEs to this stream handle.
	// streamSynthetic marks a buffer we fabricated (e.g. an empty AFP_AfpInfo
	// blob) rather than loaded from disk; such a buffer is only flushed back to
	// an xattr if the client actually wrote to it, so a mere read doesn't
	// litter the file with a zeroed metadata stream.
	streamWritten   bool
	streamSynthetic bool

	// GrantedAccess is the access mask the CREATE actually granted on this
	// handle. Reported back via FileAccessInformation / FileAllInformation —
	// macOS reads this to decide whether to even attempt READ/WRITE/QUERY_DIR
	// on the handle.
	GrantedAccess uint32

	// Durable handle bookkeeping. When IsDurable is set, this Open is
	// registered in the connection's DurableTable under
	// (DurableClientGuid, DurableCreateGuid). A clean CLOSE removes the
	// entry; a dropped connection leaves it for reclaim until expiry.
	IsDurable         bool
	DurableClientGuid [16]byte
	DurableCreateGuid [16]byte

	// pipeOut buffers a queued DCE/RPC response that the next READ/IOCTL will
	// drain. Filled by handleWrite (transactional write+read pattern is used by
	// some clients).
	pipeOut []byte

	// Directory enumeration state (for repeated QUERY_DIRECTORY calls).
	dirEntries []os.DirEntry
	dirSent    int
	dirRestart bool
}

// Session holds per-SMB-session state once auth completes.
type Session struct {
	ID             uint64
	User           config.UserConfig
	IsGuest        bool
	SigningKey     []byte
	S2CCipherKey   []byte
	C2SCipherKey   []byte
	ApplicationKey []byte

	// Authenticated latches true once SESSION_SETUP completes successfully
	// (type-3 NTLM verified, or an accepted guest). Until then the session
	// exists only to carry the multi-leg NTLM handshake; the dispatcher must
	// refuse every non-SESSION_SETUP command on an unauthenticated session.
	Authenticated bool

	// gotEncrypted latches once the client has sent an encrypted frame.
	// We then reply encrypted for the rest of the session. It is read from
	// the CHANGE_NOTIFY async goroutine while the read loop may set it, so it
	// is accessed atomically.
	gotEncrypted atomic.Bool

	pendingChallenge [8]byte

	mu         sync.Mutex
	trees      map[uint32]*Tree
	opens      map[[16]byte]*Open
	nextTreeID atomic.Uint32
}

func (s *Session) initTables() {
	if s.trees == nil {
		s.trees = make(map[uint32]*Tree)
	}
	if s.opens == nil {
		s.opens = make(map[[16]byte]*Open)
	}
	if s.nextTreeID.Load() == 0 {
		s.nextTreeID.Store(1)
	}
}

// SetGotEncrypted latches that the client has sent at least one encrypted
// frame on this session. Safe to call concurrently with GotEncrypted.
func (s *Session) SetGotEncrypted() { s.gotEncrypted.Store(true) }

// GotEncrypted reports whether the client has sent an encrypted frame. It is
// read from the CHANGE_NOTIFY async goroutine and written by the read loop,
// so it is backed by an atomic.
func (s *Session) GotEncrypted() bool { return s.gotEncrypted.Load() }

func (s *Session) AddTree(share config.ShareConfig) *Tree {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initTables()
	t := &Tree{ID: s.nextTreeID.Add(1), Share: share}
	s.trees[t.ID] = t
	return t
}

func (s *Session) GetTree(id uint32) *Tree {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.trees[id]
}

func (s *Session) RemoveTree(id uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.trees, id)
}

// RemoveTreeAndOpens removes a tree and detaches every open belonging to it,
// returning those opens so the caller can release their locks and descriptors.
// TREE_DISCONNECT must not leave a share's file handles behind: MS-SMB2
// §3.3.5.9 requires the server to close them, and without it every fd stays
// open until the whole connection dies.
func (s *Session) RemoveTreeAndOpens(id uint32) []*Open {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.trees, id)
	var out []*Open
	for fid, o := range s.opens {
		if o.Tree != nil && o.Tree.ID == id {
			out = append(out, o)
			delete(s.opens, fid)
		}
	}
	return out
}

// TakeAllOpens removes and returns every open in the session, for LOGOFF or
// session teardown.
func (s *Session) TakeAllOpens() []*Open {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Open, 0, len(s.opens))
	for fid, o := range s.opens {
		out = append(out, o)
		delete(s.opens, fid)
	}
	s.trees = make(map[uint32]*Tree)
	return out
}

// OpenCount reports how many file handles the session currently holds.
func (s *Session) OpenCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.opens)
}

// TreeCount reports how many trees the session currently holds.
func (s *Session) TreeCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.trees)
}

func (s *Session) AddOpen(o *Open) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initTables()
	s.opens[o.FileID] = o
}

func (s *Session) GetOpen(id [16]byte) *Open {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.opens[id]
}

func (s *Session) RemoveOpen(id [16]byte) *Open {
	s.mu.Lock()
	defer s.mu.Unlock()
	o := s.opens[id]
	delete(s.opens, id)
	return o
}

// RangeOpens calls fn for each open currently in the session. The session lock
// is held during the iteration, so fn must not call any Session method that
// also acquires the lock.
func (s *Session) RangeOpens(fn func(*Open)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, o := range s.opens {
		fn(o)
	}
}

// SessionTable is the parent's in-memory session map.
type SessionTable struct {
	mu     sync.Mutex
	byID   map[uint64]*Session
	nextID atomic.Uint64
}

func NewSessionTable() *SessionTable {
	t := &SessionTable{byID: make(map[uint64]*Session)}
	t.nextID.Store(1)
	return t
}

func (t *SessionTable) New() *Session {
	id := t.nextID.Add(1)
	s := &Session{ID: id}
	t.mu.Lock()
	t.byID[id] = s
	t.mu.Unlock()
	return s
}

// Remove drops a session from the table, invalidating its SessionId. LOGOFF
// must do this: leaving the entry keeps the id usable for further commands.
func (t *SessionTable) Remove(id uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.byID, id)
}

func (t *SessionTable) Get(id uint64) *Session {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.byID[id]
}

// RangeSessions calls fn for each session in the table. The table lock is held
// during the iteration, so fn must not call SessionTable methods that also
// acquire the lock.
func (t *SessionTable) RangeSessions(fn func(*Session)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, s := range t.byID {
		fn(s)
	}
}

// SessionSetupHandler runs the NTLM exchange.
type SessionSetupHandler struct {
	Conn     *Connection
	Sessions *SessionTable
	Users    []config.UserConfig
	Shares   []config.ShareConfig
	Log      *slog.Logger
}

// hasGuestShare reports whether any configured share allows anonymous access.
func (h *SessionSetupHandler) hasGuestShare() bool {
	for _, s := range h.Shares {
		if s.GuestOK {
			return true
		}
	}
	return false
}

// guestSystemUser returns a UserConfig stand-in for the anonymous guest.
// SystemUID/GID resolve to "nobody" (typically uid 65534 on Linux).
func guestSystemUser() config.UserConfig {
	uid, gid := 65534, 65534
	if u, err := lookupGuestUser(); err == nil {
		uid, gid = u.UID, u.GID
	}
	return config.UserConfig{
		Name:        "guest",
		SystemUser:  "nobody",
		SystemUID:   uid,
		SystemGID:   gid,
		AllowShares: []string{"*"},
	}
}

type uidGid struct{ UID, GID int }

func lookupGuestUser() (uidGid, error) {
	u, err := osuser.Lookup("nobody")
	if err != nil {
		return uidGid{}, err
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	return uidGid{UID: uid, GID: gid}, nil
}

// HandleSessionSetup processes one SESSION_SETUP request and writes the response.
// The full request frame (header + body) is passed in for preauth folding.
func (h *SessionSetupHandler) HandleSessionSetup(rw io.ReadWriter, hdr smb2.Header, body, fullRequestFrame []byte) (*Session, error) {
	req, err := smb2.DecodeSessionSetupRequest(body)
	if err != nil {
		return nil, fmt.Errorf("decode session-setup: %w", err)
	}
	ntlmMsg, err := smb2.UnwrapNTLM(req.SecurityBuffer)
	if err != nil {
		return nil, err
	}
	if len(ntlmMsg) < 12 {
		return nil, errors.New("ntlm message too short")
	}
	msgType := uint32(ntlmMsg[8]) | uint32(ntlmMsg[9])<<8 | uint32(ntlmMsg[10])<<16 | uint32(ntlmMsg[11])<<24

	switch msgType {
	case ntlm.MessageTypeNegotiate:
		return h.handleType1(rw, hdr, ntlmMsg, fullRequestFrame)
	case ntlm.MessageTypeAuthenticate:
		return h.handleType3(rw, hdr, ntlmMsg, fullRequestFrame)
	default:
		return nil, fmt.Errorf("unexpected NTLM message type 0x%x", msgType)
	}
}

func (h *SessionSetupHandler) handleType1(rw io.ReadWriter, hdr smb2.Header, type1, requestFrame []byte) (*Session, error) {
	sess := h.Sessions.New()

	if _, err := rand.Read(sess.pendingChallenge[:]); err != nil {
		return nil, err
	}

	avPairs := []ntlm.AVPair{
		{ID: ntlm.AVNbComputerName, Value: ntlm.UTF16LE("GOSAMBA")},
		{ID: ntlm.AVNbDomainName, Value: ntlm.UTF16LE("WORKGROUP")},
		{ID: ntlm.AVDnsComputerName, Value: ntlm.UTF16LE("gosamba")},
		{ID: ntlm.AVDnsDomainName, Value: ntlm.UTF16LE("workgroup")},
		{ID: ntlm.AVTimestamp, Value: filetimeBytes()},
	}
	type2 := ntlm.EncodeChallenge(ntlm.ChallengeMessage{
		TargetName: "GOSAMBA",
		Flags: ntlm.NegotiateUnicode | ntlm.NegotiateNTLM | ntlm.NegotiateExtendedSessionSecurity |
			ntlm.NegotiateTargetInfo | ntlm.NegotiateAlwaysSign | ntlm.RequestTarget |
			ntlm.TargetTypeServer | ntlm.Negotiate128 | ntlm.Negotiate56 |
			ntlm.NegotiateKeyExch | ntlm.NegotiateVersion | ntlm.NegotiateSign,
		Challenge:  sess.pendingChallenge,
		TargetInfo: avPairs,
	})

	spnego := smb2.WrapNTLMResp(smb2.SPNEGOAcceptIncomplete, type2)

	respBody := smb2.EncodeSessionSetupResponse(smb2.SessionSetupResponse{
		SessionFlags:   0,
		SecurityBuffer: spnego,
	})
	respHdr := smb2.Header{
		CreditCharge:   hdr.CreditCharge,
		Status:         uint32(smb2.StatusMoreProcessingReq),
		Command:        smb2.CommandSessionSetup,
		CreditResponse: grantCredits(hdr.CreditCharge, hdr.CreditResponse),
		Flags:          smb2.FlagServerToRedir,
		MessageID:      hdr.MessageID,
		SessionID:      sess.ID,
	}
	full := make([]byte, smb2.HeaderSize+len(respBody))
	if err := smb2.EncodeHeader(full[:smb2.HeaderSize], respHdr); err != nil {
		return nil, err
	}
	copy(full[smb2.HeaderSize:], respBody)

	// Fold request and response into preauth (per MS-SMB2 §3.1.4.4.1).
	h.Conn.Preauth.Update(requestFrame)
	h.Conn.Preauth.Update(full)

	if err := transport.WriteFrame(rw, full); err != nil {
		return nil, err
	}
	return nil, nil
}

func (h *SessionSetupHandler) handleType3(rw io.ReadWriter, hdr smb2.Header, type3, requestFrame []byte) (*Session, error) {
	sess := h.Sessions.Get(hdr.SessionID)
	if sess == nil {
		return nil, fmt.Errorf("unknown session id %d", hdr.SessionID)
	}
	auth, err := ntlm.DecodeAuthenticate(type3)
	if err != nil {
		return nil, fmt.Errorf("decode AUTH: %w", err)
	}

	var user *config.UserConfig
	for i := range h.Users {
		if strings.EqualFold(h.Users[i].Name, auth.UserName) {
			user = &h.Users[i]
			break
		}
	}

	isGuest := false
	if user == nil {
		// Guest fallback: empty username or "GUEST", and at least one share allows it.
		if (auth.UserName == "" || strings.EqualFold(auth.UserName, "GUEST")) && h.hasGuestShare() {
			gu := guestSystemUser()
			user = &gu
			isGuest = true
		} else {
			return nil, h.failAuth(rw, hdr, fmt.Errorf("unknown user %q", auth.UserName))
		}
	}

	// Fold the type-3 request into the preauth chain only for 3.1.1 — pre-3.1.1
	// dialects don't use preauth integrity at all.
	dialect := h.Conn.Selection.Dialect
	if dialect == smb2.Dialect311 {
		h.Conn.Preauth.Update(requestFrame)
	}

	if !isGuest {
		sbk, err := ntlm.VerifyNTLMv2(user.NTHash, auth.UserName, auth.DomainName, sess.pendingChallenge, auth.NtResponse)
		if err != nil {
			return nil, h.failAuth(rw, hdr, fmt.Errorf("user %q: %w", auth.UserName, err))
		}

		// For NTLMv2 with NegotiateKeyExch, KeyExchangeKey = SessionBaseKey.
		sessionKey := sbk[:]
		if auth.Flags&ntlm.NegotiateKeyExch != 0 && len(auth.EncryptedRandomSessionKey) == 16 {
			sessionKey = make([]byte, 16)
			rc4xor(sbk[:], auth.EncryptedRandomSessionKey, sessionKey)
		}

		switch dialect {
		case smb2.Dialect311:
			preauth := h.Conn.Preauth.Sum()
			sess.SigningKey = smb3.KDF(sessionKey, []byte("SMBSigningKey\x00"), preauth[:], 128)
			sess.S2CCipherKey = smb3.KDF(sessionKey, []byte("SMBS2CCipherKey\x00"), preauth[:], 128)
			sess.C2SCipherKey = smb3.KDF(sessionKey, []byte("SMBC2SCipherKey\x00"), preauth[:], 128)
			sess.ApplicationKey = smb3.KDF(sessionKey, []byte("SMBAppKey\x00"), preauth[:], 128)
		case smb2.Dialect300, smb2.Dialect302:
			// 3.0 / 3.0.2 use fixed context strings instead of preauth.
			sess.SigningKey = smb3.KDF(sessionKey, []byte("SMB2AESCMAC\x00"), []byte("SmbSign\x00"), 128)
			sess.S2CCipherKey = smb3.KDF(sessionKey, []byte("SMB2AESCCM\x00"), []byte("ServerOut\x00"), 128)
			sess.C2SCipherKey = smb3.KDF(sessionKey, []byte("SMB2AESCCM\x00"), []byte("ServerIn \x00"), 128)
			sess.ApplicationKey = smb3.KDF(sessionKey, []byte("SMB2APP\x00"), []byte("SmbRpc\x00"), 128)
		default:
			// 2.0.2 / 2.1: Session.SigningKey = SessionKey (HMAC-SHA256 signing,
			// no SMB3 KDF). We store the 16-byte session key directly.
			sess.SigningKey = append([]byte(nil), sessionKey...)
		}
	}
	sess.User = *user
	sess.IsGuest = isGuest
	// Authentication is complete: the dispatcher may now serve commands on
	// this session. (Set before writing the response so a pipelined follow-up
	// request can never race ahead of the flag.)
	sess.Authenticated = true

	var sessFlags uint16
	if isGuest {
		sessFlags = 0x0001 // SMB2_SESSION_FLAG_IS_GUEST
	}
	spnego := smb2.WrapNTLMResp(smb2.SPNEGOAcceptCompleted, nil)
	respBody := smb2.EncodeSessionSetupResponse(smb2.SessionSetupResponse{
		SessionFlags:   sessFlags,
		SecurityBuffer: spnego,
	})
	hdrFlags := smb2.FlagServerToRedir
	if !isGuest {
		hdrFlags |= smb2.FlagSigned
	}
	respHdr := smb2.Header{
		CreditCharge:   hdr.CreditCharge,
		Status:         uint32(smb2.StatusSuccess),
		Command:        smb2.CommandSessionSetup,
		CreditResponse: grantCredits(hdr.CreditCharge, hdr.CreditResponse),
		Flags:          hdrFlags,
		MessageID:      hdr.MessageID,
		SessionID:      sess.ID,
	}
	full := make([]byte, smb2.HeaderSize+len(respBody))
	_ = smb2.EncodeHeader(full[:smb2.HeaderSize], respHdr)
	copy(full[smb2.HeaderSize:], respBody)
	if !isGuest {
		smb3.SignMessage(uint16(h.Conn.Selection.SigningAlgo), sess.SigningKey, full)
	}

	if err := transport.WriteFrame(rw, full); err != nil {
		return nil, err
	}
	h.Log.Info("session authenticated",
		"session_id", sess.ID,
		"smb_user", user.Name,
		"system_uid", user.SystemUID,
		"guest", isGuest,
	)
	return sess, nil
}

func (h *SessionSetupHandler) failAuth(rw io.ReadWriter, hdr smb2.Header, cause error) error {
	respHdr := smb2.Header{
		CreditCharge:   hdr.CreditCharge,
		Status:         uint32(smb2.StatusLogonFailure),
		Command:        smb2.CommandSessionSetup,
		CreditResponse: grantCredits(hdr.CreditCharge, hdr.CreditResponse),
		Flags:          smb2.FlagServerToRedir,
		MessageID:      hdr.MessageID,
		SessionID:      hdr.SessionID,
	}
	errBody := []byte{0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	full := make([]byte, smb2.HeaderSize+len(errBody))
	_ = smb2.EncodeHeader(full[:smb2.HeaderSize], respHdr)
	copy(full[smb2.HeaderSize:], errBody)
	_ = transport.WriteFrame(rw, full)
	h.Log.Warn("auth failed", "err", cause)
	return cause
}

// rc4xor is a tiny RC4 implementation used once for NTLM key-exchange decrypt.
func rc4xor(key, in, out []byte) {
	var s [256]byte
	for i := 0; i < 256; i++ {
		s[i] = byte(i)
	}
	j := 0
	for i := 0; i < 256; i++ {
		j = (j + int(s[i]) + int(key[i%len(key)])) & 0xff
		s[i], s[j] = s[j], s[i]
	}
	i, jj := 0, 0
	for k := range in {
		i = (i + 1) & 0xff
		jj = (jj + int(s[i])) & 0xff
		s[i], s[jj] = s[jj], s[i]
		out[k] = in[k] ^ s[(int(s[i])+int(s[jj]))&0xff]
	}
}

// filetimeBytes returns the current time as Windows FILETIME (8 bytes LE).
func filetimeBytes() []byte {
	t := filetimeNow()
	return []byte{
		byte(t), byte(t >> 8), byte(t >> 16), byte(t >> 24),
		byte(t >> 32), byte(t >> 40), byte(t >> 48), byte(t >> 56),
	}
}
