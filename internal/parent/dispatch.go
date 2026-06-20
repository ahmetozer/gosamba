package parent

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/ahmetozer/gosamba/internal/config"
	"github.com/ahmetozer/gosamba/internal/inotify"
	"github.com/ahmetozer/gosamba/internal/smb2"
	"github.com/ahmetozer/gosamba/internal/smb3"
	"github.com/ahmetozer/gosamba/internal/transport"
	"github.com/ahmetozer/gosamba/internal/vfs"
)

// Dispatcher routes post-auth SMB2 commands to per-command handlers.
type Dispatcher struct {
	Conn     *Connection
	Sessions *SessionTable
	Shares   []config.ShareConfig
	Log      *slog.Logger

	// Chain state — set by handleCreate, consumed by the ServeConn loop
	// to satisfy "previous handle" FileIDs in compound related ops.
	LastCreatedFileID [16]byte
	HasLastCreated    bool

	// lastChainStatus is the status the most recent op in this compound
	// chain produced. Subsequent related ops referencing the previous-
	// handle sentinel FileID inherit this when it's non-success
	// (MS-SMB2 §3.3.5.2.7).
	lastChainStatus smb2.Status

	// encryptChain is set by ServeConn when the inbound frame arrived
	// inside an SMB3 transform header. All responses for this chain go
	// back encrypted.
	encryptChain bool

	// writeMu serializes writes to the connection so async goroutines
	// (CHANGE_NOTIFY completion) don't corrupt frames the main dispatcher
	// is sending.
	writeMu sync.Mutex
	// nextAsyncID allocates AsyncIds for STATUS_PENDING responses.
	nextAsyncID atomic.Uint64
}

// ResetChainState clears per-chain (per-TCP-frame) state.
func (d *Dispatcher) ResetChainState() {
	d.LastCreatedFileID = [16]byte{}
	d.HasLastCreated = false
	d.lastChainStatus = smb2.StatusSuccess
}

// hasPreviousHandleSentinel reports whether body's FileID slot holds the
// all-FF "use the previous handle" sentinel.
func hasPreviousHandleSentinel(cmd smb2.Command, body []byte) bool {
	off := fileIDOffsetInBody(cmd)
	if off < 0 || len(body) < off+16 {
		return false
	}
	return [16]byte(body[off:off+16]) == previousHandleFileID
}

// SetEncryptForChain marks whether the current inbound chain was encrypted.
func (d *Dispatcher) SetEncryptForChain(b bool) { d.encryptChain = b }

// writeFrame serializes outbound frames and applies SMB3 transform-header
// encryption when the session demands it (or when the client encrypted us).
func (d *Dispatcher) writeFrame(rw io.Writer, sess *Session, frame []byte) error {
	if sess != nil && len(sess.S2CCipherKey) > 0 && d.Conn.Selection.Cipher != 0 &&
		(sess.GotEncrypted || d.encryptChain) {
		enc, err := smb3.EncryptTransform(uint16(d.Conn.Selection.Cipher), sess.S2CCipherKey, sess.ID, frame)
		if err != nil {
			return err
		}
		frame = enc
	}
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	return transport.WriteFrame(rw, frame)
}

// previousHandleFileID is the SMB2 sentinel meaning "use the FileID returned
// by the immediately preceding CREATE in this compound chain".
var previousHandleFileID = [16]byte{
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
}

// fileIDOffsetInBody returns where the 16-byte FileID lives in the body of
// the given command, or -1 if the command has no FileID field.
func fileIDOffsetInBody(cmd smb2.Command) int {
	switch cmd {
	case smb2.CommandClose, smb2.CommandFlush, smb2.CommandIoctl, smb2.CommandLock:
		return 8
	case smb2.CommandRead, smb2.CommandWrite, smb2.CommandSetInfo:
		return 16
	case smb2.CommandQueryInfo:
		return 24
	case smb2.CommandQueryDirectory, smb2.CommandChangeNotify:
		return 8
	}
	return -1
}

// SubstitutePreviousHandleFileID replaces the all-FF sentinel FileID in body
// with the FileID returned by the most recent CREATE in this compound chain.
func (d *Dispatcher) SubstitutePreviousHandleFileID(cmd smb2.Command, body []byte) {
	if !d.HasLastCreated {
		return
	}
	off := fileIDOffsetInBody(cmd)
	if off < 0 || len(body) < off+16 {
		return
	}
	if [16]byte(body[off:off+16]) == previousHandleFileID {
		copy(body[off:off+16], d.LastCreatedFileID[:])
	}
}

// Dispatch handles one frame. Returns false to indicate the caller should
// drop the connection.
func (d *Dispatcher) Dispatch(rw io.ReadWriter, hdr smb2.Header, body, frame []byte) bool {
	sess := d.Sessions.Get(hdr.SessionID)
	if sess == nil {
		d.respondError(rw, hdr, smb2.StatusUserSessionDeleted, nil)
		return false
	}

	// Verify inbound signature when client set FlagSigned. Frames that
	// arrived inside a Transform header are already authenticated by the
	// AEAD tag, so we skip the per-message check there.
	if !d.encryptChain && hdr.Flags&smb2.FlagSigned != 0 && len(sess.SigningKey) > 0 {
		if !smb3.VerifyMessage(uint16(d.Conn.Selection.SigningAlgo), sess.SigningKey, frame) {
			d.Log.Warn("inbound signature mismatch — dropping",
				"cmd", hdr.Command,
				"msg_id", hdr.MessageID,
				"session_id", hdr.SessionID,
			)
			d.respondError(rw, hdr, smb2.StatusAccessDenied, sess)
			return false
		}
	}

	// Now that signature verification is done, in a related compound
	// chain replace any "previous handle" sentinel FileID with the one
	// returned by the most recent CREATE. If the previous op failed and
	// this op is referencing that handle, inherit the prior status (per
	// MS-SMB2 §3.3.5.2.7) — otherwise we'd send INVALID_PARAMETER and
	// confuse clients (Finder reads it as a permission fault).
	if hdr.Flags&smb2.FlagRelatedOps != 0 {
		if d.lastChainStatus != smb2.StatusSuccess && hasPreviousHandleSentinel(hdr.Command, body) {
			d.respondError(rw, hdr, d.lastChainStatus, sess)
			return true
		}
		d.SubstitutePreviousHandleFileID(hdr.Command, body)
	}

	switch hdr.Command {
	case smb2.CommandTreeConnect:
		return d.handleTreeConnect(rw, hdr, body, sess)
	case smb2.CommandTreeDisconnect:
		return d.handleTreeDisconnect(rw, hdr, body, sess)
	case smb2.CommandCreate:
		return d.handleCreate(rw, hdr, body, sess)
	case smb2.CommandRead:
		return d.handleRead(rw, hdr, body, sess)
	case smb2.CommandWrite:
		return d.handleWrite(rw, hdr, body, sess)
	case smb2.CommandFlush:
		return d.handleFlush(rw, hdr, body, sess)
	case smb2.CommandSetInfo:
		return d.handleSetInfo(rw, hdr, body, sess)
	case smb2.CommandClose:
		return d.handleClose(rw, hdr, body, sess)
	case smb2.CommandQueryDirectory:
		return d.handleQueryDirectory(rw, hdr, body, sess)
	case smb2.CommandQueryInfo:
		return d.handleQueryInfo(rw, hdr, body, sess)
	case smb2.CommandIoctl:
		return d.handleIoctl(rw, hdr, body, sess)
	case smb2.CommandLogoff:
		d.respondSuccess(rw, hdr, sess, []byte{0x04, 0x00, 0x00, 0x00})
		return true
	case smb2.CommandEcho:
		d.respondSuccess(rw, hdr, sess, []byte{0x04, 0x00, 0x00, 0x00})
		return true
	case smb2.CommandChangeNotify:
		return d.handleChangeNotify(rw, hdr, body, sess)
	case smb2.CommandLock:
		return d.handleLock(rw, hdr, body, sess)
	case smb2.CommandOplockBreak, smb2.CommandCancel:
		d.respondError(rw, hdr, smb2.StatusNotSupported, sess)
		return true
	default:
		d.Log.Warn("unhandled command", "cmd", hdr.Command)
		d.respondError(rw, hdr, smb2.StatusNotSupported, sess)
		return true
	}
}

// respondSuccess writes a signed STATUS_SUCCESS response with the given body.
func (d *Dispatcher) respondSuccess(rw io.ReadWriter, hdr smb2.Header, sess *Session, body []byte) {
	// Don't sign if we're going to wrap in transform header — encryption
	// already authenticates the frame, and signing under encryption is
	// disallowed for the wrapped message (MS-SMB2 §3.3.4.1.4).
	willEncrypt := sess != nil && len(sess.S2CCipherKey) > 0 && d.Conn.Selection.Cipher != 0 &&
		(sess.GotEncrypted || d.encryptChain)
	sign := !willEncrypt && sess != nil && len(sess.SigningKey) > 0
	out := d.buildResponse(hdr, sess, smb2.StatusSuccess, body, sign)
	d.lastChainStatus = smb2.StatusSuccess
	_ = d.writeFrame(rw, sess, out)
}

// respondError writes a signed error response with a small error body.
func (d *Dispatcher) respondError(rw io.ReadWriter, hdr smb2.Header, status smb2.Status, sess *Session) {
	errBody := []byte{0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	willEncrypt := sess != nil && len(sess.S2CCipherKey) > 0 && d.Conn.Selection.Cipher != 0 &&
		(sess.GotEncrypted || d.encryptChain)
	signed := !willEncrypt && sess != nil && len(sess.SigningKey) > 0
	out := d.buildResponse(hdr, sess, status, errBody, signed)
	d.lastChainStatus = status
	_ = d.writeFrame(rw, sess, out)
}

func (d *Dispatcher) buildResponse(reqHdr smb2.Header, sess *Session, status smb2.Status, body []byte, sign bool) []byte {
	respHdr := smb2.Header{
		CreditCharge:   reqHdr.CreditCharge,
		Status:         uint32(status),
		Command:        reqHdr.Command,
		CreditResponse: grantCredits(reqHdr.CreditCharge, reqHdr.CreditResponse),
		Flags:          smb2.FlagServerToRedir,
		MessageID:      reqHdr.MessageID,
		TreeID:         reqHdr.TreeID,
		SessionID:      reqHdr.SessionID,
	}
	out := make([]byte, smb2.HeaderSize+len(body))
	_ = smb2.EncodeHeader(out[:smb2.HeaderSize], respHdr)
	copy(out[smb2.HeaderSize:], body)
	if sign && sess != nil {
		smb3.SignMessage(uint16(d.Conn.Selection.SigningAlgo), sess.SigningKey, out)
	}
	return out
}

// --- TREE_CONNECT ---

func (d *Dispatcher) handleTreeConnect(rw io.ReadWriter, hdr smb2.Header, body []byte, sess *Session) bool {
	req, err := smb2.DecodeTreeConnectRequest(body)
	if err != nil {
		d.Log.Warn("tree-connect decode failed", "err", err)
		d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
		return true
	}
	// Path is "\\server\share". Extract the trailing share name.
	parts := strings.Split(strings.ReplaceAll(req.Path, "/", "\\"), "\\")
	shareName := parts[len(parts)-1]
	// Don't log routine IPC$ probing — clients hit it constantly.
	if !strings.EqualFold(shareName, "IPC$") {
		d.Log.Debug("tree-connect", "path", req.Path, "share_name", shareName)
	}

	if shareName == "" {
		d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
		return true
	}

	// IPC$ — accept the connect (Samba does the same; refusing causes some
	// clients to retry forever). Unsupported pipes are rejected at the
	// CREATE step with OBJECT_NAME_NOT_FOUND, which matches Samba's
	// smb2_create.c behavior for unknown pipe names.
	if strings.EqualFold(shareName, "IPC$") {
		ipc := config.ShareConfig{Name: "IPC$"}
		tree := sess.AddTree(ipc)
		resp := smb2.EncodeTreeConnectResponse(smb2.TreeConnectResponse{
			ShareType:     smb2.ShareTypePipe,
			ShareFlags:    0,
			Capabilities:  0,
			MaximalAccess: 0x001F00A9,
		})
		d.respondSuccessWithTreeID(rw, hdr, sess, resp, tree.ID)
		return true
	}

	var share *config.ShareConfig
	for i := range d.Shares {
		if strings.EqualFold(d.Shares[i].Name, shareName) {
			share = &d.Shares[i]
			break
		}
	}
	if share == nil {
		d.Log.Warn("tree-connect: unknown share", "share_name", shareName, "configured_shares", shareNames(d.Shares))
		d.respondError(rw, hdr, smb2.StatusObjectNameNotFound, sess)
		return true
	}

	// Guests can only mount shares marked guest_ok.
	if sess.IsGuest && !share.GuestOK {
		d.Log.Warn("guest denied non-guest share", "share_name", shareName)
		d.respondError(rw, hdr, smb2.StatusAccessDenied, sess)
		return true
	}

	// Check user is allowed (named users only — guest passes via guest_ok).
	if !sess.IsGuest && !shareAllowed(sess.User, share.Name) {
		d.respondError(rw, hdr, smb2.StatusAccessDenied, sess)
		return true
	}

	tree := sess.AddTree(*share)
	// SMB2 caching flags: MANUAL (0x0) for read-only, AUTO (0x10) for read-write.
	// Apple clients write-back-cache aggressively under AUTO, which surfaces as
	// phantom EACCES on RO shares — MANUAL avoids that.
	shareFlags := uint32(0x00000010) // AUTO_CACHING
	if share.ReadOnly {
		shareFlags = 0x00000000 // MANUAL_CACHING
	}
	maximalAccess := uint32(0x001F01FF) // generic all
	if share.ReadOnly {
		maximalAccess = 0x001200A9 // read + execute
	}
	respBody := smb2.EncodeTreeConnectResponse(smb2.TreeConnectResponse{
		ShareType:     smb2.ShareTypeDisk,
		ShareFlags:    shareFlags,
		Capabilities:  0,
		MaximalAccess: maximalAccess,
	})
	d.respondSuccessWithTreeID(rw, hdr, sess, respBody, tree.ID)
	return true
}

func shareNames(shares []config.ShareConfig) []string {
	names := make([]string, len(shares))
	for i, s := range shares {
		names[i] = s.Name
	}
	return names
}

func shareNamesAndPaths(shares []config.ShareConfig) []string {
	out := make([]string, len(shares))
	for i, s := range shares {
		out[i] = s.Name + "=" + s.Path
	}
	return out
}

// syntheticDirEntry stands in for "." and ".." in directory listings.
type syntheticDirEntry struct {
	name string
	info os.FileInfo
}

func (s syntheticDirEntry) Name() string               { return s.name }
func (s syntheticDirEntry) IsDir() bool                { return true }
func (s syntheticDirEntry) Type() os.FileMode          { return os.ModeDir }
func (s syntheticDirEntry) Info() (os.FileInfo, error) { return s.info, nil }

func (d *Dispatcher) respondSuccessWithTreeID(rw io.ReadWriter, hdr smb2.Header, sess *Session, body []byte, treeID uint32) {
	respHdr := smb2.Header{
		CreditCharge:   hdr.CreditCharge,
		Status:         uint32(smb2.StatusSuccess),
		Command:        hdr.Command,
		CreditResponse: grantCredits(hdr.CreditCharge, hdr.CreditResponse),
		Flags:          smb2.FlagServerToRedir,
		MessageID:      hdr.MessageID,
		TreeID:         treeID,
		SessionID:      hdr.SessionID,
	}
	out := make([]byte, smb2.HeaderSize+len(body))
	_ = smb2.EncodeHeader(out[:smb2.HeaderSize], respHdr)
	copy(out[smb2.HeaderSize:], body)
	willEncrypt := len(sess.S2CCipherKey) > 0 && d.Conn.Selection.Cipher != 0 &&
		(sess.GotEncrypted || d.encryptChain)
	if !willEncrypt && len(sess.SigningKey) > 0 {
		smb3.SignMessage(uint16(d.Conn.Selection.SigningAlgo), sess.SigningKey, out)
	}
	d.lastChainStatus = smb2.StatusSuccess
	_ = d.writeFrame(rw, sess, out)
}

func shareAllowed(u config.UserConfig, shareName string) bool {
	for _, a := range u.AllowShares {
		if a == "*" || strings.EqualFold(a, shareName) {
			return true
		}
	}
	return false
}

// --- TREE_DISCONNECT ---

func (d *Dispatcher) handleTreeDisconnect(rw io.ReadWriter, hdr smb2.Header, body []byte, sess *Session) bool {
	if _, err := smb2.DecodeTreeDisconnectRequest(body); err != nil {
		d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
		return true
	}
	sess.RemoveTree(hdr.TreeID)
	d.respondSuccess(rw, hdr, sess, smb2.EncodeTreeDisconnectResponse())
	return true
}

// --- CREATE ---

func (d *Dispatcher) handleCreate(rw io.ReadWriter, hdr smb2.Header, body []byte, sess *Session) bool {
	req, err := smb2.DecodeCreateRequest(body)
	if err != nil {
		d.Log.Warn("create decode failed", "err", err)
		d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
		return true
	}
	tree := sess.GetTree(hdr.TreeID)
	if tree == nil {
		d.Log.Warn("create: unknown tree", "tree_id", hdr.TreeID)
		d.respondError(rw, hdr, smb2.StatusNetworkNameDeleted, sess)
		return true
	}
	d.Log.Debug("create",
		"tree", tree.Share.Name,
		"name", req.Name,
		"disposition", req.CreateDisposition,
		"options", req.CreateOptions,
		"access", req.DesiredAccess,
	)

	// Parse durable-handle and lease create contexts up front. A reconnect
	// (DH2C/DHnC) short-circuits the normal CREATE path: we reclaim the saved
	// Open and re-open its backing file rather than re-running disposition.
	durReq, durRec, leaseReq := parseDurableContexts(req.CreateContexts)
	if durRec.present && tree.Share.Path != "" {
		if d.handleDurableReconnect(rw, hdr, sess, tree, durRec) {
			return true
		}
		// Reclaim failed/expired → OBJECT_NAME_NOT_FOUND so the client
		// re-opens fresh (MS-SMB2 §3.3.5.9.7/.12).
		d.respondError(rw, hdr, smb2.StatusObjectNameNotFound, sess)
		return true
	}

	// IPC$ tree: open virtual pipe handles. We support \PIPE\srvsvc (share
	// enumeration); other pipes return OBJECT_NAME_NOT_FOUND so the client
	// stops retrying.
	if tree.Share.Path == "" {
		pipeName := strings.TrimPrefix(strings.TrimPrefix(req.Name, "\\"), "PIPE\\")
		pipeName = strings.TrimPrefix(pipeName, "pipe\\")
		switch strings.ToLower(pipeName) {
		case "srvsvc":
			open := &Open{
				Tree:     tree,
				IsPipe:   true,
				PipeName: "srvsvc",
			}
			if _, err := rand.Read(open.FileID[:]); err != nil {
				d.respondError(rw, hdr, smb2.StatusInternalError, sess)
				return true
			}
			sess.AddOpen(open)
			d.LastCreatedFileID = open.FileID
			d.HasLastCreated = true
			now := filetimeFromTime(time.Now())
			resp := smb2.EncodeCreateResponse(smb2.CreateResponse{
				CreateAction:   smb2.CreateActionOpened,
				CreationTime:   now,
				LastAccessTime: now,
				LastWriteTime:  now,
				ChangeTime:     now,
				FileAttributes: smb2.FileAttrNormal,
				FileID:         open.FileID,
			})
			d.respondSuccess(rw, hdr, sess, resp)
			return true
		default:
			d.respondError(rw, hdr, smb2.StatusObjectNameNotFound, sess)
			return true
		}
	}

	baseName, streamName, streamOK := splitStreamName(req.Name)
	if !streamOK {
		// Non-$DATA stream type (e.g. $INDEX_ALLOCATION) — Samba returns
		// EINVAL here, which maps to STATUS_INVALID_PARAMETER.
		d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
		return true
	}
	if streamName != "" {
		return d.handleCreateNamedStream(rw, hdr, sess, tree, req, baseName, streamName)
	}

	// Use normalization-insensitive resolution so an NFD-named file (created
	// on macOS) can be found by an NFC lookup (Windows/Linux), and vice-versa.
	// ResolveSecureNorm still enforces symlink-containment inside the share.
	osPath, err := vfs.ResolveSecureNorm(tree.Share.Path, baseName)
	if err != nil {
		d.respondError(rw, hdr, smb2.StatusAccessDenied, sess)
		return true
	}
	wantedDir := req.CreateOptions&smb2.CreateOptDirectoryFile != 0
	wantedNonDir := req.CreateOptions&smb2.CreateOptNonDirFile != 0
	wantsWrite := req.DesiredAccess&(smb2.AccessFileWriteData|smb2.AccessFileAppendData|smb2.AccessGenericAll|smb2.AccessGenericWrite) != 0

	// Enforce read-only share restrictions before any mutation.
	if tree.Share.ReadOnly {
		// Any disposition other than plain Open (=1) would create, overwrite, or
		// supersede — deny all of them.
		if req.CreateDisposition != smb2.CreateDispositionOpen {
			d.respondError(rw, hdr, smb2.StatusAccessDenied, sess)
			return true
		}
		// Deny write/append/delete access bits, generic-write/all.
		const writeMask = smb2.AccessFileWriteData | smb2.AccessFileAppendData |
			smb2.AccessGenericWrite | smb2.AccessGenericAll |
			0x00000100 | // FILE_WRITE_ATTRIBUTES
			0x00010000 // DELETE
		if req.DesiredAccess&writeMask != 0 {
			d.respondError(rw, hdr, smb2.StatusAccessDenied, sess)
			return true
		}
		// DELETE_ON_CLOSE would silently remove the file on close.
		if req.CreateOptions&smb2.CreateOptDeleteOnClose != 0 {
			d.respondError(rw, hdr, smb2.StatusAccessDenied, sess)
			return true
		}
		// mkdir on a read-only share: DirectoryFile + any creating disposition.
		// (We already rejected non-Open dispositions above, so this is covered;
		// guard here for clarity if the logic above ever changes.)
		if wantedDir && req.CreateDisposition != smb2.CreateDispositionOpen {
			d.respondError(rw, hdr, smb2.StatusAccessDenied, sess)
			return true
		}
	}

	st, statErr := os.Lstat(osPath)
	exists := statErr == nil
	isDir := exists && st.IsDir()
	if !exists && !os.IsNotExist(statErr) {
		d.Log.Warn("create: lstat failed", "path", osPath, "err", statErr)
		d.respondError(rw, hdr, statusFromErr(statErr), sess)
		return true
	}

	// Apply disposition logic.
	createAction := uint32(smb2.CreateActionOpened)
	switch req.CreateDisposition {
	case smb2.CreateDispositionOpen:
		if !exists {
			d.respondError(rw, hdr, smb2.StatusObjectNameNotFound, sess)
			return true
		}
	case smb2.CreateDispositionCreate:
		if exists {
			d.respondError(rw, hdr, smb2.StatusObjectNameCollision, sess)
			return true
		}
		if wantedDir {
			if err := os.Mkdir(osPath, 0775); err != nil {
				d.Log.Warn("create: mkdir failed", "path", osPath, "err", err)
				d.respondError(rw, hdr, statusFromErr(err), sess)
				return true
			}
			isDir = true
		} else {
			f, err := os.OpenFile(osPath, os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0664)
			if err != nil {
				d.Log.Warn("create: open EXCL failed", "path", osPath, "err", err)
				d.respondError(rw, hdr, statusFromErr(err), sess)
				return true
			}
			f.Close()
		}
		st, _ = os.Lstat(osPath)
		exists = true
		createAction = smb2.CreateActionCreated
	case smb2.CreateDispositionOpenIf:
		if !exists {
			if wantedDir {
				if err := os.Mkdir(osPath, 0775); err != nil {
					d.respondError(rw, hdr, statusFromErr(err), sess)
					return true
				}
				isDir = true
			} else {
				f, err := os.OpenFile(osPath, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0664)
				if err != nil {
					d.respondError(rw, hdr, statusFromErr(err), sess)
					return true
				}
				f.Close()
			}
			st, _ = os.Lstat(osPath)
			exists = true
			createAction = smb2.CreateActionCreated
		}
	case smb2.CreateDispositionOverwrite:
		if !exists {
			d.respondError(rw, hdr, smb2.StatusObjectNameNotFound, sess)
			return true
		}
		if !isDir {
			if err := os.Truncate(osPath, 0); err != nil {
				d.respondError(rw, hdr, statusFromErr(err), sess)
				return true
			}
		}
		createAction = smb2.CreateActionOverwritten
		st, _ = os.Lstat(osPath)
	case smb2.CreateDispositionOverwriteIf, smb2.CreateDispositionSupersede:
		if exists && !isDir {
			if err := os.Truncate(osPath, 0); err != nil {
				d.respondError(rw, hdr, statusFromErr(err), sess)
				return true
			}
			createAction = smb2.CreateActionOverwritten
		} else if !exists {
			f, err := os.OpenFile(osPath, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0664)
			if err != nil {
				d.respondError(rw, hdr, statusFromErr(err), sess)
				return true
			}
			f.Close()
			createAction = smb2.CreateActionCreated
		}
		st, _ = os.Lstat(osPath)
		exists = true
	default:
		d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
		return true
	}

	if wantedDir && !isDir {
		d.respondError(rw, hdr, smb2.StatusNotADirectory, sess)
		return true
	}
	if wantedNonDir && isDir {
		d.respondError(rw, hdr, smb2.StatusFileIsADirectory, sess)
		return true
	}

	// Granted-access mask reported back via FileAccessInformation /
	// FileAllInformation. macOS derives mode bits from this and refuses to
	// LIST a directory whose mask doesn't include FILE_LIST_DIRECTORY
	// (= FILE_READ_DATA) — even when the CREATE itself succeeded. Match what
	// Samba does: report the full per-share max access regardless of what
	// the client asked for in CREATE. RW shares get FILE_ALL_ACCESS; RO
	// shares get FILE_GENERIC_READ|FILE_GENERIC_EXECUTE.
	var granted uint32 = 0x001F01FF // FILE_ALL_ACCESS
	if tree.Share.ReadOnly {
		granted = 0x001200A9 // FILE_GENERIC_READ | FILE_GENERIC_EXECUTE
	}

	open := &Open{
		Path:          osPath,
		IsDir:         isDir,
		Tree:          tree,
		GrantedAccess: granted,
		DeleteOnClose: req.CreateOptions&smb2.CreateOptDeleteOnClose != 0,
	}
	if !isDir {
		// Always open RW when possible so that later SET_INFO (truncate / EOF)
		// or rename ops on this handle don't fail with EBADF. If RW fails
		// (e.g. read-only filesystem), fall back to read-only when the client
		// only asked for read-only access.
		// O_NOFOLLOW on the leaf closes the TOCTOU window where a symlink
		// swapped in after ResolveSecure would otherwise be followed silently.
		f, err := os.OpenFile(osPath, os.O_RDWR|syscall.O_NOFOLLOW, 0)
		if err != nil {
			if errors.Is(err, syscall.ELOOP) {
				d.respondError(rw, hdr, smb2.StatusAccessDenied, sess)
				return true
			}
			if !wantsWrite {
				f, err = os.OpenFile(osPath, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
			}
			if err != nil {
				if errors.Is(err, syscall.ELOOP) {
					d.respondError(rw, hdr, smb2.StatusAccessDenied, sess)
					return true
				}
				d.respondError(rw, hdr, statusFromErr(err), sess)
				return true
			}
		}
		open.File = f
	}
	if _, err := rand.Read(open.FileID[:]); err != nil {
		if open.File != nil {
			open.File.Close()
		}
		d.respondError(rw, hdr, smb2.StatusInternalError, sess)
		return true
	}
	sess.AddOpen(open)

	d.LastCreatedFileID = open.FileID
	d.HasLastCreated = true

	attrs := uint32(smb2.FileAttrNormal)
	allocSize := uint64(0)
	endOfFile := uint64(0)
	if isDir {
		attrs = smb2.FileAttrDirectory
	} else if st != nil {
		allocSize = uint64(st.Size())
		endOfFile = uint64(st.Size())
	}
	mtime := filetimeFromTime(time.Now())
	if st != nil {
		mtime = filetimeFromTime(st.ModTime())
	}
	// F9: use real birth time (statx btime) for CreationTime in the CREATE
	// response when the filesystem provides it. Falls back to ModTime.
	createCtime := mtime
	if bt, ok := birthTime(osPath); ok {
		createCtime = filetimeFromTime(bt)
	}

	// Register a durable handle and collect the extra response contexts
	// (DH2Q/DHnQ echo, RqLs lease grant) to append to the AAPL/MxAc set.
	respCtxs := buildCreateResponseContexts(req.CreateContexts, d.Conn, granted)
	respCtxs = d.applyDurableAndLease(open, durReq, leaseReq, respCtxs)

	resp := smb2.EncodeCreateResponse(smb2.CreateResponse{
		CreateAction:   createAction,
		CreationTime:   createCtime,
		LastAccessTime: mtime,
		LastWriteTime:  mtime,
		ChangeTime:     mtime,
		AllocationSize: allocSize,
		EndOfFile:      endOfFile,
		FileAttributes: attrs,
		FileID:         open.FileID,
		CreateContexts: respCtxs,
	})
	d.respondSuccess(rw, hdr, sess, resp)
	return true
}

func statusFromErr(err error) smb2.Status {
	switch {
	case os.IsNotExist(err):
		return smb2.StatusObjectNameNotFound
	case os.IsPermission(err):
		return smb2.StatusAccessDenied
	case os.IsExist(err):
		return smb2.StatusObjectNameCollision
	}
	return smb2.StatusInternalError
}

// --- READ ---

func (d *Dispatcher) handleRead(rw io.ReadWriter, hdr smb2.Header, body []byte, sess *Session) bool {
	req, err := smb2.DecodeReadRequest(body)
	if err != nil {
		d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
		return true
	}
	open := sess.GetOpen(req.FileID)
	if open == nil {
		d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
		return true
	}
	if open.IsPipe {
		// Drain any queued DCE/RPC response from a prior WRITE.
		if len(open.pipeOut) == 0 {
			d.respondError(rw, hdr, smb2.StatusEndOfFile, sess)
			return true
		}
		n := int(req.Length)
		if n > len(open.pipeOut) {
			n = len(open.pipeOut)
		}
		out := open.pipeOut[:n]
		open.pipeOut = open.pipeOut[n:]
		d.respondSuccess(rw, hdr, sess, smb2.EncodeReadResponse(smb2.ReadResponse{Data: out}))
		return true
	}
	if open.IsStream {
		off := int(req.Offset)
		if off >= len(open.streamBuf) {
			d.respondError(rw, hdr, smb2.StatusEndOfFile, sess)
			return true
		}
		end := off + int(req.Length)
		if end > len(open.streamBuf) {
			end = len(open.streamBuf)
		}
		d.respondSuccess(rw, hdr, sess, smb2.EncodeReadResponse(smb2.ReadResponse{Data: open.streamBuf[off:end]}))
		return true
	}
	if open.File == nil {
		d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
		return true
	}
	buf := make([]byte, req.Length)
	n, err := open.File.ReadAt(buf, int64(req.Offset))
	if err != nil && err != io.EOF {
		d.Log.Warn("read failed", "path", open.Path, "err", err)
		d.respondError(rw, hdr, statusFromErr(err), sess)
		return true
	}
	if n == 0 {
		d.respondError(rw, hdr, smb2.StatusEndOfFile, sess)
		return true
	}
	resp := smb2.EncodeReadResponse(smb2.ReadResponse{Data: buf[:n]})
	d.respondSuccess(rw, hdr, sess, resp)
	return true
}

// --- WRITE ---

func (d *Dispatcher) handleWrite(rw io.ReadWriter, hdr smb2.Header, body []byte, sess *Session) bool {
	req, err := smb2.DecodeWriteRequest(body)
	if err != nil {
		d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
		return true
	}
	open := sess.GetOpen(req.FileID)
	if open == nil {
		d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
		return true
	}
	// Enforce read-only share: writes are never permitted.
	if open.Tree != nil && open.Tree.Share.ReadOnly && !open.IsPipe {
		d.respondError(rw, hdr, smb2.StatusAccessDenied, sess)
		return true
	}
	if open.IsPipe {
		// Run DCE/RPC and queue the response for the next READ.
		if open.PipeName == "srvsvc" {
			if out := dcerpcHandle(req.Data, d.Shares); out != nil {
				open.pipeOut = append(open.pipeOut, out...)
			}
		}
		d.respondSuccess(rw, hdr, sess, smb2.EncodeWriteResponse(smb2.WriteResponse{Count: uint32(len(req.Data))}))
		return true
	}
	if open.IsStream {
		off := int(req.Offset)
		end := off + len(req.Data)
		if end > len(open.streamBuf) {
			grown := make([]byte, end)
			copy(grown, open.streamBuf)
			open.streamBuf = grown
		}
		copy(open.streamBuf[off:end], req.Data)
		open.streamWritten = true
		d.respondSuccess(rw, hdr, sess, smb2.EncodeWriteResponse(smb2.WriteResponse{Count: uint32(len(req.Data))}))
		return true
	}
	if open.File == nil {
		d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
		return true
	}
	n, err := open.File.WriteAt(req.Data, int64(req.Offset))
	if err != nil {
		d.Log.Warn("write failed", "path", open.Path, "err", err)
		d.respondError(rw, hdr, statusFromErr(err), sess)
		return true
	}
	d.respondSuccess(rw, hdr, sess, smb2.EncodeWriteResponse(smb2.WriteResponse{Count: uint32(n)}))
	return true
}

// --- FLUSH ---

func (d *Dispatcher) handleFlush(rw io.ReadWriter, hdr smb2.Header, body []byte, sess *Session) bool {
	req, err := smb2.DecodeFlushRequest(body)
	if err != nil {
		d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
		return true
	}
	open := sess.GetOpen(req.FileID)
	if open == nil {
		d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
		return true
	}
	if open.File != nil {
		_ = open.File.Sync()
	}
	d.respondSuccess(rw, hdr, sess, smb2.EncodeFlushResponse())
	return true
}

// --- SET_INFO ---

func (d *Dispatcher) handleSetInfo(rw io.ReadWriter, hdr smb2.Header, body []byte, sess *Session) bool {
	req, err := smb2.DecodeSetInfoRequest(body)
	if err != nil {
		d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
		return true
	}
	open := sess.GetOpen(req.FileID)
	if open == nil {
		d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
		return true
	}
	d.Log.Debug("set-info",
		"info_type", req.InfoType,
		"info_class", req.FileInfoClass,
		"path", open.Path,
		"buf_len", len(req.Buffer),
	)
	// Enforce read-only share: SET_INFO is always a write mutation.
	if open.Tree != nil && open.Tree.Share.ReadOnly {
		d.respondError(rw, hdr, smb2.StatusAccessDenied, sess)
		return true
	}
	if open.IsStream {
		// Honor EOF (resize the in-memory buffer) and Disposition (delete-on-
		// close → remove the backing xattr at CLOSE). Rename/EA/Basic on a
		// stream are accepted silently.
		switch {
		case req.InfoType == smb2.InfoTypeFile && req.FileInfoClass == smb2.FileEndOfFileInformation && len(req.Buffer) >= 8:
			size := int(binary.LittleEndian.Uint64(req.Buffer[0:]))
			switch {
			case size <= 0:
				open.streamBuf = nil
			case size <= len(open.streamBuf):
				open.streamBuf = open.streamBuf[:size]
			default:
				grown := make([]byte, size)
				copy(grown, open.streamBuf)
				open.streamBuf = grown
			}
		case req.InfoType == smb2.InfoTypeFile && req.FileInfoClass == smb2.FileDispositionInformation && len(req.Buffer) >= 1:
			open.DeleteOnClose = req.Buffer[0] != 0
		}
		d.respondSuccess(rw, hdr, sess, smb2.EncodeSetInfoResponse())
		return true
	}
	// Silently accept SD / quota / FS-info SET_INFO. We don't persist ACLs,
	// but Samba and Windows answer SUCCESS here so clients (Finder especially)
	// don't conclude the handle is broken. Refusing surfaces as "you don't
	// have permission to see its contents" on macOS for newly created dirs.
	if req.InfoType == smb2.InfoTypeSecurity ||
		req.InfoType == smb2.InfoTypeQuota ||
		req.InfoType == smb2.InfoTypeFilesystem {
		d.respondSuccess(rw, hdr, sess, smb2.EncodeSetInfoResponse())
		return true
	}
	if req.InfoType != smb2.InfoTypeFile {
		d.respondError(rw, hdr, smb2.StatusNotSupported, sess)
		return true
	}
	switch req.FileInfoClass {
	case smb2.FileEndOfFileInformation:
		if len(req.Buffer) < 8 {
			d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
			return true
		}
		size := int64(binary.LittleEndian.Uint64(req.Buffer[0:]))
		if err := os.Truncate(open.Path, size); err != nil {
			d.respondError(rw, hdr, statusFromErr(err), sess)
			return true
		}
	case smb2.FileAllocationInformation:
		// Best-effort: ignore (POSIX doesn't have a portable preallocation primitive).
	case smb2.FileDispositionInformation:
		if len(req.Buffer) < 1 {
			d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
			return true
		}
		open.DeleteOnClose = req.Buffer[0] != 0
	case smb2.FileRenameInformation:
		// Buffer: ReplaceIfExists(1) + Reserved(7) + RootDirectory(8) + FileNameLength(4) + FileName(N)
		if len(req.Buffer) < 20 {
			d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
			return true
		}
		replace := req.Buffer[0] != 0
		nameLen := binary.LittleEndian.Uint32(req.Buffer[16:])
		if 20+int(nameLen) > len(req.Buffer) {
			d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
			return true
		}
		newName := decodeUTF16LE(req.Buffer[20 : 20+nameLen])
		// Use normalization-insensitive resolution for the rename destination so
		// that lookups across NFC/NFD boundaries work. For a new name (doesn't
		// exist yet), it falls through to the requested name unchanged.
		newPath, err := vfs.ResolveSecureNorm(open.Tree.Share.Path, newName)
		if err != nil {
			d.respondError(rw, hdr, smb2.StatusAccessDenied, sess)
			return true
		}
		if !replace {
			if _, err := os.Lstat(newPath); err == nil {
				d.respondError(rw, hdr, smb2.StatusObjectNameCollision, sess)
				return true
			}
		}
		if err := os.Rename(open.Path, newPath); err != nil {
			d.respondError(rw, hdr, statusFromErr(err), sess)
			return true
		}
		open.Path = newPath
	case smb2.FileFullEaInformation:
		// Parse the FILE_FULL_EA_INFORMATION list (MS-FSCC §2.4.15) and persist
		// each EA as a user.* xattr. macOS uses this to seed Versions/Quarantine/
		// AppleDouble metadata. If the filesystem lacks xattr support we accept
		// silently (matching the prior accept-and-drop behavior) so clients
		// don't conclude the handle is broken.
		for _, ea := range parseFullEaList(req.Buffer) {
			if err := setEA(open.Path, ea.Name, ea.Value); err != nil {
				if errors.Is(err, errXattrUnsupported) {
					break
				}
				d.respondError(rw, hdr, statusFromErr(err), sess)
				return true
			}
		}
	case smb2.FileBasicInformationSet:
		// Best-effort: only LastWriteTime via os.Chtimes if non-zero/non-(-1).
		if len(req.Buffer) >= 32 {
			lastWrite := int64(binary.LittleEndian.Uint64(req.Buffer[16:]))
			lastAccess := int64(binary.LittleEndian.Uint64(req.Buffer[8:]))
			if lastWrite > 0 && lastWrite != -1 {
				wt := timeFromFiletime(uint64(lastWrite))
				at := wt
				if lastAccess > 0 && lastAccess != -1 {
					at = timeFromFiletime(uint64(lastAccess))
				}
				_ = os.Chtimes(open.Path, at, wt)
			}
		}
	default:
		d.Log.Warn("set-info: unsupported class", "class", req.FileInfoClass)
		d.respondError(rw, hdr, smb2.StatusNotSupported, sess)
		return true
	}
	d.respondSuccess(rw, hdr, sess, smb2.EncodeSetInfoResponse())
	return true
}

func decodeUTF16LE(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	r := make([]rune, 0, len(b)/2)
	for i := 0; i < len(b); i += 2 {
		r = append(r, rune(uint16(b[i])|uint16(b[i+1])<<8))
	}
	return string(r)
}

func timeFromFiletime(ft uint64) time.Time {
	if ft == 0 {
		return time.Now()
	}
	secs := int64(ft/10_000_000) - filetimeEpochDelta
	nanos := int64(ft%10_000_000) * 100
	return time.Unix(secs, nanos).UTC()
}

// --- CLOSE ---

func (d *Dispatcher) handleClose(rw io.ReadWriter, hdr smb2.Header, body []byte, sess *Session) bool {
	req, err := smb2.DecodeCloseRequest(body)
	if err != nil {
		d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
		return true
	}
	open := sess.RemoveOpen(req.FileID)
	if open == nil {
		d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
		return true
	}
	// A clean CLOSE of a durable handle means it is no longer reclaimable —
	// drop its durable-table entry (a dropped connection, by contrast, leaves
	// it for reclaim until expiry).
	if open.IsDurable && d.Conn != nil && d.Conn.Durable != nil {
		d.Conn.Durable.Remove(open.DurableClientGuid, open.DurableCreateGuid)
	}
	if open.File != nil {
		open.File.Close()
	}
	if open.IsPipe {
		d.respondSuccess(rw, hdr, sess, smb2.EncodeCloseResponse(smb2.CloseResponse{}))
		return true
	}
	if open.IsStream {
		// Persist the stream buffer to its backing xattr, or remove it on
		// delete-on-close. A zero-length buffer still writes an (empty) xattr so
		// the stream "exists". ENOTSUP (no xattr support) is tolerated silently.
		if open.DeleteOnClose {
			if err := removeStreamXattr(open.Path, open.StreamName); err != nil && !errors.Is(err, errXattrUnsupported) {
				d.Log.Warn("stream delete-on-close failed", "path", open.Path, "stream", open.StreamName, "err", err)
			}
		} else if open.streamSynthetic && !open.streamWritten {
			// A fabricated blob (e.g. empty AFP_AfpInfo) the client only read —
			// don't persist it, so we don't litter the file with metadata xattrs.
		} else if err := writeStreamXattr(open.Path, open.StreamName, open.streamBuf); err != nil && !errors.Is(err, errXattrUnsupported) {
			// Linux user.* xattrs are size-limited (~64 KiB on ext4). A resource
			// fork larger than that yields E2BIG — map to STATUS_DISK_FULL rather
			// than silently losing data.
			if errors.Is(err, syscall.E2BIG) {
				d.respondError(rw, hdr, smb2.StatusDiskFull, sess)
				return true
			}
			d.Log.Warn("stream flush failed", "path", open.Path, "stream", open.StreamName, "err", err)
		}
		now := filetimeFromTime(time.Now())
		d.respondSuccess(rw, hdr, sess, smb2.EncodeCloseResponse(smb2.CloseResponse{
			CreationTime:   now,
			LastAccessTime: now,
			LastWriteTime:  now,
			ChangeTime:     now,
			AllocationSize: uint64(len(open.streamBuf)),
			EndOfFile:      uint64(len(open.streamBuf)),
			FileAttributes: smb2.FileAttrNormal,
		}))
		return true
	}
	if open.DeleteOnClose {
		if err := os.Remove(open.Path); err != nil {
			d.Log.Warn("delete-on-close failed", "path", open.Path, "err", err)
		}
	}
	st, _ := os.Lstat(open.Path)
	resp := smb2.CloseResponse{}
	if st != nil {
		mt := filetimeFromTime(st.ModTime())
		// F9: use btime for CreationTime in CLOSE response when available.
		ct := mt
		if bt, ok := birthTime(open.Path); ok {
			ct = filetimeFromTime(bt)
		}
		resp.CreationTime = ct
		resp.LastAccessTime = mt
		resp.LastWriteTime = mt
		resp.ChangeTime = mt
		resp.AllocationSize = uint64(st.Size())
		resp.EndOfFile = uint64(st.Size())
		if st.IsDir() {
			resp.FileAttributes = smb2.FileAttrDirectory
		} else {
			resp.FileAttributes = smb2.FileAttrNormal
		}
	}
	d.respondSuccess(rw, hdr, sess, smb2.EncodeCloseResponse(resp))
	return true
}

// --- QUERY_DIRECTORY ---

func (d *Dispatcher) handleQueryDirectory(rw io.ReadWriter, hdr smb2.Header, body []byte, sess *Session) bool {
	req, err := smb2.DecodeQueryDirectoryRequest(body)
	if err != nil {
		d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
		return true
	}
	open := sess.GetOpen(req.FileID)
	if open == nil || !open.IsDir {
		d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
		return true
	}
	d.Log.Debug("query-dir",
		"path", open.Path,
		"info_class", req.FileInformationClass,
		"flags", req.Flags,
		"pattern", req.FileName,
		"buf_len", req.OutputBufferLength,
	)
	if req.Flags&smb2.QueryDirRestartScans != 0 || open.dirEntries == nil {
		entries, err := os.ReadDir(open.Path)
		if err != nil {
			d.Log.Warn("query-dir: ReadDir failed", "path", open.Path, "err", err, "status", statusFromErr(err))
			d.respondError(rw, hdr, statusFromErr(err), sess)
			return true
		}
		// Prepend synthetic "." and ".." entries — Windows/macOS clients expect them.
		dirInfo, _ := os.Lstat(open.Path)
		parentInfo := dirInfo
		if pi, err := os.Lstat(filepath.Dir(open.Path)); err == nil {
			parentInfo = pi
		}
		all := make([]os.DirEntry, 0, len(entries)+2)
		all = append(all,
			syntheticDirEntry{name: ".", info: dirInfo},
			syntheticDirEntry{name: "..", info: parentInfo},
		)
		all = append(all, entries...)

		// Apply pattern filter (SMB-style glob, case-insensitive). Hide
		// names containing `:` so any pre-existing stream-syntax pollution
		// (created before stream parsing was wired up) is invisible to
		// clients — `:` is illegal in NTFS names anyway, so a real SMB
		// client could never have legitimately created such a name.
		pattern := req.FileName
		if pattern == "" {
			pattern = "*"
		}
		filtered := all[:0:0]
		for _, e := range all {
			if strings.ContainsRune(e.Name(), ':') {
				continue
			}
			if matchSMBPattern(pattern, e.Name()) {
				filtered = append(filtered, e)
			}
		}
		open.dirEntries = filtered
		open.dirSent = 0
		d.Log.Debug("query-dir: enumerated",
			"path", open.Path,
			"total", len(all),
			"matched", len(filtered),
			"pattern", pattern,
		)
	}

	// Empty result on a fresh enumeration → STATUS_NO_SUCH_FILE.
	// Empty result on a continuation → STATUS_NO_MORE_FILES.
	if len(open.dirEntries) == 0 {
		d.respondError(rw, hdr, smb2.StatusNoSuchFile, sess)
		return true
	}
	if open.dirSent >= len(open.dirEntries) {
		d.respondError(rw, hdr, smb2.StatusNoMoreFiles, sess)
		return true
	}

	limit := len(open.dirEntries) - open.dirSent
	if req.Flags&smb2.QueryDirReturnSingleEntry != 0 {
		limit = 1
	}
	// AAPL READ_DIR_ATTR overlay applies only on disk shares (not IPC$) and
	// only for the level-37 record class.
	useAAPL := d.Conn.AAPLReadDirAttr &&
		open.Tree != nil && open.Tree.Share.Path != "" &&
		req.FileInformationClass == smb2.InfoFileIdBothDirectoryInformation
	buf, sent, err := encodeDirEntriesLimited(open, int(req.OutputBufferLength), req.FileInformationClass, limit, useAAPL)
	if err != nil {
		d.respondError(rw, hdr, smb2.StatusInternalError, sess)
		return true
	}
	open.dirSent += sent
	if sent == 0 {
		d.respondError(rw, hdr, smb2.StatusNoMoreFiles, sess)
		return true
	}
	d.respondSuccess(rw, hdr, sess, smb2.EncodeQueryDirectoryResponse(smb2.QueryDirectoryResponse{Buffer: buf}))
	return true
}

// matchSMBPattern matches name against an SMB glob pattern, case-insensitively.
// Supports `*` and `?`. Empty pattern means match all.
func matchSMBPattern(pattern, name string) bool {
	if pattern == "" || pattern == "*" {
		return true
	}
	ok, _ := filepath.Match(strings.ToLower(pattern), strings.ToLower(name))
	return ok
}

// encodeDirEntriesLimited packs at most `limit` entries (or as many as fit in
// maxBytes) starting at open.dirSent. When useAAPL is true and infoClass is
// FileIdBothDirectoryInformation, each record carries the Apple overlay so
// Finder gets FinderInfo/rfork/mode in one round-trip.
func encodeDirEntriesLimited(open *Open, maxBytes int, infoClass uint8, limit int, useAAPL bool) ([]byte, int, error) {
	out := make([]byte, 0, maxBytes)
	consumed := 0
	maxAccess := uint32(0x001F01FF)
	if open.Tree != nil && open.Tree.Share.ReadOnly {
		maxAccess = 0x001200A9
	}
	for i := open.dirSent; i < len(open.dirEntries) && consumed < limit; i++ {
		ent := open.dirEntries[i]
		info, err := ent.Info()
		if err != nil {
			continue
		}
		var rforkSize uint64
		if useAAPL && !info.IsDir() {
			// Report the AAPL resource-fork size from its backing ADS xattr.
			if data, err := readStreamXattr(filepath.Join(open.Path, ent.Name()), rforkStreamName); err == nil {
				rforkSize = uint64(len(data))
			}
		}
		rec := encodeDirRecord(ent.Name(), info, infoClass, useAAPL, maxAccess, rforkSize)
		padded := rec
		if len(rec)%8 != 0 {
			padded = append(append([]byte{}, rec...), make([]byte, 8-len(rec)%8)...)
		}
		if len(out)+len(padded) > maxBytes {
			break
		}
		if consumed > 0 {
			prevStart := lastRecordStart(out)
			binary.LittleEndian.PutUint32(out[prevStart:], uint32(len(out)-prevStart))
		}
		out = append(out, padded...)
		consumed++
	}
	return out, consumed, nil
}

func lastRecordStart(buf []byte) int {
	// Walk the linked list to find the last record start.
	off := 0
	for {
		next := binary.LittleEndian.Uint32(buf[off:])
		if next == 0 {
			return off
		}
		off += int(next)
	}
}

// encodeDirRecord builds a single directory entry record. Supported classes:
// FileDirectoryInformation, FileBothDirectoryInformation,
// FileIdBothDirectoryInformation, FileFullDirectoryInformation,
// FileNamesInformation. Other classes fall back to FileBothDirectoryInformation.
//
// When useAAPL is true and infoClass is FileIdBothDirectoryInformation, the
// record overlays Apple's AAPL fields onto the record per Apple's spec
// (max_access in EaSize, rfork_size+FinderInfo in ShortName, UNIX mode in
// Reserved2). maxAccess is the per-share maximal access mask reported as
// max_access. See Samba's smb2_trans2.c SMB_FIND_ID_BOTH_DIRECTORY_INFO case.
func encodeDirRecord(name string, info os.FileInfo, infoClass uint8, useAAPL bool, maxAccess uint32, rforkSize uint64) []byte {
	nameU16 := utf16leName(name)
	switch infoClass {
	case smb2.InfoFileDirectoryInformation:
		// MS-FSCC §2.4.10 — 64 fixed bytes + name.
		const fixed = 64
		out := make([]byte, fixed+len(nameU16))
		binary.LittleEndian.PutUint64(out[8:], filetimeFromTime(info.ModTime()))
		binary.LittleEndian.PutUint64(out[16:], filetimeFromTime(info.ModTime()))
		binary.LittleEndian.PutUint64(out[24:], filetimeFromTime(info.ModTime()))
		binary.LittleEndian.PutUint64(out[32:], filetimeFromTime(info.ModTime()))
		size := uint64(info.Size())
		if info.IsDir() {
			size = 0
		}
		binary.LittleEndian.PutUint64(out[40:], size)
		binary.LittleEndian.PutUint64(out[48:], size)
		attrs := uint32(smb2.FileAttrNormal)
		if info.IsDir() {
			attrs = smb2.FileAttrDirectory
		}
		binary.LittleEndian.PutUint32(out[56:], attrs)
		binary.LittleEndian.PutUint32(out[60:], uint32(len(nameU16)))
		copy(out[fixed:], nameU16)
		return out
	case smb2.InfoFileFullDirectoryInformation:
		// MS-FSCC §2.4.14 — 68 fixed bytes (adds EaSize) + name.
		const fixed = 68
		out := make([]byte, fixed+len(nameU16))
		binary.LittleEndian.PutUint64(out[8:], filetimeFromTime(info.ModTime()))
		binary.LittleEndian.PutUint64(out[16:], filetimeFromTime(info.ModTime()))
		binary.LittleEndian.PutUint64(out[24:], filetimeFromTime(info.ModTime()))
		binary.LittleEndian.PutUint64(out[32:], filetimeFromTime(info.ModTime()))
		size := uint64(info.Size())
		if info.IsDir() {
			size = 0
		}
		binary.LittleEndian.PutUint64(out[40:], size)
		binary.LittleEndian.PutUint64(out[48:], size)
		attrs := uint32(smb2.FileAttrNormal)
		if info.IsDir() {
			attrs = smb2.FileAttrDirectory
		}
		binary.LittleEndian.PutUint32(out[56:], attrs)
		binary.LittleEndian.PutUint32(out[60:], uint32(len(nameU16)))
		copy(out[fixed:], nameU16)
		return out
	case smb2.InfoFileNamesInformation:
		// MS-FSCC §2.4.26 — 12 fixed (NextEntryOffset+FileIndex+FileNameLength) + name.
		const fixed = 12
		out := make([]byte, fixed+len(nameU16))
		binary.LittleEndian.PutUint32(out[8:], uint32(len(nameU16)))
		copy(out[fixed:], nameU16)
		return out
	case smb2.InfoFileIdBothDirectoryInformation:
		// Layout (104 fixed bytes + name):
		// 0  NextEntryOffset (4)
		// 4  FileIndex (4)
		// 8  CreationTime (8)
		// 16 LastAccessTime (8)
		// 24 LastWriteTime (8)
		// 32 ChangeTime (8)
		// 40 EndOfFile (8)
		// 48 AllocationSize (8)
		// 56 FileAttributes (4)
		// 60 FileNameLength (4)
		// 64 EaSize (4)
		// 68 ShortNameLength (1)
		// 69 Reserved (1)
		// 70 ShortName (24)
		// 94 Reserved2 (2)
		// 96 FileId (8)
		// 104 FileName (variable)
		const fixed = 104
		out := make([]byte, fixed+len(nameU16))
		binary.LittleEndian.PutUint64(out[8:], filetimeFromTime(info.ModTime()))
		binary.LittleEndian.PutUint64(out[16:], filetimeFromTime(info.ModTime()))
		binary.LittleEndian.PutUint64(out[24:], filetimeFromTime(info.ModTime()))
		binary.LittleEndian.PutUint64(out[32:], filetimeFromTime(info.ModTime()))
		size := uint64(info.Size())
		if info.IsDir() {
			size = 0
		}
		binary.LittleEndian.PutUint64(out[40:], size)
		binary.LittleEndian.PutUint64(out[48:], size)
		attrs := uint32(smb2.FileAttrNormal)
		if info.IsDir() {
			attrs = smb2.FileAttrDirectory
		}
		binary.LittleEndian.PutUint32(out[56:], attrs)
		binary.LittleEndian.PutUint32(out[60:], uint32(len(nameU16)))
		unixMode, inode := unixModeAndInode(info)
		if useAAPL {
			// Apple overlay (matches Samba's vfs_fruit + smb2_trans2.c):
			//  EaSize          = max_access
			//  ShortNameLength = 24 (Apple writes literal 24 even though spec says 0)
			//  ShortName[0..7] = rfork_size (always 0 — no resource fork store)
			//  ShortName[8..23]= compressed FinderInfo (16 bytes of zeros)
			//  Reserved2       = UNIX mode (low 16 bits)
			//  FileId          = inode
			binary.LittleEndian.PutUint32(out[64:], maxAccess)
			out[68] = 24
			out[69] = 0
			// ShortName[0..7] = rfork_size (from the AFP_AfpResource ADS xattr;
			// 0 when no resource fork is stored).
			binary.LittleEndian.PutUint64(out[70:], rforkSize)
			// out[78..93] FinderInfo = 0 (already zero)
			binary.LittleEndian.PutUint16(out[94:], unixMode)
			binary.LittleEndian.PutUint64(out[96:], inode)
		} else if inode != 0 {
			// Always populate FileId so clients have a stable identifier.
			binary.LittleEndian.PutUint64(out[96:], inode)
		}
		copy(out[fixed:], nameU16)
		return out
	default:
		// FileBothDirectoryInformation: like above but no FileId field.
		// Layout (94 bytes fixed + name).
		const fixed = 94
		out := make([]byte, fixed+len(nameU16))
		binary.LittleEndian.PutUint64(out[8:], filetimeFromTime(info.ModTime()))
		binary.LittleEndian.PutUint64(out[16:], filetimeFromTime(info.ModTime()))
		binary.LittleEndian.PutUint64(out[24:], filetimeFromTime(info.ModTime()))
		binary.LittleEndian.PutUint64(out[32:], filetimeFromTime(info.ModTime()))
		size := uint64(info.Size())
		if info.IsDir() {
			size = 0
		}
		binary.LittleEndian.PutUint64(out[40:], size)
		binary.LittleEndian.PutUint64(out[48:], size)
		attrs := uint32(smb2.FileAttrNormal)
		if info.IsDir() {
			attrs = smb2.FileAttrDirectory
		}
		binary.LittleEndian.PutUint32(out[56:], attrs)
		binary.LittleEndian.PutUint32(out[60:], uint32(len(nameU16)))
		copy(out[fixed:], nameU16)
		return out
	}
}

// --- QUERY_INFO ---

func (d *Dispatcher) handleQueryInfo(rw io.ReadWriter, hdr smb2.Header, body []byte, sess *Session) bool {
	req, err := smb2.DecodeQueryInfoRequest(body)
	if err != nil {
		d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
		return true
	}
	open := sess.GetOpen(req.FileID)
	if open == nil {
		d.Log.Warn("query-info: unknown file id")
		d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
		return true
	}
	d.Log.Debug("query-info",
		"info_type", req.InfoType,
		"info_class", req.FileInfoClass,
		"path", open.Path,
	)

	switch req.InfoType {
	case smb2.InfoTypeFile:
		info := openFileInfo(open)
		buf, ok := encodeFileInfo(req.FileInfoClass, info, open)
		if !ok {
			d.Log.Warn("query-info: unsupported file info class", "class", req.FileInfoClass, "path", open.Path)
			d.respondError(rw, hdr, smb2.StatusNotSupported, sess)
			return true
		}
		d.respondSuccess(rw, hdr, sess, smb2.EncodeQueryInfoResponse(smb2.QueryInfoResponse{Buffer: buf}))
		return true
	case smb2.InfoTypeFilesystem:
		buf, ok := encodeFsInfo(req.FileInfoClass, open)
		if !ok {
			d.Log.Warn("query-info: unsupported fs info class", "class", req.FileInfoClass, "path", open.Path)
			d.respondError(rw, hdr, smb2.StatusNotSupported, sess)
			return true
		}
		d.respondSuccess(rw, hdr, sess, smb2.EncodeQueryInfoResponse(smb2.QueryInfoResponse{Buffer: buf}))
		return true
	case smb2.InfoTypeSecurity:
		buf := minimalSelfRelativeSD()
		d.respondSuccess(rw, hdr, sess, smb2.EncodeQueryInfoResponse(smb2.QueryInfoResponse{Buffer: buf}))
		return true
	default:
		d.respondError(rw, hdr, smb2.StatusNotSupported, sess)
		return true
	}
}

func openFileInfo(o *Open) os.FileInfo {
	if o.IsStream {
		return streamFileInfo{name: o.StreamName, size: int64(len(o.streamBuf))}
	}
	info, _ := os.Lstat(o.Path)
	return info
}

func encodeFileInfo(class uint8, info os.FileInfo, o *Open) ([]byte, bool) {
	if info == nil {
		return nil, false
	}
	t := filetimeFromTime(info.ModTime())
	// F9: use real birth time (statx btime) for CreationTime when available.
	// Falls back to ModTime when the filesystem/kernel doesn't provide btime
	// (e.g. tmpfs, older kernels < 4.11, or filesystems that don't populate
	// stx_btime). LastAccess / LastWrite / ChangeTime remain as ModTime.
	ctime := t
	if o != nil && o.Path != "" && !o.IsStream {
		if bt, ok := birthTime(o.Path); ok {
			ctime = filetimeFromTime(bt)
		}
	}
	attrs := uint32(smb2.FileAttrNormal)
	if info.IsDir() {
		attrs = smb2.FileAttrDirectory
	}
	switch class {
	case smb2.FileBasicInformation:
		out := make([]byte, 40)
		binary.LittleEndian.PutUint64(out[0:], ctime) // CreationTime
		binary.LittleEndian.PutUint64(out[8:], t)     // LastAccessTime
		binary.LittleEndian.PutUint64(out[16:], t)    // LastWriteTime
		binary.LittleEndian.PutUint64(out[24:], t)    // ChangeTime
		binary.LittleEndian.PutUint32(out[32:], attrs)
		return out, true
	case smb2.FileStandardInformation:
		out := make([]byte, 24)
		size := uint64(info.Size())
		if info.IsDir() {
			size = 0
		}
		binary.LittleEndian.PutUint64(out[0:], size)
		binary.LittleEndian.PutUint64(out[8:], size)
		binary.LittleEndian.PutUint32(out[16:], 1) // NumberOfLinks
		if info.IsDir() {
			out[21] = 0x01
		}
		return out, true
	case smb2.FileInternalInformation:
		out := make([]byte, 8)
		// Use the inode-like value: hash of path is a reasonable proxy.
		var v uint64
		for _, c := range o.Path {
			v = v*131 + uint64(c)
		}
		binary.LittleEndian.PutUint64(out[0:], v)
		return out, true
	case smb2.FileEaInformation:
		return make([]byte, 4), true
	case smb2.FileFullEaInformation:
		// Encode the persisted EAs as a FILE_FULL_EA_INFORMATION list. An empty
		// list (no EAs, or a filesystem without xattr support) is a valid
		// zero-length buffer — what NTFS returns for "no EAs".
		eas, err := listEAs(o.Path)
		if err != nil {
			return []byte{}, true
		}
		return encodeFullEaList(eas), true
	case smb2.FileAccessInformation:
		out := make([]byte, 4)
		access := o.GrantedAccess
		if access == 0 {
			access = smb2.AccessFileReadData | smb2.AccessFileReadAttributes | smb2.AccessFileReadEa | smb2.AccessReadControl
		}
		binary.LittleEndian.PutUint32(out[0:], access)
		return out, true
	case smb2.FilePositionInformation:
		return make([]byte, 8), true
	case smb2.FileModeInformation:
		return make([]byte, 4), true
	case smb2.FileAlignmentInformation:
		return make([]byte, 4), true
	case smb2.FileNetworkOpenInformation:
		out := make([]byte, 56)
		size := uint64(info.Size())
		if info.IsDir() {
			size = 0
		}
		binary.LittleEndian.PutUint64(out[0:], ctime) // CreationTime
		binary.LittleEndian.PutUint64(out[8:], t)     // LastAccessTime
		binary.LittleEndian.PutUint64(out[16:], t)    // LastWriteTime
		binary.LittleEndian.PutUint64(out[24:], t)    // ChangeTime
		binary.LittleEndian.PutUint64(out[32:], size)
		binary.LittleEndian.PutUint64(out[40:], size)
		binary.LittleEndian.PutUint32(out[48:], attrs)
		return out, true
	case smb2.FileAttributeTagInformation:
		// FileAttributes(4) + ReparseTag(4)
		out := make([]byte, 8)
		binary.LittleEndian.PutUint32(out[0:], attrs)
		return out, true
	case smb2.FileAlternateNameInformation:
		// FileNameLength(4) + FileName(N) — empty 8.3 alt name.
		out := make([]byte, 4)
		return out, true
	case smb2.FileStreamInformation:
		// Default ::$DATA entry plus one :<name>:$DATA entry per persisted ADS
		// stream. Dirs report no streams.
		if info.IsDir() {
			return []byte{}, true
		}
		return encodeStreamInfoList(o.Path, info.Size()), true
	case smb2.FileNameInformation:
		// FileNameLength(4) + FileName(N) — return basename.
		nameU16 := utf16leName(filepath.Base(o.Path))
		out := make([]byte, 4+len(nameU16))
		binary.LittleEndian.PutUint32(out[0:], uint32(len(nameU16)))
		copy(out[4:], nameU16)
		return out, true
	case smb2.FileAllInformation:
		nameU16 := utf16leName(filepath.Base(o.Path))
		const fixedHead = 40 + 24 + 8 + 4 + 4 + 8 + 4 + 4 // 96
		out := make([]byte, fixedHead+4+len(nameU16))
		size := uint64(info.Size())
		if info.IsDir() {
			size = 0
		}
		// Basic (40)
		binary.LittleEndian.PutUint64(out[0:], ctime) // CreationTime
		binary.LittleEndian.PutUint64(out[8:], t)     // LastAccessTime
		binary.LittleEndian.PutUint64(out[16:], t)    // LastWriteTime
		binary.LittleEndian.PutUint64(out[24:], t)    // ChangeTime
		binary.LittleEndian.PutUint32(out[32:], attrs)
		// Standard (24) at offset 40
		binary.LittleEndian.PutUint64(out[40:], size)
		binary.LittleEndian.PutUint64(out[48:], size)
		binary.LittleEndian.PutUint32(out[56:], 1)
		if info.IsDir() {
			out[61] = 0x01 // Directory
		}
		// Internal (8) at offset 64 — best-effort inode-like value
		var v uint64
		for _, c := range o.Path {
			v = v*131 + uint64(c)
		}
		binary.LittleEndian.PutUint64(out[64:], v)
		// Ea (4) at 72 — zero
		// Access (4) at 76
		access := o.GrantedAccess
		if access == 0 {
			access = smb2.AccessFileReadData | smb2.AccessFileReadAttributes | smb2.AccessFileReadEa | smb2.AccessReadControl
		}
		binary.LittleEndian.PutUint32(out[76:], access)
		// Position (8) at 80 — zero
		// Mode (4) at 88 — zero
		// Alignment (4) at 92 — zero
		// NameInformation: FileNameLength(4) + FileName at offset 96
		binary.LittleEndian.PutUint32(out[fixedHead:], uint32(len(nameU16)))
		copy(out[fixedHead+4:], nameU16)
		return out, true
	}
	return nil, false
}

func encodeFsInfo(class uint8, o *Open) ([]byte, bool) {
	switch class {
	case smb2.FileFsAttributeInformation:
		// FileSystemAttributes(4) + MaxFileNameLength(4) + FileSystemNameLength(4) + Name (UTF-16LE)
		//
		// Bits we claim (MS-FSCC §2.5.1):
		//   0x00000001 FILE_CASE_SENSITIVE_SEARCH
		//   0x00000002 FILE_CASE_PRESERVED_NAMES
		//   0x00000004 FILE_UNICODE_ON_DISK
		//   0x00000008 FILE_PERSISTENT_ACLS
		//   0x00000040 FILE_SUPPORTS_SPARSE_FILES
		//   0x00040000 FILE_NAMED_STREAMS  — needed so macOS will round-trip
		//                                    AppleDouble metadata via streams
		//                                    rather than creating ._foo files.
		//   0x00800000 FILE_SUPPORTS_EXTENDED_ATTRIBUTES — required for macOS
		//                                    Versions ("permanent version
		//                                    storage") to enable on the share.
		const fsAttrs uint32 = 0x0084004F
		name := utf16leName("NTFS")
		out := make([]byte, 12+len(name))
		binary.LittleEndian.PutUint32(out[0:], fsAttrs)
		binary.LittleEndian.PutUint32(out[4:], 255)
		binary.LittleEndian.PutUint32(out[8:], uint32(len(name)))
		copy(out[12:], name)
		return out, true
	case smb2.FileFsVolumeInformation:
		// CreationTime(8) + SerialNumber(4) + LabelLength(4) + Reserved(2) + Label
		label := utf16leName(filepath.Base(o.Tree.Share.Path))
		out := make([]byte, 18+len(label))
		binary.LittleEndian.PutUint64(out[0:], filetimeNow())
		binary.LittleEndian.PutUint32(out[8:], 0xCAFE1337)
		binary.LittleEndian.PutUint32(out[12:], uint32(len(label)))
		copy(out[18:], label)
		return out, true
	case smb2.FileFsSizeInformation:
		total, avail, spu, bps := fsStats(o.Tree.Share.Path)
		out := make([]byte, 24)
		binary.LittleEndian.PutUint64(out[0:], total)
		binary.LittleEndian.PutUint64(out[8:], avail)
		binary.LittleEndian.PutUint32(out[16:], spu)
		binary.LittleEndian.PutUint32(out[20:], bps)
		return out, true
	case smb2.FileFsFullSizeInformation:
		total, avail, spu, bps := fsStats(o.Tree.Share.Path)
		out := make([]byte, 32)
		binary.LittleEndian.PutUint64(out[0:], total)
		binary.LittleEndian.PutUint64(out[8:], avail)
		binary.LittleEndian.PutUint64(out[16:], avail)
		binary.LittleEndian.PutUint32(out[24:], spu)
		binary.LittleEndian.PutUint32(out[28:], bps)
		return out, true
	case smb2.FileFsDeviceInformation:
		// DeviceType(4) + Characteristics(4)
		out := make([]byte, 8)
		binary.LittleEndian.PutUint32(out[0:], 0x07) // FILE_DEVICE_DISK
		binary.LittleEndian.PutUint32(out[4:], 0x20) // FILE_DEVICE_IS_MOUNTED
		return out, true
	}
	return nil, false
}

// --- IOCTL ---

func (d *Dispatcher) handleIoctl(rw io.ReadWriter, hdr smb2.Header, body []byte, sess *Session) bool {
	req, err := smb2.DecodeIoctlRequest(body)
	if err != nil {
		d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
		return true
	}
	d.Log.Debug("ioctl", "ctl_code", fmt.Sprintf("0x%08x", req.CtlCode), "input_len", len(req.InputBuffer))
	switch req.CtlCode {
	case smb2.FsctlPipeTransceive:
		open := sess.GetOpen(req.FileID)
		if open == nil || !open.IsPipe || open.PipeName != "srvsvc" {
			// Unknown pipe — reply with bind_nak so the client stops retrying.
			var callID uint32
			if len(req.InputBuffer) >= 16 {
				callID = binary.LittleEndian.Uint32(req.InputBuffer[12:16])
			}
			d.respondSuccess(rw, hdr, sess, smb2.EncodeIoctlResponse(smb2.IoctlResponse{
				CtlCode:      req.CtlCode,
				FileID:       req.FileID,
				OutputBuffer: dcerpcBindNakBytes(callID),
			}))
			return true
		}
		out := dcerpcHandle(req.InputBuffer, d.Shares)
		if out == nil {
			d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
			return true
		}
		d.respondSuccess(rw, hdr, sess, smb2.EncodeIoctlResponse(smb2.IoctlResponse{
			CtlCode:      req.CtlCode,
			FileID:       req.FileID,
			OutputBuffer: out,
		}))
		return true
	case smb2.FsctlDfsGetReferrals:
		// We are not a DFS root. Reply with FSDRIVER_NOT_DFS so the client
		// stops asking. Some old clients use STATUS_NOT_FOUND here too.
		d.respondError(rw, hdr, smb2.StatusFsDriverRequired, sess)
		return true
	case smb2.FsctlSrvCopyChunk, smb2.FsctlSrvRequestResumeKey, smb2.FsctlPipeWait:
		// Decline gracefully so clients fall back to read+write.
		d.respondError(rw, hdr, smb2.StatusNotSupported, sess)
		return true
	case smb2.FsctlValidateNegotiateInfo:
		// Echo back a minimal response confirming we agree on the negotiate info.
		// Body: Capabilities(4) + ClientGuid(16) + SecurityMode(2) + Dialect(2)
		out := make([]byte, 24)
		binary.LittleEndian.PutUint32(out[0:], 0)
		copy(out[4:20], d.Conn.ServerGuid[:])
		binary.LittleEndian.PutUint16(out[20:], 1) // signing enabled
		binary.LittleEndian.PutUint16(out[22:], uint16(d.Conn.Selection.Dialect))
		resp := smb2.EncodeIoctlResponse(smb2.IoctlResponse{
			CtlCode:      req.CtlCode,
			FileID:       req.FileID,
			OutputBuffer: out,
		})
		d.respondSuccess(rw, hdr, sess, resp)
		return true
	default:
		d.respondError(rw, hdr, smb2.StatusNotSupported, sess)
		return true
	}
}

// --- helpers ---

// unixModeAndInode pulls the POSIX mode bits (low 16 bits of st_mode, including
// the type field) and inode number out of os.FileInfo. Returns (0, 0) for
// FileInfo implementations that don't expose syscall.Stat_t (synthetic streams,
// non-Linux platforms).
func unixModeAndInode(info os.FileInfo) (uint16, uint64) {
	if info == nil {
		return 0, 0
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return 0, 0
	}
	return uint16(st.Mode & 0xFFFF), uint64(st.Ino)
}

const filetimeEpochDelta = 11644473600

func filetimeFromTime(t time.Time) uint64 {
	t = t.UTC()
	if t.Year() < 1601 {
		return 0
	}
	secs := uint64(t.Unix() + filetimeEpochDelta)
	return secs*10_000_000 + uint64(t.Nanosecond())/100
}

func utf16leName(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for _, r := range s {
		if r <= 0xFFFF {
			out = append(out, byte(r), byte(r>>8))
		} else {
			r -= 0x10000
			hi := 0xD800 + uint16(r>>10)
			lo := 0xDC00 + uint16(r&0x3FF)
			out = append(out, byte(hi), byte(hi>>8), byte(lo), byte(lo>>8))
		}
	}
	return out
}

// silence unused-vars for the dispatcher's helpers when not referenced.
var _ = errors.New
var _ = fmt.Errorf

// handleChangeNotify watches the directory referenced by FileID via inotify
// and replies asynchronously when an event arrives. The immediate reply is
// STATUS_PENDING with an AsyncId; the eventual completion is signed and
// posted from a goroutine.
func (d *Dispatcher) handleChangeNotify(rw io.ReadWriter, hdr smb2.Header, body []byte, sess *Session) bool {
	req, err := smb2.DecodeChangeNotifyRequest(body)
	if err != nil {
		d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
		return true
	}
	open := sess.GetOpen(req.FileID)
	if open == nil || !open.IsDir {
		d.respondError(rw, hdr, smb2.StatusInvalidParameter, sess)
		return true
	}

	w, err := inotify.New(open.Path)
	if err != nil {
		d.Log.Warn("inotify init failed", "path", open.Path, "err", err)
		d.respondError(rw, hdr, smb2.StatusNotSupported, sess)
		return true
	}

	asyncID := d.nextAsyncID.Add(1)

	// Send STATUS_PENDING (async-format header) immediately.
	d.sendAsync(rw, hdr, sess, asyncID, smb2.StatusPending, []byte{0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	go func() {
		defer w.Close()
		go w.Watch()

		// Collect events until the buffer would overflow or the dir is closed.
		var entries []smb2.NotifyEntry
		timer := time.NewTimer(5 * time.Minute)
		defer timer.Stop()

		for {
			select {
			case ev, ok := <-w.Events:
				if !ok || ev.Event == inotify.WatchStop {
					goto done
				}
				rel, err := filepath.Rel(open.Path, ev.Path)
				if err != nil {
					continue
				}
				rel = strings.ReplaceAll(rel, "/", "\\")
				action := actionForEvent(ev.Event)
				if action == 0 {
					continue
				}
				entries = append(entries, smb2.NotifyEntry{Action: action, Name: rel})
				// Drain quickly: collect a short burst, then send.
				drainTimer := time.NewTimer(30 * time.Millisecond)
				drain := true
				for drain {
					select {
					case ev2, ok := <-w.Events:
						if !ok || ev2.Event == inotify.WatchStop {
							drain = false
							break
						}
						rel2, err := filepath.Rel(open.Path, ev2.Path)
						if err != nil {
							continue
						}
						rel2 = strings.ReplaceAll(rel2, "/", "\\")
						a := actionForEvent(ev2.Event)
						if a == 0 {
							continue
						}
						entries = append(entries, smb2.NotifyEntry{Action: a, Name: rel2})
					case <-drainTimer.C:
						drain = false
					}
				}
				drainTimer.Stop()
				goto done
			case <-timer.C:
				goto done
			}
		}
	done:
		buf := smb2.EncodeFileNotifyInformation(entries)
		respBody := smb2.EncodeChangeNotifyResponse(smb2.ChangeNotifyResponse{Buffer: buf})
		status := smb2.StatusSuccess
		if len(entries) == 0 {
			// Watcher closed without events.
			status = smb2.StatusCancelled
		}
		d.sendAsync(rw, hdr, sess, asyncID, status, respBody)
	}()
	return true
}

func actionForEvent(t inotify.EventType) uint32 {
	switch t {
	case inotify.FileCreate, inotify.FolderCreate:
		return smb2.FileActionAdded
	case inotify.Delete:
		return smb2.FileActionRemoved
	case inotify.Modified:
		return smb2.FileActionModified
	case inotify.MovedFrom:
		return smb2.FileActionRenamedOldName
	case inotify.MovedTo:
		return smb2.FileActionRenamedNewName
	}
	return 0
}

// sendAsync builds and writes an SMB2 async-format response (FlagAsyncCommand
// set, AsyncId in bytes 32-39 instead of TreeId/Reserved). The whole frame
// is signed end-to-end like a sync response.
func (d *Dispatcher) sendAsync(rw io.ReadWriter, reqHdr smb2.Header, sess *Session, asyncID uint64, status smb2.Status, body []byte) {
	respHdr := smb2.Header{
		CreditCharge:   reqHdr.CreditCharge,
		Status:         uint32(status),
		Command:        reqHdr.Command,
		CreditResponse: grantCredits(reqHdr.CreditCharge, reqHdr.CreditResponse),
		Flags:          smb2.FlagServerToRedir,
		MessageID:      reqHdr.MessageID,
		SessionID:      reqHdr.SessionID,
	}
	out := make([]byte, smb2.HeaderSize+len(body))
	_ = smb2.EncodeAsyncHeader(out[:smb2.HeaderSize], respHdr, asyncID)
	copy(out[smb2.HeaderSize:], body)
	willEncrypt := sess != nil && len(sess.S2CCipherKey) > 0 && d.Conn.Selection.Cipher != 0 &&
		sess.GotEncrypted
	if !willEncrypt && sess != nil && len(sess.SigningKey) > 0 {
		smb3.SignMessage(uint16(d.Conn.Selection.SigningAlgo), sess.SigningKey, out)
	}
	_ = d.writeFrame(rw, sess, out)
}

