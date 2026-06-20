package parent

import (
	"crypto/rand"
	"errors"
	"io"
	"io/fs"
	"os"
	"strings"
	"time"

	"github.com/ahmetozer/gosamba/internal/smb2"
	"github.com/ahmetozer/gosamba/internal/vfs"
)

// streamFileInfo is the os.FileInfo we return for a synthetic named-stream Open.
// Size reflects the in-memory stream buffer; everything else is constant.
type streamFileInfo struct {
	name string
	size int64
}

func (s streamFileInfo) Name() string       { return s.name }
func (s streamFileInfo) Size() int64        { return s.size }
func (s streamFileInfo) Mode() fs.FileMode  { return 0 }
func (s streamFileInfo) ModTime() time.Time { return time.Now() }
func (s streamFileInfo) IsDir() bool        { return false }
func (s streamFileInfo) Sys() any           { return nil }

// afpInfoSize is the fixed size of the NT "AFP_AfpInfo" metadata stream
// (MS/Apple AFP_INFO_SIZE = 0x3c). macOS reads this stream during a copy and
// requires a well-formed blob — a short/empty read makes Finder abort the copy
// before writing file data. See Samba source3/include/MacExtensions.h.
const afpInfoSize = 60

// isAFPInfoStream reports whether a stream name is Apple's metadata stream.
func isAFPInfoStream(name string) bool { return strings.EqualFold(name, "AFP_AfpInfo") }

// synthAFPInfo builds an empty-but-valid 60-byte AFP_AfpInfo blob: signature
// "AFP\0", version 0x00000100 (big-endian), zeroed FinderInfo. Mirrors Samba's
// afpinfo_new + afpinfo_pack (vfs_fruit) for a freshly-created, not-yet-written
// metadata stream.
func synthAFPInfo() []byte {
	b := make([]byte, afpInfoSize)
	b[0], b[1], b[2], b[3] = 'A', 'F', 'P', 0x00 // afpi_Signature
	b[4], b[5], b[6], b[7] = 0x00, 0x00, 0x01, 0x00 // afpi_Version 0x00000100 (BE)
	return b
}

// splitStreamName parses an SMB CREATE name that may carry NTFS alternate-
// data-stream syntax `path[:streamname[:type]]` and returns the base path,
// the stream name (empty for the default $DATA stream), and ok=false if the
// stream type is something other than $DATA.
//
// macOS writes extended attributes via stream syntax such as
// `foo.txt:com.apple.metadata:_kMDItemUserTags:$DATA`. The stream name itself
// can contain colons, so the split is "first colon separates basename from
// stream-component, last colon (if present and the suffix is `$DATA`)
// separates stream-name from stream-type".
func splitStreamName(name string) (base, stream string, ok bool) {
	i := strings.IndexByte(name, ':')
	if i < 0 {
		return name, "", true
	}
	base = name[:i]
	rest := name[i+1:]
	if j := strings.LastIndexByte(rest, ':'); j >= 0 {
		if !strings.EqualFold(rest[j+1:], "$DATA") {
			return "", "", false
		}
		stream = rest[:j]
		return base, stream, true
	}
	return base, rest, true
}

// handleCreateNamedStream services a CREATE on `path:streamname[:$DATA]`. The
// base file must exist; stream contents are persisted as a Linux user xattr
// (user.gosamba.ads.<stream>) so they survive across handles. READ/WRITE/
// SET_INFO operate on an in-memory streamBuf seeded here from the xattr; the
// buffer is flushed back to the xattr (or removed on DeleteOnClose) at CLOSE.
func (d *Dispatcher) handleCreateNamedStream(rw io.ReadWriter, hdr smb2.Header, sess *Session, tree *Tree, req smb2.CreateRequest, baseName, streamName string) bool {
	// Named-stream writes are mutations; deny them on read-only shares.
	// Reads of existing streams on a read-only share are allowed: a plain
	// Open disposition with no write-access bits is still served below.
	if tree.Share.ReadOnly {
		const writeMask = smb2.AccessFileWriteData | smb2.AccessFileAppendData |
			smb2.AccessGenericWrite | smb2.AccessGenericAll |
			0x00000100 | // FILE_WRITE_ATTRIBUTES
			0x00010000 // DELETE
		if req.CreateDisposition != smb2.CreateDispositionOpen || req.DesiredAccess&writeMask != 0 {
			d.respondError(rw, hdr, smb2.StatusAccessDenied, sess)
			return true
		}
	}
	osPath, err := vfs.ResolveSecure(tree.Share.Path, baseName)
	if err != nil {
		d.respondError(rw, hdr, smb2.StatusAccessDenied, sess)
		return true
	}
	st, statErr := os.Lstat(osPath)
	if statErr != nil {
		// Streams require a base file. Map missing/permission/traversal to
		// OBJECT_NAME_NOT_FOUND so the client doesn't retry.
		d.respondError(rw, hdr, smb2.StatusObjectNameNotFound, sess)
		return true
	}
	if st.IsDir() {
		// Directories don't have $DATA streams. Samba returns FILE_IS_A_DIRECTORY.
		d.respondError(rw, hdr, smb2.StatusFileIsADirectory, sess)
		return true
	}

	maxAccess := uint32(0x001F01FF) // FILE_ALL_ACCESS
	if tree.Share.ReadOnly {
		maxAccess = 0x001200A9 // FILE_GENERIC_READ | FILE_GENERIC_EXECUTE
	}
	open := &Open{
		Path:          osPath,
		Tree:          tree,
		IsStream:      true,
		StreamName:    streamName,
		GrantedAccess: maxAccess,
	}
	// Load any previously persisted stream content so READ returns it. A stream
	// that was never written (or a filesystem without xattr support) yields an
	// empty buffer; writes still accumulate and get flushed at CLOSE.
	if buf, rerr := readStreamXattr(osPath, streamName); rerr == nil {
		open.streamBuf = buf
	} else if !errors.Is(rerr, errXattrUnsupported) {
		d.Log.Warn("stream xattr read failed", "path", osPath, "stream", streamName, "err", rerr)
	}
	// Apple's AFP_AfpInfo metadata stream must always present a valid 60-byte
	// blob. macOS reads it during a copy; returning 0 bytes makes Finder abort
	// before writing the file data. Fabricate one when nothing is stored yet —
	// flagged synthetic so a read-only open doesn't persist a spurious xattr.
	if isAFPInfoStream(streamName) && len(open.streamBuf) < afpInfoSize {
		open.streamBuf = synthAFPInfo()
		open.streamSynthetic = true
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
		AllocationSize: uint64(len(open.streamBuf)),
		EndOfFile:      uint64(len(open.streamBuf)),
		FileID:         open.FileID,
		CreateContexts: buildCreateResponseContexts(req.CreateContexts, d.Conn, maxAccess),
	})
	d.respondSuccess(rw, hdr, sess, resp)
	return true
}
