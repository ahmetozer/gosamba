package parent

import (
	"encoding/binary"
	"errors"
	"strings"

	"golang.org/x/sys/unix"
)

// adsXattrPrefix namespaces NTFS alternate-data-stream (ADS) contents stored as
// Linux user xattrs. macOS/Windows clients address streams via the NTFS syntax
// `file:stream:$DATA`; we persist each stream's bytes under
// `user.gosamba.ads.<stream>` so they survive across handles (and reboots)
// instead of living in an ephemeral in-memory buffer.
const adsXattrPrefix = "user.gosamba.ads."

// eaXattrPrefix is the Linux namespace for ordinary extended attributes (EAs)
// set via SET_INFO FileFullEaInformation. NTFS EA names are case-insensitive
// ASCII; we lower-case and prefix with "user." so they live alongside other
// user xattrs but are still distinguishable from our ADS storage.
const eaXattrPrefix = "user."

// errXattrUnsupported is returned (wrapped) when the underlying filesystem does
// not support extended attributes (ENOTSUP). Callers and tests can use
// errors.Is to skip gracefully rather than fail.
var errXattrUnsupported = errors.New("filesystem does not support extended attributes")

// streamXattrName maps an NTFS stream name to its backing Linux xattr name.
func streamXattrName(stream string) string {
	return adsXattrPrefix + stream
}

// eaXattrName maps an NTFS EA name to its backing Linux xattr name. NTFS EA
// names are ASCII and case-insensitive; we sanitize to lower-case and strip any
// characters that are illegal in a Linux xattr name (NUL, '/').
func eaXattrName(name string) string {
	name = strings.ToLower(name)
	name = strings.Map(func(r rune) rune {
		if r == 0 || r == '/' {
			return -1
		}
		return r
	}, name)
	return eaXattrPrefix + name
}

// classifyXattrErr converts a raw unix errno from a get/set/list/remove call
// into one of: nil (no data / not present -> treat as empty), errXattrUnsupported,
// or the original error.
func classifyXattrErr(err error) error {
	if err == nil {
		return nil
	}
	// ENODATA = "attribute does not exist" on Linux. (On BSD/macOS the same
	// condition is ENOATTR, but on Linux ENOATTR is an alias for ENODATA and
	// not exported by x/sys/unix, so we only test ENODATA here.)
	if errors.Is(err, unix.ENODATA) {
		// Attribute not present — caller treats as empty.
		return nil
	}
	if errors.Is(err, unix.ENOTSUP) {
		return errXattrUnsupported
	}
	return err
}

// getxattr reads the full value of a single xattr. A missing attribute returns
// (nil, nil). ENOTSUP returns errXattrUnsupported.
func getxattr(path, name string) ([]byte, error) {
	// First size query, then read.
	size, err := unix.Getxattr(path, name, nil)
	if err != nil {
		if e := classifyXattrErr(err); e == nil {
			return nil, nil
		} else {
			return nil, e
		}
	}
	if size == 0 {
		return []byte{}, nil
	}
	buf := make([]byte, size)
	n, err := unix.Getxattr(path, name, buf)
	if err != nil {
		if e := classifyXattrErr(err); e == nil {
			return nil, nil
		} else {
			return nil, e
		}
	}
	return buf[:n], nil
}

// listXattrNames enumerates all xattr names on path. A filesystem without xattr
// support returns errXattrUnsupported.
func listXattrNames(path string) ([]string, error) {
	size, err := unix.Listxattr(path, nil)
	if err != nil {
		if e := classifyXattrErr(err); e == nil {
			return nil, nil
		} else {
			return nil, e
		}
	}
	if size == 0 {
		return nil, nil
	}
	buf := make([]byte, size)
	n, err := unix.Listxattr(path, buf)
	if err != nil {
		if e := classifyXattrErr(err); e == nil {
			return nil, nil
		} else {
			return nil, e
		}
	}
	// Listxattr returns NUL-separated names.
	var names []string
	for _, raw := range strings.Split(string(buf[:n]), "\x00") {
		if raw != "" {
			names = append(names, raw)
		}
	}
	return names, nil
}

// readStreamXattr returns the persisted bytes for the named stream on path.
// A stream that was never written returns (nil, nil).
func readStreamXattr(path, stream string) ([]byte, error) {
	return getxattr(path, streamXattrName(stream))
}

// writeStreamXattr persists data as the named stream's content. A zero-length
// write still creates the attribute so the stream "exists".
func writeStreamXattr(path, stream string, data []byte) error {
	err := unix.Setxattr(path, streamXattrName(stream), data, 0)
	if err == nil {
		return nil
	}
	if errors.Is(err, unix.ENOTSUP) {
		return errXattrUnsupported
	}
	return err
}

// removeStreamXattr deletes the named stream. A missing stream is not an error.
func removeStreamXattr(path, stream string) error {
	err := unix.Removexattr(path, streamXattrName(stream))
	if e := classifyXattrErr(err); e != nil {
		return e
	}
	return nil
}

// streamInfo is one enumerated alternate data stream.
type streamInfo struct {
	Name string
	Size int
}

// listStreams enumerates persisted ADS streams on path: every xattr under the
// adsXattrPrefix, with the prefix stripped to recover the NTFS stream name and
// its stored byte size.
func listStreams(path string) ([]streamInfo, error) {
	names, err := listXattrNames(path)
	if err != nil {
		return nil, err
	}
	var out []streamInfo
	for _, n := range names {
		if !strings.HasPrefix(n, adsXattrPrefix) {
			continue
		}
		stream := strings.TrimPrefix(n, adsXattrPrefix)
		if stream == "" {
			continue
		}
		size, gerr := unix.Getxattr(path, n, nil)
		if gerr != nil {
			if e := classifyXattrErr(gerr); e != nil {
				return nil, e
			}
			size = 0
		}
		out = append(out, streamInfo{Name: stream, Size: size})
	}
	return out, nil
}

// eaInfo is one extended attribute as exposed to SMB clients.
type eaInfo struct {
	Name  string
	Value []byte
}

// setEA persists an extended attribute under "user.<name>".
func setEA(path, name string, val []byte) error {
	err := unix.Setxattr(path, eaXattrName(name), val, 0)
	if err == nil {
		return nil
	}
	if errors.Is(err, unix.ENOTSUP) {
		return errXattrUnsupported
	}
	return err
}

// listEAs enumerates user EAs on path, EXCLUDING our internal ADS storage
// (user.gosamba.ads.*) and any other gosamba-internal names. The returned EA
// name has the "user." prefix stripped.
func listEAs(path string) ([]eaInfo, error) {
	names, err := listXattrNames(path)
	if err != nil {
		return nil, err
	}
	var out []eaInfo
	for _, n := range names {
		if !strings.HasPrefix(n, eaXattrPrefix) {
			continue // skip non-user namespaces (system.*, security.*, trusted.*)
		}
		if strings.HasPrefix(n, adsXattrPrefix) {
			continue // skip our ADS-backing storage
		}
		val, gerr := getxattr(path, n)
		if gerr != nil {
			return nil, gerr
		}
		out = append(out, eaInfo{Name: strings.TrimPrefix(n, eaXattrPrefix), Value: val})
	}
	return out, nil
}

// parseFullEaList decodes a FILE_FULL_EA_INFORMATION chained list (MS-FSCC
// §2.4.15). Each entry: NextEntryOffset(4), Flags(1), EaNameLength(1),
// EaValueLength(2), EaName(ASCII, NUL-terminated), EaValue. A zero
// NextEntryOffset marks the last entry. Malformed buffers are truncated safely.
func parseFullEaList(buf []byte) []eaInfo {
	var out []eaInfo
	off := 0
	for off+8 <= len(buf) {
		next := binary.LittleEndian.Uint32(buf[off:])
		nameLen := int(buf[off+5])
		valLen := int(binary.LittleEndian.Uint16(buf[off+6:]))
		nameStart := off + 8
		valStart := nameStart + nameLen + 1 // skip NUL terminator
		if nameStart+nameLen > len(buf) || valStart+valLen > len(buf) {
			break
		}
		name := string(buf[nameStart : nameStart+nameLen])
		val := append([]byte{}, buf[valStart:valStart+valLen]...)
		if name != "" {
			out = append(out, eaInfo{Name: name, Value: val})
		}
		if next == 0 {
			break
		}
		off += int(next)
	}
	return out
}

// encodeFullEaList encodes EAs into a FILE_FULL_EA_INFORMATION chained list
// (MS-FSCC §2.4.15). Returns a zero-length slice for no EAs (valid "no EAs"
// response). EA names are emitted upper-cased ASCII (NTFS convention) and
// 4-byte aligned per entry except the last.
func encodeFullEaList(eas []eaInfo) []byte {
	if len(eas) == 0 {
		return []byte{}
	}
	var out []byte
	for i, ea := range eas {
		name := []byte(strings.ToUpper(ea.Name))
		entry := make([]byte, 8+len(name)+1+len(ea.Value))
		// out[off+0..3] NextEntryOffset (filled below), out[off+4] Flags=0
		entry[5] = byte(len(name))
		binary.LittleEndian.PutUint16(entry[6:], uint16(len(ea.Value)))
		copy(entry[8:], name)
		// entry[8+len(name)] = NUL (already zero)
		copy(entry[8+len(name)+1:], ea.Value)
		if i < len(eas)-1 {
			for len(entry)%4 != 0 {
				entry = append(entry, 0)
			}
			binary.LittleEndian.PutUint32(entry[0:], uint32(len(entry)))
		}
		out = append(out, entry...)
	}
	return out
}

// encodeStreamInfoList builds a FILE_STREAM_INFORMATION list (MS-FSCC §2.4.40):
// the default ::$DATA entry (size = file size) followed by one :<name>:$DATA
// entry per persisted ADS stream. Each entry:
// NextEntryOffset(4), StreamNameLength(4), StreamSize(8),
// StreamAllocationSize(8), StreamName (UTF-16LE).
func encodeStreamInfoList(path string, fileSize int64) []byte {
	type sentry struct {
		name string
		size int64
	}
	entries := []sentry{{name: "::$DATA", size: fileSize}}
	if streams, err := listStreams(path); err == nil {
		for _, s := range streams {
			entries = append(entries, sentry{name: ":" + s.Name + ":$DATA", size: int64(s.Size)})
		}
	}

	var out []byte
	for i, e := range entries {
		nameU16 := utf16leName(e.name)
		const fixed = 24
		rec := make([]byte, fixed+len(nameU16))
		binary.LittleEndian.PutUint32(rec[4:], uint32(len(nameU16)))
		binary.LittleEndian.PutUint64(rec[8:], uint64(e.size))
		binary.LittleEndian.PutUint64(rec[16:], uint64(e.size))
		copy(rec[fixed:], nameU16)
		// Pad each record to an 8-byte boundary; set NextEntryOffset on all but
		// the last.
		for len(rec)%8 != 0 {
			rec = append(rec, 0)
		}
		if i < len(entries)-1 {
			binary.LittleEndian.PutUint32(rec[0:], uint32(len(rec)))
		}
		out = append(out, rec...)
	}
	return out
}
