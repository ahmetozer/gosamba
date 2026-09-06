package parent

import (
	"sync"
	"sync/atomic"
)

// fileKey identifies a file by device + inode for in-process lock tracking.
type fileKey struct {
	dev uint64
	ino uint64
}

type lockRange struct {
	owner         *Open
	start, length uint64
	exclusive     bool
}

// kind maps a tracked range back to the lockKind that created it, so a rolled
// back LOCK request can re-apply the handle's prior locks exactly as the
// client originally asked for them.
func (r lockRange) kind() lockKind {
	if r.exclusive {
		return lockExclusive
	}
	return lockShared
}

// Byte-range bookkeeping is bounded. Every granted element of every LOCK
// request adds an entry that only a matching UNLOCK or a CLOSE removes, so
// without a cap a client can grow the table indefinitely — and every entry is
// walked by the conflict scan that runs on each READ and WRITE. The caps are
// far above what real clients use (SQLite and Office hold a handful of ranges
// per handle) while keeping the worst case bounded and the scan short.
const (
	// maxLockRangesPerFile caps the ranges tracked for one file across all handles.
	maxLockRangesPerFile = 4096
	// maxLockRangesPerOwner caps the ranges a single open handle may hold on one file.
	maxLockRangesPerOwner = 1024
)

// rangeTable is the portable core of the in-process lock manager: on darwin it
// is the sole authority for byte-range locking, on linux it shadows the
// kernel's OFD locks. It lives in an untagged file so its conflict logic is
// unit-testable on any host.
type rangeTable struct {
	locks map[fileKey][]lockRange
	// n is the total number of tracked ranges across every file. It exists so
	// the mutex-guarded lockTable can publish "nothing is locked anywhere" to
	// the I/O hot path without walking the map.
	n int
}

func newRangeTable() *rangeTable { return &rangeTable{locks: map[fileKey][]lockRange{}} }

// rangeEnd returns the exclusive end of [start,start+length), saturating at
// 2^64-1 instead of wrapping. SMB2 clients express "lock to end of file" as a
// huge length (commonly 0xFFFFFFFFFFFFFFFF); computing start+length directly
// wraps to a small number and makes the range appear to cover almost nothing,
// so two conflicting locks would both be granted.
func rangeEnd(start, length uint64) uint64 {
	end := start + length
	if end < start {
		return ^uint64(0)
	}
	return end
}

// rangesOverlap reports whether [aStart,aStart+aLen) and [bStart,bStart+bLen)
// share any byte. A zero-length range covers no bytes and never overlaps.
func rangesOverlap(aStart, aLen, bStart, bLen uint64) bool {
	if aLen == 0 || bLen == 0 {
		return false
	}
	return aStart < rangeEnd(bStart, bLen) && bStart < rangeEnd(aStart, aLen)
}

// sameRange reports whether r covers exactly [start,start+length).
func (r lockRange) sameRange(start, length uint64) bool {
	return r.start == start && r.length == length
}

// conflict reports whether an I/O of [start,start+length) by owner would touch
// a range locked by a DIFFERENT owner in a way SMB2 forbids: any overlap with
// an exclusive lock, or — for a write — any overlap at all.
func (t *rangeTable) conflict(key fileKey, owner *Open, start, length uint64, write bool) bool {
	if length == 0 {
		return false
	}
	for _, r := range t.locks[key] {
		if r.owner == owner {
			continue
		}
		if !rangesOverlap(start, length, r.start, r.length) {
			continue
		}
		if write || r.exclusive {
			return true
		}
	}
	return false
}

// lockTable is a mutex-guarded rangeTable. Both the darwin and linux lock
// managers embed one: darwin uses it as the sole authority for byte-range
// locking, linux keeps it alongside the kernel's OFD locks so READ/WRITE can be
// checked against SMB2 lock state without a syscall per I/O (the kernel would
// not block our own process's reads and writes anyway — POSIX locks are
// advisory and OFD locks never conflict with the fd that holds them).
type lockTable struct {
	mu sync.Mutex
	t  *rangeTable

	// n mirrors t.n outside the mutex. Conflict checks now run on every READ
	// and WRITE, and on a server where nobody holds a byte-range lock (the
	// overwhelmingly common case) that check must not cost a process-global
	// mutex acquisition — let alone the fstat the callers do to build the
	// fileKey. One atomic load answers it instead.
	n atomic.Int64

	// released is closed and replaced whenever a tracked range disappears,
	// which is the only event that can turn a refused lock into a grantable
	// one. Blocking LOCK requests park on it (see handleLock); it is created
	// lazily so a server with no waiters allocates nothing.
	released chan struct{}
}

func newLockTable() *lockTable { return &lockTable{t: newRangeTable()} }

func (l *lockTable) apply(key fileKey, owner *Open, start, length uint64, kind lockKind) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	before := l.t.n
	err := l.t.apply(key, owner, start, length, kind)
	l.publish(before)
	return err
}

func (l *lockTable) releaseOwner(key fileKey, owner *Open) {
	l.mu.Lock()
	defer l.mu.Unlock()
	before := l.t.n
	l.t.releaseOwner(key, owner)
	l.publish(before)
}

func (l *lockTable) conflict(key fileKey, owner *Open, start, length uint64, write bool) bool {
	if l.empty() {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.t.conflict(key, owner, start, length, write)
}

// empty reports whether the process tracks no byte ranges at all. Callers use
// it to skip the mutex (and their own fstat) on unlocked I/O. A lock taken
// concurrently with this check may be missed, which is harmless: a client has
// no ordering guarantee between its LOCK and another client's in-flight I/O.
func (l *lockTable) empty() bool { return l.n.Load() == 0 }

// snapshot copies the ranges owner currently holds on key, for a LOCK request
// that may have to put them back.
func (l *lockTable) snapshot(key fileKey, owner *Open) []lockRange {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []lockRange
	for _, r := range l.t.locks[key] {
		if r.owner == owner {
			out = append(out, r)
		}
	}
	return out
}

// atCapacity reports whether recording one more range for (key, owner) would
// exceed the caps. Linux consults this before asking the kernel for a lock,
// because a lock the table cannot record would be invisible to the READ/WRITE
// conflict checks.
func (l *lockTable) atCapacity(key fileKey, owner *Open) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	ranges := l.t.locks[key]
	if len(ranges) >= maxLockRangesPerFile {
		return true
	}
	owned := 0
	for _, r := range ranges {
		if r.owner == owner {
			owned++
		}
	}
	return owned >= maxLockRangesPerOwner
}

// releaseSignal returns a channel closed the next time any range is released.
// A blocking LOCK request MUST take the channel *before* its failed attempt:
// subscribing afterwards can miss a release that happened in between and park
// the request until its timeout for no reason.
func (l *lockTable) releaseSignal() <-chan struct{} {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.released == nil {
		l.released = make(chan struct{})
	}
	return l.released
}

// publish republishes the range count and, when ranges disappeared, wakes
// every parked LOCK request so it can retry. Called with mu held.
func (l *lockTable) publish(before int) {
	l.n.Store(int64(l.t.n))
	if l.t.n < before && l.released != nil {
		close(l.released)
		l.released = nil
	}
}

// apply adds or removes a lock. For lockShared/lockExclusive it returns
// errLockConflict if an existing range from a DIFFERENT owner overlaps and
// either side is exclusive, errLockLimit if the file or the handle already
// tracks as many ranges as it may; otherwise it appends the range. For
// lockUnlock it removes ranges owned by `owner` that exactly match
// (start,length); a no-match unlock is a no-op (rollback safety).
func (t *rangeTable) apply(key fileKey, owner *Open, start, length uint64, kind lockKind) error {
	// An SMB2 zero-length range covers no bytes (MS-SMB2 §2.2.26.1): it can
	// neither conflict nor be conflicted with, so tracking it would only burn
	// a table slot. Linux already discards these before reaching fcntl (where
	// a zero length would mean "to end of file"); doing the same here keeps
	// both platforms on identical semantics.
	if length == 0 {
		return nil
	}
	switch kind {
	case lockUnlock:
		ranges := t.locks[key]
		out := ranges[:0]
		for _, r := range ranges {
			if r.owner == owner && r.sameRange(start, length) {
				continue
			}
			out = append(out, r)
		}
		t.n -= len(ranges) - len(out)
		if len(out) == 0 {
			delete(t.locks, key)
		} else {
			t.locks[key] = out
		}
		return nil
	case lockShared, lockExclusive:
		exclusive := kind == lockExclusive
		owned := 0
		for _, r := range t.locks[key] {
			if r.owner == owner {
				owned++
				// The handle already holds exactly this range: re-locking is
				// a no-op, not a second entry. Tracking the duplicate would
				// let a client grow the table by repeating one request, and
				// would make a rollback that unlocks the range look like it
				// still holds it.
				if r.sameRange(start, length) && r.exclusive == exclusive {
					return nil
				}
				continue
			}
			if !rangesOverlap(start, length, r.start, r.length) {
				continue
			}
			if exclusive || r.exclusive {
				return errLockConflict
			}
		}
		if len(t.locks[key]) >= maxLockRangesPerFile || owned >= maxLockRangesPerOwner {
			return errLockLimit
		}
		t.locks[key] = append(t.locks[key], lockRange{owner: owner, start: start, length: length, exclusive: exclusive})
		t.n++
		return nil
	default:
		return nil
	}
}

// releaseOwner drops every range owned by owner; deletes emptied keys.
func (t *rangeTable) releaseOwner(key fileKey, owner *Open) {
	ranges := t.locks[key]
	out := ranges[:0]
	for _, r := range ranges {
		if r.owner != owner {
			out = append(out, r)
		}
	}
	t.n -= len(ranges) - len(out)
	if len(out) == 0 {
		delete(t.locks, key)
	} else {
		t.locks[key] = out
	}
}

// rangesDiff returns the entries of a that have no counterpart in b, comparing
// the range itself (owner is implied: both lists belong to one handle).
func rangesDiff(a, b []lockRange) []lockRange {
	var out []lockRange
	for _, r := range a {
		found := false
		for _, o := range b {
			if o.sameRange(r.start, r.length) && o.exclusive == r.exclusive {
				found = true
				break
			}
		}
		if !found {
			out = append(out, r)
		}
	}
	return out
}
