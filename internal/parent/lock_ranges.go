package parent

import "sync"

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

// rangeTable is the portable core of the darwin in-process lock manager. It is
// unused on linux (which delegates to kernel OFD locks) but lives in an
// untagged file so its conflict logic is unit-testable on any host.
type rangeTable struct {
	locks map[fileKey][]lockRange
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
}

func newLockTable() *lockTable { return &lockTable{t: newRangeTable()} }

func (l *lockTable) apply(key fileKey, owner *Open, start, length uint64, kind lockKind) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.t.apply(key, owner, start, length, kind)
}

func (l *lockTable) releaseOwner(key fileKey, owner *Open) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.t.releaseOwner(key, owner)
}

func (l *lockTable) conflict(key fileKey, owner *Open, start, length uint64, write bool) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.t.conflict(key, owner, start, length, write)
}

// apply adds or removes a lock. For lockShared/lockExclusive it returns
// errLockConflict if an existing range from a DIFFERENT owner overlaps and
// either side is exclusive; otherwise it appends the range. For lockUnlock it
// removes ranges owned by `owner` that exactly match (start,length); a
// no-match unlock is a no-op (rollback safety).
func (t *rangeTable) apply(key fileKey, owner *Open, start, length uint64, kind lockKind) error {
	switch kind {
	case lockUnlock:
		ranges := t.locks[key]
		out := ranges[:0]
		for _, r := range ranges {
			if r.owner == owner && r.start == start && r.length == length {
				continue
			}
			out = append(out, r)
		}
		if len(out) == 0 {
			delete(t.locks, key)
		} else {
			t.locks[key] = out
		}
		return nil
	case lockShared, lockExclusive:
		exclusive := kind == lockExclusive
		for _, r := range t.locks[key] {
			if r.owner == owner {
				continue
			}
			if !rangesOverlap(start, length, r.start, r.length) {
				continue
			}
			if exclusive || r.exclusive {
				return errLockConflict
			}
		}
		t.locks[key] = append(t.locks[key], lockRange{owner: owner, start: start, length: length, exclusive: exclusive})
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
	if len(out) == 0 {
		delete(t.locks, key)
	} else {
		t.locks[key] = out
	}
}
