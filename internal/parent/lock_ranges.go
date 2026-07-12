package parent

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

// rangesOverlap reports whether [aStart,aStart+aLen) and [bStart,bStart+bLen)
// share any byte. A zero-length range covers no bytes and never overlaps.
func rangesOverlap(aStart, aLen, bStart, bLen uint64) bool {
	if aLen == 0 || bLen == 0 {
		return false
	}
	return aStart < bStart+bLen && bStart < aStart+aLen
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
