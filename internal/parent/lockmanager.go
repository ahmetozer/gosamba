package parent

// sharedLockManager is the process-global byte-range lock manager. On darwin it
// holds the in-process (dev,ino)-keyed table so byte-range locks are enforced
// across ALL client connections; on linux it is stateless (kernel OFD locks).
//
// It MUST be a single instance for the entire process: byte-range locking
// only prevents client-vs-client conflicts if every connection consults the
// same table. A per-connection instance (as darwin previously used) lets two
// different clients hold conflicting exclusive locks on the same file.
var sharedLockManager = newLockManager()
