//go:build darwin

package parent

import (
	"fmt"
	"syscall"
)

// maxSupplementaryGroups is NGROUPS_MAX on darwin. The kernel credential still
// carries the traditional 16-entry group list and setgroups(2) rejects anything
// longer with EINVAL, even though getgrouplist(3) happily reports more (macOS
// resolves membership past 16 through OpenDirectory, not the process
// credential). Callers truncate to this before dropping, which can only ever
// narrow the resulting credentials.
const maxSupplementaryGroups = 16

// applyPrivDrop performs the credential drop on darwin. macOS credentials are
// process-wide at the kernel level (not per-thread as on Linux), so a single
// Setre{u,g}id covers every goroutine/thread — the property the Linux path
// secures via the runtime's all-threads coordination. Darwin has no
// Setresuid/Setresgid; Setreuid/Setregid with real==effective, followed by a
// euid verification, is the equivalent permanent drop.
func applyPrivDrop(plan privDropPlan) error {
	if !plan.Drop {
		return nil
	}
	// Setgroups REPLACES the group set, so this is also what clears root's
	// supplementary groups (wheel, admin, ...). It must run before the uid drop
	// — only root may call it. A nil plan.Groups falls back to the primary gid
	// alone, which is the safe direction: fewer groups, never root's.
	g := plan.Groups
	if g == nil {
		g = []int{plan.GID}
	}
	if err := syscall.Setgroups(g); err != nil {
		return fmt.Errorf("setgroups %v: %w", g, err)
	}
	if err := syscall.Setregid(plan.GID, plan.GID); err != nil {
		return fmt.Errorf("setregid %d: %w", plan.GID, err)
	}
	if err := syscall.Setreuid(plan.UID, plan.UID); err != nil {
		return fmt.Errorf("setreuid %d: %w", plan.UID, err)
	}
	if syscall.Geteuid() != plan.UID {
		return fmt.Errorf("privilege drop verification failed: euid=%d want=%d", syscall.Geteuid(), plan.UID)
	}
	return nil
}
