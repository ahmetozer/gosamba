//go:build linux

package parent

import (
	"fmt"
	"syscall"
)

// maxSupplementaryGroups is NGROUPS_MAX on Linux (65536 since 2.6.4). It is
// large enough that truncation never happens in practice; the constant exists
// so the caller can apply the same bound on both platforms without a build tag.
const maxSupplementaryGroups = 65536

// applyPrivDrop performs the syscalls described by plan. On Linux the stdlib
// Setres*/Setgroups are applied to ALL OS threads by the Go runtime, so a
// goroutine later scheduled on another thread is also unprivileged.
func applyPrivDrop(plan privDropPlan) error {
	if !plan.Drop {
		return nil
	}
	// Setgroups REPLACES the group set, so this is also what clears root's
	// supplementary groups (wheel, adm, ...). It must run before the uid drop —
	// only root may call it. A nil plan.Groups falls back to the primary gid
	// alone, which is the safe direction: fewer groups, never root's.
	g := plan.Groups
	if g == nil {
		g = []int{plan.GID}
	}
	if err := syscall.Setgroups(g); err != nil {
		return fmt.Errorf("setgroups %v: %w", g, err)
	}
	if err := syscall.Setresgid(plan.GID, plan.GID, plan.GID); err != nil {
		return fmt.Errorf("setresgid %d: %w", plan.GID, err)
	}
	if err := syscall.Setresuid(plan.UID, plan.UID, plan.UID); err != nil {
		return fmt.Errorf("setresuid %d: %w", plan.UID, err)
	}
	if syscall.Geteuid() != plan.UID {
		return fmt.Errorf("privilege drop verification failed: euid=%d want=%d", syscall.Geteuid(), plan.UID)
	}
	return nil
}
