//go:build darwin

package parent

import (
	"fmt"
	"syscall"
)

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
