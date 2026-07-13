//go:build linux

package parent

import (
	"fmt"
	"syscall"
)

// applyPrivDrop performs the syscalls described by plan. On Linux the stdlib
// Setres*/Setgroups are applied to ALL OS threads by the Go runtime, so a
// goroutine later scheduled on another thread is also unprivileged.
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
