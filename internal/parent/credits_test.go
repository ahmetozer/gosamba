package parent

import "testing"

func TestGrantCredits(t *testing.T) {
	tests := []struct {
		charge uint16
		req    uint16
		want   uint16
	}{
		// Basic floor cases
		{0, 0, 1},   // zero charge, zero request → floor=1
		{1, 0, 1},   // consumed 1, request 0 → floor wins → 1
		{3, 5, 5},   // charge=3, request=5 → grant request
		{5, 3, 5},   // charge=5 wins over request=3
		{1, 600, creditWindow}, // request capped at creditWindow (512)
		// Charge exceeds window: grant the charge to keep balance non-negative
		{513, 600, 513},
		// Charge exactly at window
		{creditWindow, 0, creditWindow},
		// Charge below window, request below charge
		{10, 2, 10},
		// Charge=1 request at window
		{1, creditWindow, creditWindow},
	}

	for _, tc := range tests {
		got := grantCredits(tc.charge, tc.req)
		if got != tc.want {
			t.Errorf("grantCredits(%d, %d) = %d, want %d", tc.charge, tc.req, got, tc.want)
		}
		// Invariant: never zero
		if got < 1 {
			t.Errorf("grantCredits(%d, %d) = %d: violates never-zero invariant", tc.charge, tc.req, got)
		}
		// Invariant: never below charge (unless charge=0, in which case floor=1)
		minExpected := tc.charge
		if minExpected < 1 {
			minExpected = 1
		}
		if got < minExpected {
			t.Errorf("grantCredits(%d, %d) = %d: violates never-below-charge invariant (min=%d)", tc.charge, tc.req, got, minExpected)
		}
	}
}
