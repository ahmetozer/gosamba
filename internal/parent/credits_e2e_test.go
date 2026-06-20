//go:build smbclient_e2e

// Package parent — credit window E2E tests.
//
// The go-smb2 multi-credit test (TestE2E_Credits_LargeIO) has been removed in
// favour of the smbclient 64 MiB large-file round-trip in
// credits_smbclient_e2e_test.go, which proves the same credit-window behaviour
// without requiring the github.com/cloudsoda/go-smb2 package.
package parent
