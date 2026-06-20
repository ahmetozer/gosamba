// Package smb2 implements the SMB2/3 wire protocol. It is a pure-byte layer:
// no I/O, no goroutines, no logging.
package smb2

// Status is an NTSTATUS code as carried in the SMB2 header Status field.
type Status uint32

const (
	StatusSuccess             Status = 0x00000000
	StatusPending             Status = 0x00000103
	StatusInvalidParameter    Status = 0xC000000D
	StatusAccessDenied        Status = 0xC0000022
	StatusObjectNameNotFound  Status = 0xC0000034
	StatusObjectNameCollision Status = 0xC0000035
	StatusFileIsADirectory    Status = 0xC00000BA
	StatusNotADirectory       Status = 0xC0000103
	StatusNotSupported        Status = 0xC00000BB
	StatusInternalError       Status = 0xC00000E5
	StatusUserSessionDeleted  Status = 0xC0000203
	StatusLogonFailure        Status = 0xC000006D
	StatusMoreProcessingReq   Status = 0xC0000016
	StatusNoSuchFile          Status = 0xC000000F
	StatusNoMoreFiles         Status = 0x80000006
	StatusPipeNotAvailable    Status = 0xC00000AC
	StatusBadNetworkName      Status = 0xC00000CC
	StatusEndOfFile           Status = 0xC0000011
	StatusPipeBroken          Status = 0xC000014B
	StatusCancelled           Status = 0xC0000120
	StatusNotifyEnumDir       Status = 0x0000010C
	StatusNotifyCleanup       Status = 0x0000010B
	StatusFsDriverRequired    Status = 0xC000019C
	StatusNetworkNameDeleted  Status = 0xC00000C9
	StatusBufferOverflow      Status = 0x80000005
	StatusLockNotGranted      Status = 0xC0000055
	StatusDiskFull            Status = 0xC000007F
)
