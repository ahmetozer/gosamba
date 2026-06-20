package smb2

// Command identifies an SMB2 command (header.Command field).
type Command uint16

const (
	CommandNegotiate      Command = 0x0000
	CommandSessionSetup   Command = 0x0001
	CommandLogoff         Command = 0x0002
	CommandTreeConnect    Command = 0x0003
	CommandTreeDisconnect Command = 0x0004
	CommandCreate         Command = 0x0005
	CommandClose          Command = 0x0006
	CommandFlush          Command = 0x0007
	CommandRead           Command = 0x0008
	CommandWrite          Command = 0x0009
	CommandLock           Command = 0x000A
	CommandIoctl          Command = 0x000B
	CommandCancel         Command = 0x000C
	CommandEcho           Command = 0x000D
	CommandQueryDirectory Command = 0x000E
	CommandChangeNotify   Command = 0x000F
	CommandQueryInfo      Command = 0x0010
	CommandSetInfo        Command = 0x0011
	CommandOplockBreak    Command = 0x0012
)

func (c Command) String() string {
	switch c {
	case CommandNegotiate:
		return "NEGOTIATE"
	case CommandSessionSetup:
		return "SESSION_SETUP"
	case CommandLogoff:
		return "LOGOFF"
	case CommandTreeConnect:
		return "TREE_CONNECT"
	case CommandTreeDisconnect:
		return "TREE_DISCONNECT"
	case CommandCreate:
		return "CREATE"
	case CommandClose:
		return "CLOSE"
	case CommandFlush:
		return "FLUSH"
	case CommandRead:
		return "READ"
	case CommandWrite:
		return "WRITE"
	case CommandLock:
		return "LOCK"
	case CommandIoctl:
		return "IOCTL"
	case CommandCancel:
		return "CANCEL"
	case CommandEcho:
		return "ECHO"
	case CommandQueryDirectory:
		return "QUERY_DIRECTORY"
	case CommandChangeNotify:
		return "CHANGE_NOTIFY"
	case CommandQueryInfo:
		return "QUERY_INFO"
	case CommandSetInfo:
		return "SET_INFO"
	case CommandOplockBreak:
		return "OPLOCK_BREAK"
	default:
		return "UNKNOWN"
	}
}
