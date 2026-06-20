package config

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

type tomlSection int

const (
	secRoot tomlSection = iota
	secServer
	secLog
	secShare
	secUser
)

// decodeTOMLFile parses a minimal subset of TOML into *File.
//
// Supported:
//   - # comments (not inside quoted strings)
//   - [server], [log] tables
//   - [[share]], [[user]] arrays-of-tables
//   - key = "string" (double-quoted, \", \\, \n, \t, \r escapes)
//   - key = true | false
//   - key = ["a", "b", ...] string arrays
//
// Unknown keys are silently ignored (matches BurntSushi default).
func decodeTOMLFile(path string, f *File) error {
	fh, err := os.Open(path)
	if err != nil {
		return err
	}
	defer fh.Close()

	cur := secRoot
	lineNum := 0

	scanner := bufio.NewScanner(fh)
	for scanner.Scan() {
		lineNum++
		raw := scanner.Text()

		// Strip inline comment (only outside quoted strings)
		line := stripComment(raw)
		line = strings.TrimSpace(line)

		if line == "" {
			continue
		}

		// Array-of-tables header: [[share]] or [[user]]
		if strings.HasPrefix(line, "[[") {
			if !strings.HasSuffix(line, "]]") {
				return fmt.Errorf("line %d: malformed array-of-tables header: %s", lineNum, raw)
			}
			name := strings.TrimSpace(line[2 : len(line)-2])
			switch name {
			case "share":
				f.Shares = append(f.Shares, FileShare{})
				cur = secShare
			case "user":
				f.Users = append(f.Users, FileUser{})
				cur = secUser
			default:
				// unknown array-of-tables: ignore entries until next header
				cur = secRoot
			}
			continue
		}

		// Table header: [server] or [log]
		if strings.HasPrefix(line, "[") {
			if !strings.HasSuffix(line, "]") {
				return fmt.Errorf("line %d: malformed table header: %s", lineNum, raw)
			}
			name := strings.TrimSpace(line[1 : len(line)-1])
			switch name {
			case "server":
				cur = secServer
			case "log":
				cur = secLog
			default:
				cur = secRoot
			}
			continue
		}

		// Key = value
		eq := strings.Index(line, "=")
		if eq < 0 {
			return fmt.Errorf("line %d: expected key=value, got: %s", lineNum, raw)
		}
		key := strings.TrimSpace(line[:eq])
		valStr := strings.TrimSpace(line[eq+1:])
		if key == "" {
			return fmt.Errorf("line %d: empty key before '=': %s", lineNum, raw)
		}

		if err := applyKV(f, cur, key, valStr, lineNum); err != nil {
			return fmt.Errorf("line %d: %w", lineNum, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}

// stripComment removes everything from the first unquoted '#' character onward.
func stripComment(s string) string {
	inStr := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '"' {
			inStr = !inStr
		} else if c == '\\' && inStr {
			i++ // skip escaped char
		} else if c == '#' && !inStr {
			return s[:i]
		}
	}
	return s
}

func applyKV(f *File, cur tomlSection, key, valStr string, lineNum int) error {
	switch cur {
	case secServer:
		return applyServerKV(f, key, valStr, lineNum)
	case secLog:
		return applyLogKV(f, key, valStr, lineNum)
	case secShare:
		if len(f.Shares) == 0 {
			return fmt.Errorf("key %q outside share table", key)
		}
		return applyShareKV(&f.Shares[len(f.Shares)-1], key, valStr, lineNum)
	case secUser:
		if len(f.Users) == 0 {
			return fmt.Errorf("key %q outside user table", key)
		}
		return applyUserKV(&f.Users[len(f.Users)-1], key, valStr, lineNum)
	}
	// secRoot: ignore
	return nil
}

func applyServerKV(f *File, key, valStr string, lineNum int) error {
	switch key {
	case "listen":
		s, err := parseString(valStr, lineNum)
		if err != nil {
			return err
		}
		f.Server.Listen = &s
	case "netbios":
		b, err := parseBool(valStr, lineNum)
		if err != nil {
			return err
		}
		f.Server.Netbios = &b
	case "mdns":
		b, err := parseBool(valStr, lineNum)
		if err != nil {
			return err
		}
		f.Server.MDNS = &b
	case "encryption":
		s, err := parseString(valStr, lineNum)
		if err != nil {
			return err
		}
		em := EncryptionMode(s)
		f.Server.Encryption = &em
	case "signing":
		s, err := parseString(valStr, lineNum)
		if err != nil {
			return err
		}
		sm := SigningMode(s)
		f.Server.Signing = &sm
	case "durable_timeout":
		s, err := parseString(valStr, lineNum)
		if err != nil {
			return err
		}
		f.Server.DurableTimeout = &s
	case "state_dir":
		s, err := parseString(valStr, lineNum)
		if err != nil {
			return err
		}
		f.Server.StateDir = &s
	case "per_user_privdrop":
		b, err := parseBool(valStr, lineNum)
		if err != nil {
			return err
		}
		f.Server.PerUserPrivdrop = &b
	// unknown keys silently ignored
	}
	return nil
}

func applyLogKV(f *File, key, valStr string, lineNum int) error {
	switch key {
	case "level":
		s, err := parseString(valStr, lineNum)
		if err != nil {
			return err
		}
		f.Log.Level = &s
	case "format":
		s, err := parseString(valStr, lineNum)
		if err != nil {
			return err
		}
		f.Log.Format = &s
	// unknown keys silently ignored
	}
	return nil
}

func applyShareKV(sh *FileShare, key, valStr string, lineNum int) error {
	switch key {
	case "name":
		s, err := parseString(valStr, lineNum)
		if err != nil {
			return err
		}
		sh.Name = s
	case "path":
		s, err := parseString(valStr, lineNum)
		if err != nil {
			return err
		}
		sh.Path = s
	case "read_only":
		b, err := parseBool(valStr, lineNum)
		if err != nil {
			return err
		}
		sh.ReadOnly = b
	case "guest_ok":
		b, err := parseBool(valStr, lineNum)
		if err != nil {
			return err
		}
		sh.GuestOK = b
	// unknown keys silently ignored
	}
	return nil
}

func applyUserKV(u *FileUser, key, valStr string, lineNum int) error {
	switch key {
	case "name":
		s, err := parseString(valStr, lineNum)
		if err != nil {
			return err
		}
		u.Name = s
	case "nt_hash":
		s, err := parseString(valStr, lineNum)
		if err != nil {
			return err
		}
		u.NTHashHex = s
	case "system_user":
		s, err := parseString(valStr, lineNum)
		if err != nil {
			return err
		}
		u.SystemUser = s
	case "allow_shares":
		arr, err := parseStringArray(valStr, lineNum)
		if err != nil {
			return err
		}
		u.AllowShares = arr
	// unknown keys silently ignored
	}
	return nil
}

// parseString parses a double-quoted TOML string value.
func parseString(s string, lineNum int) (string, error) {
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		return "", fmt.Errorf("expected double-quoted string, got: %s", s)
	}
	inner := s[1 : len(s)-1]
	var b strings.Builder
	for i := 0; i < len(inner); i++ {
		c := inner[i]
		if c == '\\' {
			i++
			if i >= len(inner) {
				return "", fmt.Errorf("unterminated escape sequence in string")
			}
			switch inner[i] {
			case '"':
				b.WriteByte('"')
			case '\\':
				b.WriteByte('\\')
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'r':
				b.WriteByte('\r')
			default:
				return "", fmt.Errorf("unknown escape \\%c", inner[i])
			}
		} else {
			b.WriteByte(c)
		}
	}
	return b.String(), nil
}

// parseBool parses a TOML boolean: true or false.
func parseBool(s string, lineNum int) (bool, error) {
	switch s {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, fmt.Errorf("expected true or false, got: %s", s)
}

// parseStringArray parses a TOML inline string array: ["a", "b", ...].
func parseStringArray(s string, lineNum int) ([]string, error) {
	s = strings.TrimSpace(s)
	if len(s) < 2 || s[0] != '[' || s[len(s)-1] != ']' {
		return nil, fmt.Errorf("expected string array [...], got: %s", s)
	}
	inner := strings.TrimSpace(s[1 : len(s)-1])
	if inner == "" {
		return []string{}, nil
	}

	var result []string
	for inner != "" {
		inner = strings.TrimSpace(inner)
		if inner == "" {
			break
		}
		if inner[0] != '"' {
			return nil, fmt.Errorf("expected quoted string in array, got: %s", inner)
		}
		// Find closing quote (accounting for escapes)
		end := -1
		for i := 1; i < len(inner); i++ {
			if inner[i] == '\\' {
				i++
				continue
			}
			if inner[i] == '"' {
				end = i
				break
			}
		}
		if end < 0 {
			return nil, fmt.Errorf("unterminated string in array: %s", inner)
		}
		elem, err := parseString(inner[:end+1], lineNum)
		if err != nil {
			return nil, err
		}
		result = append(result, elem)
		inner = strings.TrimSpace(inner[end+1:])
		if inner == "" {
			break
		}
		if inner[0] != ',' {
			return nil, fmt.Errorf("expected ',' or ']' in array, got: %s", inner)
		}
		inner = inner[1:]
	}
	return result, nil
}
