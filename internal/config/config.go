// Package config holds validation and normalization for loader flags.
package config

import (
	"fmt"
)

// TaskCommLen mirrors TASK_COMM_LEN in the kernel (16 incl. NUL).
const TaskCommLen = 16

// MaxCommName is the longest process name the kernel keeps (15 chars + NUL).
const MaxCommName = TaskCommLen - 1

// ValidatePort rejects anything outside 1-65535. Port 0 means
// "disabled" inside the BPF programs, so loaders must not accept it.
func ValidatePort(p int) error {
	if p < 1 || p > 65535 {
		return fmt.Errorf("invalid port %d: must be 1-65535", p)
	}
	return nil
}

// NormalizeComm validates a process name against kernel comm limits:
// non-empty, no NUL bytes, at most 15 chars. Overlong names are rejected
// rather than truncated: the kernel compares only the first 15 chars, so
// truncating "averylongname-extra" would also filter "averylongname-other".
func NormalizeComm(name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("process name must not be empty")
	}
	for _, r := range name {
		if r == '\x00' {
			return "", fmt.Errorf("process name contains NUL byte")
		}
	}
	if len(name) > MaxCommName {
		return "", fmt.Errorf("process name %q too long: kernel comm keeps %d chars", name, MaxCommName)
	}
	return name, nil
}

// CommKey16 builds the 16-byte NUL-padded comm value for BPF maps.
// The name is validated first, so the key always matches what the kernel
// stores for that exact name.
func CommKey16(name string) ([16]int8, error) {
	var k [16]int8
	norm, err := NormalizeComm(name)
	if err != nil {
		return k, err
	}
	for i := 0; i < len(norm); i++ {
		k[i] = int8(norm[i])
	}
	return k, nil
}
