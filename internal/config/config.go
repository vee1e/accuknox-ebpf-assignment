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

// NormalizeComm checks a process name and truncates it the way the
// kernel truncates comm to 15 chars. It returns the effective name.
func NormalizeComm(name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("process name must not be empty")
	}
	for _, r := range name {
		if r == '/' || r == '\x00' {
			return "", fmt.Errorf("process name %q contains invalid character", name)
		}
	}
	if len(name) > MaxCommName {
		name = name[:MaxCommName]
	}
	return name, nil
}

// CommKey builds the 16-byte NUL-padded map key for a process name.
func CommKey(name string) [TaskCommLen]byte {
	var k [TaskCommLen]byte
	copy(k[:], name)
	return k
}
