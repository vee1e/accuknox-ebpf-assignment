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
// kernel truncates comm to 15 chars. It reports whether truncation
// happened so callers can warn: filtering "averylongname" when the user
// typed "averylongname-extra" would be a silent surprise otherwise.
func NormalizeComm(name string) (eff string, truncated bool, err error) {
	if name == "" {
		return "", false, fmt.Errorf("process name must not be empty")
	}
	for _, r := range name {
		if r == '/' || r == '\x00' {
			return "", false, fmt.Errorf("process name %q contains invalid character", name)
		}
	}
	if len(name) > MaxCommName {
		return name[:MaxCommName], true, nil
	}
	return name, false, nil
}

// CommKey16 builds the 16-byte NUL-padded comm value for BPF maps.
// The name is normalized first, so overlong input can never produce an
// unterminated key that matches nothing.
func CommKey16(name string) ([16]int8, error) {
	var k [16]int8
	norm, _, err := NormalizeComm(name)
	if err != nil {
		return k, err
	}
	for i := 0; i < len(norm); i++ {
		k[i] = int8(norm[i])
	}
	return k, nil
}
