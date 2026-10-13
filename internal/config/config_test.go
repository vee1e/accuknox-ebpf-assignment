package config

import (
	"strings"
	"testing"
)

func TestValidatePort(t *testing.T) {
	for _, p := range []int{1, 80, 4040, 65535} {
		if err := ValidatePort(p); err != nil {
			t.Errorf("ValidatePort(%d) = %v, want nil", p, err)
		}
	}
	for _, p := range []int{-1, 0, 65536, 100000} {
		if err := ValidatePort(p); err == nil {
			t.Errorf("ValidatePort(%d) = nil, want error", p)
		}
	}
}

func TestNormalizeComm(t *testing.T) {
	got, err := NormalizeComm("myprocess")
	if err != nil || got != "myprocess" {
		t.Fatalf("NormalizeComm(myprocess) = %q, %v", got, err)
	}
	if _, err := NormalizeComm(""); err == nil {
		t.Fatal("empty name must fail")
	}
	if _, err := NormalizeComm("a/b"); err == nil {
		t.Fatal("slash must fail")
	}
	long := strings.Repeat("x", 30)
	got, err = NormalizeComm(long)
	if err != nil {
		t.Fatalf("long name must truncate, got %v", err)
	}
	if len(got) != MaxCommName {
		t.Fatalf("truncated len = %d, want %d", len(got), MaxCommName)
	}
}

func TestCommKeyPadding(t *testing.T) {
	k := CommKey("myprocess")
	if string(k[:9]) != "myprocess" {
		t.Fatalf("key prefix = %q", k[:9])
	}
	for _, b := range k[9:] {
		if b != 0 {
			t.Fatal("key must be NUL-padded")
		}
	}
	if len(k) != TaskCommLen {
		t.Fatalf("len = %d", len(k))
	}
}
