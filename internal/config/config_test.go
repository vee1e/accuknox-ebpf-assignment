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
	// Overlong names fail instead of truncating: truncating would also
	// filter every other process sharing the 15-char prefix.
	if _, err := NormalizeComm(strings.Repeat("x", 30)); err == nil {
		t.Fatal("overlong name must fail, not truncate")
	}
	if _, err := NormalizeComm(strings.Repeat("x", MaxCommName)); err != nil {
		t.Fatalf("15-char name must pass: %v", err)
	}
}

func TestCommKey16(t *testing.T) {
	k, err := CommKey16("myprocess")
	if err != nil {
		t.Fatalf("CommKey16: %v", err)
	}
	if string([]byte{byte(k[0]), byte(k[1]), byte(k[2])}) != "myp" {
		t.Fatalf("key prefix wrong: %v", k[:9])
	}
	for _, b := range k[9:] {
		if b != 0 {
			t.Fatal("key must be NUL-padded")
		}
	}
	// Overlong input is rejected, so the key always matches exactly the
	// name the kernel stores (no 15-char prefix collisions).
	if _, err := CommKey16(strings.Repeat("y", 30)); err == nil {
		t.Fatal("overlong input must fail")
	}
	if _, err := CommKey16(""); err == nil {
		t.Fatal("empty name must fail")
	}
}
