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
	got, trunc, err := NormalizeComm("myprocess")
	if err != nil || got != "myprocess" || trunc {
		t.Fatalf("NormalizeComm(myprocess) = %q, %v, %v", got, trunc, err)
	}
	if _, _, err := NormalizeComm(""); err == nil {
		t.Fatal("empty name must fail")
	}
	if _, _, err := NormalizeComm("a/b"); err == nil {
		t.Fatal("slash must fail")
	}
	long := strings.Repeat("x", 30)
	got, trunc, err = NormalizeComm(long)
	if err != nil {
		t.Fatalf("long name must truncate, got %v", err)
	}
	if !trunc {
		t.Fatal("overlong name must report truncation")
	}
	if len(got) != MaxCommName {
		t.Fatalf("truncated len = %d, want %d", len(got), MaxCommName)
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
	// Overlong input truncates exactly like the kernel, so the key
	// always matches what the kernel stores.
	klong, err := CommKey16(strings.Repeat("y", 30))
	if err != nil {
		t.Fatalf("CommKey16 long: %v", err)
	}
	for i := 0; i < MaxCommName; i++ {
		if klong[i] != int8('y') {
			t.Fatalf("key[%d] = %d, want 'y'", i, klong[i])
		}
	}
	if klong[15] != 0 {
		t.Fatal("key must stay NUL-terminated after truncation")
	}
	if _, err := CommKey16(""); err == nil {
		t.Fatal("empty name must fail")
	}
}
