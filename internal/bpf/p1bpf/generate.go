// Package p1bpf holds the generated BPF objects for Problem 1.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target bpfel P1 ../../../bpf/p1_drop_port.c -- -I../../../bpf -I/usr/include
package p1bpf
