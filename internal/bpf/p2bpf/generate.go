// Package p2bpf holds the generated BPF objects for Problem 2.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target bpfel P2 ../../../bpf/p2_proc_filter.c -- -I../../../bpf -I/usr/include
package p2bpf
