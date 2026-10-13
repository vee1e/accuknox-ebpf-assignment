GO ?= go
CLANG ?= clang
BPF_CFLAGS := -O2 -g -Wall -Werror

P1_PKG := ./internal/bpf/p1bpf
P2_PKG := ./internal/bpf/p2bpf

.PHONY: all generate build test test-e2e vet lint fmt clean demo

all: build

# vmlinux.h is a committed minimal header (see bpf/vmlinux.h); CO-RE
# resolves its fields against the running kernel's BTF at load time.
generate:
	$(GO) generate $(P1_PKG) $(P2_PKG)
	test -z "$$(gofmt -l internal cmd test testdata)"

build:
	$(GO) build -o bin/p1 ./cmd/p1
	$(GO) build -o bin/p2 ./cmd/p2
	$(GO) build -o bin/dialer ./testdata/dialer

test:
	$(GO) test -count=1 ./...

# Needs Linux + root + BTF + TCX/cgroupv2. Safe no-op elsewhere (tests skip).
test-e2e:
	$(GO) test -tags e2e -count=1 -v -timeout 10m ./test/e2e/...

vet:
	$(GO) vet ./...

lint:
	golangci-lint run ./...
	clang-format --dry-run --Werror bpf/p1_drop_port.c bpf/p2_proc_filter.c

fmt:
	gofmt -w internal cmd test testdata
	clang-format -i bpf/p1_drop_port.c bpf/p2_proc_filter.c

demo:
	sudo bash ./demo.sh

clean:
	rm -rf bin
	$(GO) clean
