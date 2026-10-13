# AccuKnox Golang Trainee Assignment (eBPF)

Two eBPF packet/process filters with Go userspace (`cilium/ebpf` + `bpf2go`,
CO-RE C with `vmlinux.h`), plus a written answer for Problem 3
(`ANSWERS.md`).

| Problem | Hook | Default behavior |
|---|---|---|
| P1: drop TCP packets on a port | TC ingress (via TCX) | drops TCP dport **4040** |
| P2: restrict a process to one port | cgroup `connect4/connect6` + `bind4/bind6` | `myprocess` may use only **4040** |

## Why these hooks

- **P1 uses TC ingress, not XDP.** XDP cannot attach to loopback and needs
  driver support, which makes local and netns testing painful. TC ingress
  attaches to `lo`, `veth` and physical NICs uniformly and still runs early
  in receive path, before socket delivery. TC observes a 14-byte Ethernet
  header even on loopback (verified empirically), so one fixed offset
  serves all interfaces.
- **P2 uses cgroup connect/bind hooks, not XDP/TC.** At XDP/TC ingress
  there is no reliable task context (softirq), so a packet cannot be tied
  to a process. `connect`/`bind` run in the caller's syscall context, so
  `bpf_get_current_comm` identifies the process exactly and the connection
  is denied before any packet is sent. Both `connect` (outbound) and
  `bind` (listeners) are filtered.

The blocked/allowed port and the target process name live in BPF maps,
set from CLI flags (`--port`, `--process`) at startup with no BPF
recompile. Map updates take effect on the next packet/syscall (covered by
e2e); the loaders themselves write the maps once at startup, so changing
the flag means restarting the loader.

## Layout

```
bpf/            kernel C (p1_drop_port.c, p2_proc_filter.c, minimal vmlinux.h)
cmd/p1, cmd/p2  Go loaders (flags, attach, maps, signal handling, stats)
internal/config flag validation (unit-tested)
internal/bpf/   bpf2go-generated bindings (committed, so builds need no clang)
test/e2e/       privileged end-to-end tests (build tag e2e)
testdata/dialer helper: sets its comm, dials/binds/serves
demo.sh         scripted terminal demo for the video recording
```

## Requirements

- Linux kernel >= 6.6 with BTF (`/sys/kernel/btf/vmlinux`), TCX (P1) and
  cgroupv2 mounted at `/sys/fs/cgroup` (P2). Tested on 6.10 (Docker
  Desktop) and Ubuntu 24.04 runners.
- Root (`CAP_NET_ADMIN`/`CAP_BPF`). BPF toolchain (`clang`, `libbpf-dev`)
  only needed to regenerate bindings (`make generate`). `bpf/vmlinux.h` is
  a committed minimal header; CO-RE resolves its fields against the running
  kernel's BTF at load time.

## Build and run

```bash
make build                # emits bin/p1, bin/p2, bin/dialer
sudo ./bin/p1 --port 4040 --iface lo           # Problem 1, Ctrl-C detaches
sudo ./bin/p2 --process myprocess --port 4040  # Problem 2, Ctrl-C detaches
```

Regenerate (Linux, installs toolchain first):

```bash
sudo apt-get install -y clang llvm libbpf-dev
make generate   # bpf2go rebuilds internal/bpf/... from bpf/*.c
```

## Tests

```bash
go test ./...                                            # unit (any OS)
sudo go test -tags e2e -count=1 -v ./test/e2e/...        # e2e (Linux, root)
make lint   # golangci-lint + clang-format check
```

E2E covers: P1 drops the blocked port while others pass, runtime map
update flips the block immediately, detach restores traffic, IPv4 + IPv6;
P2 target reaches only the allowed port (connect and bind) while another
process is unaffected, detach restores; invalid flags rejected (unit).

## Demo (for the video)

[![asciicast](https://asciinema.org/a/mguGdB6WKFEEdLXr.svg)](https://asciinema.org/a/mguGdB6WKFEEdLXr)

Recorded terminal demo: https://asciinema.org/a/mguGdB6WKFEEdLXr
(replay locally with `asciinema play demo.cast`).

```bash
sudo bash ./demo.sh
```

It builds both loaders, serves 4040/4050, shows P1 dropping 4040 then
(after restart with `--port 4050`) dropping 4050, then P2 blocking
`myprocess` off 4040 while `otherproc` is unaffected, with detach
restoring traffic each time.

## Limitations

- P1 attaches to one interface (`--iface`, default `lo`). Traffic on other
  interfaces is unaffected.
- P1 parses Ethernet (+ one optional VLAN tag) and filters only first
  IPv4 fragments; non-first fragments, double-tagged frames and
  non-Ethernet framing (tun, sit) are passed, not dropped.
- P1 parses IPv6 TCP without extension headers; packets with extension
  headers are passed, not dropped.
- P1 matches destination port on ingress; return traffic is unaffected.
- P2 filters TCP only; UDP and other protocols are unaffected by design.
  `bind(0)` (ephemeral allocation) stays allowed.
- P2 applies to new connections and binds only; already-established flows
  keep going after attach.
- P2 matches `comm`, which is per-thread, set at `exec`, capped at 15
  chars, and changeable by the process itself (names over 15 chars are
  rejected to avoid prefix collisions). A process can rename itself to
  dodge the filter; for hard isolation use cgroup membership or LSM labels
  instead.
- An empty/unset P2 config fails open (allows); the loader always writes
  the maps before attaching.
- No bpffs map pinning: configuration lives as long as the loader runs;
  stopping the loader detaches and restores traffic (by design).
