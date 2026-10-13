// Command p2 restricts a process (by comm) to a single TCP port using
// cgroup connect/bind hooks. All other ports are denied for that process
// only; every other process is unaffected.
//
// Usage: sudo ./p2 --process myprocess --port 4040 --cgroup /sys/fs/cgroup
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"github.com/vee1e/accuknox-ebpf-assignment/internal/bpf/p2bpf"
	"github.com/vee1e/accuknox-ebpf-assignment/internal/config"
)

func main() {
	proc := flag.String("process", "myprocess", "process name (comm) to restrict to one TCP port (a process can rename itself, so this is scoping, not a security boundary)")
	port := flag.Int("port", 4040, "only TCP port the process may use (1-65535)")
	cgroup := flag.String("cgroup", "/sys/fs/cgroup", "cgroupv2 mount point to attach to")
	statsEvery := flag.Duration("stats", 10*time.Second, "stats log interval (0 disables)")
	flag.Parse()

	if err := run(*proc, *port, *cgroup, *statsEvery); err != nil {
		log.Fatalf("p2: %v", err)
	}
}

func run(proc string, port int, cgroupPath string, statsEvery time.Duration) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("must run as root (need CAP_BPF/CAP_NET_ADMIN)")
	}
	if err := config.ValidatePort(port); err != nil {
		return err
	}
	eff, err := config.NormalizeComm(proc)
	if err != nil {
		return err
	}
	if err := checkCgroupV2(cgroupPath); err != nil {
		return err
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock (needed on older kernels): %w", err)
	}

	objs := p2bpf.P2Objects{}
	if err := p2bpf.LoadP2Objects(&objs, nil); err != nil {
		return fmt.Errorf("load BPF objects: %w", err)
	}
	defer func() { _ = objs.Close() }()

	comm, err := config.CommKey16(eff)
	if err != nil {
		return err
	}
	var key uint32
	if err := objs.P2Target.Update(key, p2bpf.P2P2Target{Comm: comm}, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("set target process: %w", err)
	}
	if err := objs.P2Port.Update(key, uint32(port), ebpf.UpdateAny); err != nil {
		return fmt.Errorf("set allowed port: %w", err)
	}

	attach := []struct {
		name   string
		prog   *ebpf.Program
		attach ebpf.AttachType
	}{
		{"connect4", objs.P2Connect4, ebpf.AttachCGroupInet4Connect},
		{"connect6", objs.P2Connect6, ebpf.AttachCGroupInet6Connect},
		{"bind4", objs.P2Bind4, ebpf.AttachCGroupInet4Bind},
		{"bind6", objs.P2Bind6, ebpf.AttachCGroupInet6Bind},
	}
	var links []link.Link
	for _, a := range attach {
		l, err := link.AttachCgroup(link.CgroupOptions{
			Path:    cgroupPath,
			Attach:  a.attach,
			Program: a.prog,
		})
		if err != nil {
			for _, open := range links {
				_ = open.Close()
			}
			return fmt.Errorf("attach cgroup/%s on %s: %w (cgroupv2 + BTF required)", a.name, cgroupPath, err)
		}
		links = append(links, l)
	}
	defer func() {
		for _, l := range links {
			if err := l.Close(); err != nil {
				log.Printf("p2: detach: %v", err)
			}
		}
	}()

	log.Printf("p2: process %q restricted to TCP port %d (cgroup %s); Ctrl-C to detach",
		eff, port, cgroupPath)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var ticker *time.Ticker
	var tickCh <-chan time.Time
	if statsEvery > 0 {
		ticker = time.NewTicker(statsEvery)
		defer ticker.Stop()
		tickCh = ticker.C
	}
	for {
		select {
		case <-ctx.Done():
			allowed, denied, err := readStats(&objs)
			if err != nil {
				log.Printf("p2: detached; final stats unavailable: %v", err)
			} else {
				log.Printf("p2: detached; final stats allowed=%d denied=%d", allowed, denied)
			}
			return nil
		case <-tickCh:
			allowed, denied, err := readStats(&objs)
			if err != nil {
				log.Printf("p2: stats unavailable: %v", err)
			} else {
				log.Printf("p2: stats allowed=%d denied=%d (process %q on port %d)", allowed, denied, eff, port)
			}
		}
	}
}

// checkCgroupV2 rejects non-directories and non-v2 hierarchies early,
// so a cgroupv1 path fails with a clear message instead of a raw attach error.
func checkCgroupV2(cgroupPath string) error {
	st, err := os.Stat(cgroupPath)
	if err != nil {
		return fmt.Errorf("cgroup path %q: %w", cgroupPath, err)
	}
	if !st.IsDir() {
		return fmt.Errorf("cgroup path %q is not a directory", cgroupPath)
	}
	if _, err := os.Stat(filepath.Join(cgroupPath, "cgroup.controllers")); err != nil {
		return fmt.Errorf("cgroup path %q is not a cgroupv2 mount (no cgroup.controllers): %w", cgroupPath, err)
	}
	return nil
}

func readStats(objs *p2bpf.P2Objects) (allowed, denied uint64, err error) {
	if err = objs.P2Stats.Lookup(uint32(0), &allowed); err != nil {
		return 0, 0, fmt.Errorf("lookup allowed counter: %w", err)
	}
	if err = objs.P2Stats.Lookup(uint32(1), &denied); err != nil {
		return 0, 0, fmt.Errorf("lookup denied counter: %w", err)
	}
	return allowed, denied, nil
}
