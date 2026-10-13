// Command p1 drops TCP packets to a configurable port using TC ingress.
//
// Usage: sudo ./p1 --port 4040 --iface lo
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/vee1e/accuknox-ebpf-assignment/internal/bpf/p1bpf"
	"github.com/vee1e/accuknox-ebpf-assignment/internal/config"
)

func main() {
	port := flag.Int("port", 4040, "TCP destination port to drop (1-65535)")
	ifaceName := flag.String("iface", "lo", "network interface to attach to")
	statsEvery := flag.Duration("stats", 10*time.Second, "stats log interval (0 disables)")
	flag.Parse()

	if err := run(*port, *ifaceName, *statsEvery); err != nil {
		log.Fatalf("p1: %v", err)
	}
}

func run(port int, ifaceName string, statsEvery time.Duration) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("must run as root (need CAP_NET_ADMIN/CAP_BPF)")
	}
	if err := config.ValidatePort(port); err != nil {
		return err
	}
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("lookup interface %q: %w", ifaceName, err)
	}

	objs := p1bpf.P1Objects{}
	if err := p1bpf.LoadP1Objects(&objs, nil); err != nil {
		return fmt.Errorf("load BPF objects: %w", err)
	}
	defer func() { _ = objs.Close() }()

	var key uint32
	if err := objs.P1Port.Update(key, uint32(port), ebpf.UpdateAny); err != nil {
		return fmt.Errorf("set blocked port: %w", err)
	}

	tclink, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   objs.TcDropPort,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		return fmt.Errorf("attach TCX ingress on %s: %w (kernel >= 6.6 with TCX/BTF required)", ifaceName, err)
	}
	defer func() {
		if err := tclink.Close(); err != nil {
			log.Printf("p1: detach: %v", err)
		}
	}()

	log.Printf("p1: dropping TCP dport %d on %s; Ctrl-C to detach and restore traffic",
		port, ifaceName)

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
			passed, dropped := readStats(&objs)
			log.Printf("p1: detached from %s; final stats passed=%d dropped=%d", ifaceName, passed, dropped)
			return nil
		case <-tickCh:
			passed, dropped := readStats(&objs)
			log.Printf("p1: stats passed=%d dropped=%d (blocked port %d)", passed, dropped, port)
		}
	}
}

func readStats(objs *p1bpf.P1Objects) (passed, dropped uint64) {
	_ = objs.P1Stats.Lookup(uint32(0), &passed)
	_ = objs.P1Stats.Lookup(uint32(1), &dropped)
	return passed, dropped
}
