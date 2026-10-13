//go:build e2e

// E2E tests for Problems 1 and 2. Requirements: Linux, root
// (CAP_NET_ADMIN/CAP_BPF), kernel with BTF (/sys/kernel/btf/vmlinux),
// TCX support (P1) and cgroupv2 (P2). Run with:
//
//	sudo go test -tags e2e -count=1 -v ./test/e2e/...
package e2e

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/vee1e/accuknox-ebpf-assignment/internal/bpf/p1bpf"
	"github.com/vee1e/accuknox-ebpf-assignment/internal/bpf/p2bpf"
	"github.com/vee1e/accuknox-ebpf-assignment/internal/config"
)

var dialerBin string

func TestMain(m *testing.M) {
	if runtime.GOOS != "linux" {
		fmt.Fprintln(os.Stderr, "e2e: linux only, skipping")
		os.Exit(0)
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "e2e: must run as root, skipping")
		os.Exit(0)
	}
	tmp, err := os.MkdirTemp("", "dialer")
	if err != nil {
		fmt.Fprintln(os.Stderr, "e2e:", err)
		os.Exit(1)
	}
	dialerBin = filepath.Join(tmp, "dialer")
	// dialer source lives in testdata relative to repo root; resolve via runtime file.
	if out, err := exec.Command("go", "build", "-o", dialerBin, "../../testdata/dialer").CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "e2e: build dialer: %v\n%s\n", err, out)
		_ = os.RemoveAll(tmp)
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(tmp)
	os.Exit(code)
}

// freePorts returns n free localhost TCP ports (closed immediately after,
// so a small race exists; acceptable for tests).
func freePorts(t *testing.T, n int) []int {
	t.Helper()
	var ports []int
	for i := 0; i < n; i++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("free port: %v", err)
		}
		ports = append(ports, l.Addr().(*net.TCPAddr).Port)
		if err := l.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
	}
	return ports
}

// serve starts TCP servers on each port; callers dial them.
func serve(t *testing.T, network string, ports ...int) {
	t.Helper()
	for _, p := range ports {
		l, err := net.Listen(network, net.JoinHostPort(loopback(network), strconv.Itoa(p)))
		if err != nil {
			t.Fatalf("listen %s %d: %v", network, p, err)
		}
		t.Cleanup(func() { _ = l.Close() })
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				_ = c.Close()
			}
		}()
	}
	// Give the stack a moment to install listeners.
	time.Sleep(200 * time.Millisecond)
}

func loopback(network string) string {
	if network == "tcp6" {
		return "::1"
	}
	return "127.0.0.1"
}

func dialOK(t *testing.T, network string, port int) bool {
	t.Helper()
	addr := net.JoinHostPort(loopback(network), strconv.Itoa(port))
	c, err := net.DialTimeout(network, addr, 2*time.Second)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

func TestP1DropAndReconfig(t *testing.T) {
	ports := freePorts(t, 2)
	blocked, allowed := ports[0], ports[1]
	serve(t, "tcp", blocked, allowed)

	iface, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatalf("lo: %v", err)
	}
	objs := p1bpf.P1Objects{}
	if err := p1bpf.LoadP1Objects(&objs, nil); err != nil {
		t.Fatalf("load: %v", err)
	}
	defer func() { _ = objs.Close() }()

	var key uint32
	if err := objs.P1Port.Update(key, uint32(blocked), ebpf.UpdateAny); err != nil {
		t.Fatalf("set port: %v", err)
	}
	tclink, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   objs.TcDropPort,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		t.Fatalf("attach TCX: %v", err)
	}
	// Safety net: any Fatalf below still detaches. The explicit Close
	// later tests the detach-restores-traffic path; the deferred second
	// Close is a harmless no-op by then.
	defer func() { _ = tclink.Close() }()

	if dialOK(t, "tcp", blocked) {
		t.Fatalf("port %d should be dropped", blocked)
	}
	if !dialOK(t, "tcp", allowed) {
		t.Fatalf("port %d should pass", allowed)
	}
	assertP1Stats(t, &objs, 1, 1)

	// Runtime reconfig takes effect immediately: flip the blocked port.
	if err := objs.P1Port.Update(key, uint32(allowed), ebpf.UpdateAny); err != nil {
		t.Fatalf("reconfig: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
	if !dialOK(t, "tcp", blocked) {
		t.Fatalf("port %d should pass after reconfig", blocked)
	}
	if dialOK(t, "tcp", allowed) {
		t.Fatalf("port %d should be dropped after reconfig", allowed)
	}

	// Detach restores traffic on both ports.
	if err := tclink.Close(); err != nil {
		t.Fatalf("detach: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
	if !dialOK(t, "tcp", blocked) || !dialOK(t, "tcp", allowed) {
		t.Fatal("traffic not restored after detach")
	}
}

func TestP1IPv6(t *testing.T) {
	l, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6: %v", err)
	}
	blocked := l.Addr().(*net.TCPAddr).Port
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	// Second listener on another port must keep passing.
	l2, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("no second IPv6 listener: %v", err)
	}
	allowed := l2.Addr().(*net.TCPAddr).Port
	t.Cleanup(func() { _ = l2.Close() })
	go func() {
		for {
			c, err := l2.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	iface, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatalf("lo: %v", err)
	}
	objs := p1bpf.P1Objects{}
	if err := p1bpf.LoadP1Objects(&objs, nil); err != nil {
		t.Fatalf("load: %v", err)
	}
	defer func() { _ = objs.Close() }()
	var key uint32
	_ = objs.P1Port.Update(key, uint32(blocked), ebpf.UpdateAny)
	tclink, err := link.AttachTCX(link.TCXOptions{Interface: iface.Index, Program: objs.TcDropPort, Attach: ebpf.AttachTCXIngress})
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	defer func() { _ = tclink.Close() }()
	time.Sleep(200 * time.Millisecond)
	if dialOK(t, "tcp6", blocked) {
		t.Fatalf("IPv6 port %d should be dropped", blocked)
	}
	if !dialOK(t, "tcp6", allowed) {
		t.Fatalf("IPv6 port %d should pass", allowed)
	}
	assertP1Stats(t, &objs, 1, 1)
}

func assertP1Stats(t *testing.T, objs *p1bpf.P1Objects, wantPassed, wantDropped uint64) {
	t.Helper()
	var passed, dropped uint64
	if err := objs.P1Stats.Lookup(uint32(0), &passed); err != nil {
		t.Fatalf("stats passed: %v", err)
	}
	if err := objs.P1Stats.Lookup(uint32(1), &dropped); err != nil {
		t.Fatalf("stats dropped: %v", err)
	}
	if passed < wantPassed || dropped < wantDropped {
		t.Fatalf("stats passed=%d dropped=%d, want at least %d/%d", passed, dropped, wantPassed, wantDropped)
	}
}

func TestP2ProcessFilter(t *testing.T) {
	ports := freePorts(t, 2)
	allowedPort, otherPort := ports[0], ports[1]
	serve(t, "tcp", allowedPort, otherPort)

	const target = "myprocess"
	objs := p2bpf.P2Objects{}
	if err := p2bpf.LoadP2Objects(&objs, nil); err != nil {
		t.Fatalf("load: %v", err)
	}
	defer func() { _ = objs.Close() }()

	comm, err := config.CommKey16(target)
	if err != nil {
		t.Fatalf("comm: %v", err)
	}
	var key uint32
	if err := objs.P2Target.Update(key, p2bpf.P2P2Target{Comm: comm}, ebpf.UpdateAny); err != nil {
		t.Fatalf("set target: %v", err)
	}
	if err := objs.P2Port.Update(key, uint32(allowedPort), ebpf.UpdateAny); err != nil {
		t.Fatalf("set port: %v", err)
	}
	progs := []struct {
		prog   *ebpf.Program
		attach ebpf.AttachType
	}{
		{objs.P2Connect4, ebpf.AttachCGroupInet4Connect},
		{objs.P2Connect6, ebpf.AttachCGroupInet6Connect},
		{objs.P2Bind4, ebpf.AttachCGroupInet4Bind},
		{objs.P2Bind6, ebpf.AttachCGroupInet6Bind},
	}
	var links []link.Link
	cgroupPath := os.Getenv("AK_CGROUP")
	if cgroupPath == "" {
		cgroupPath = "/sys/fs/cgroup"
	}
	for _, p := range progs {
		l, err := link.AttachCgroup(link.CgroupOptions{
			Path:    cgroupPath,
			Attach:  p.attach,
			Program: p.prog,
		})
		if err != nil {
			for _, open := range links {
				_ = open.Close()
			}
			t.Fatalf("attach cgroup: %v", err)
		}
		links = append(links, l)
	}
	defer func() {
		for _, l := range links {
			_ = l.Close()
		}
	}()
	time.Sleep(200 * time.Millisecond)

	// Target process: allowed port OK, other port denied.
	if out := runDialer(t, target, allowedPort, false); !strings.HasPrefix(out, "OK") {
		t.Fatalf("target allowed port: %s", out)
	}
	if out := runDialer(t, target, otherPort, false); !strings.HasPrefix(out, "FAIL") {
		t.Fatalf("target other port must fail: %s", out)
	}
	// Other process: unaffected on both ports.
	if out := runDialer(t, "otherproc", allowedPort, false); !strings.HasPrefix(out, "OK") {
		t.Fatalf("other allowed port: %s", out)
	}
	if out := runDialer(t, "otherproc", otherPort, false); !strings.HasPrefix(out, "OK") {
		t.Fatalf("other other port: %s", out)
	}
	// TCP-only scope: UDP from the target process is unaffected.
	udpPort := serveUDP(t)
	if out := runDialerUDP(t, target, udpPort); !strings.HasPrefix(out, "OK") {
		t.Fatalf("target UDP must be unaffected: %s", out)
	}
	assertP2Denied(t, &objs, 1)
	// Bind side: point the filter at a fresh free port (the served ports
	// are already bound by listeners, so binding them would fail with
	// EADDRINUSE regardless of BPF). This also proves runtime reconfig.
	bindPorts := freePorts(t, 2)
	bindAllowed, bindOther := bindPorts[0], bindPorts[1]
	if err := objs.P2Port.Update(key, uint32(bindAllowed), ebpf.UpdateAny); err != nil {
		t.Fatalf("reconfig for bind test: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
	if out := runDialer(t, target, bindAllowed, true); !strings.HasPrefix(out, "OK") {
		t.Fatalf("target bind allowed: %s", out)
	}
	if out := runDialer(t, target, bindOther, true); !strings.HasPrefix(out, "FAIL") {
		t.Fatalf("target bind other must fail: %s", out)
	}
	if out := runDialer(t, "otherproc", bindOther, true); !strings.HasPrefix(out, "OK") {
		t.Fatalf("otherproc bind unaffected: %s", out)
	}
	// bind(0) asks the kernel for an ephemeral port and must stay allowed.
	if out := runDialer(t, target, 0, true); !strings.HasPrefix(out, "OK") {
		t.Fatalf("target bind(0) must be allowed: %s", out)
	}

	// Detach restores: target reaches the other port again.
	for _, l := range links {
		_ = l.Close()
	}
	links = nil
	time.Sleep(200 * time.Millisecond)
	if out := runDialer(t, target, otherPort, false); !strings.HasPrefix(out, "OK") {
		t.Fatalf("after detach target must pass: %s", out)
	}
}

func runDialer(t *testing.T, comm string, port int, bind bool) string {
	t.Helper()
	args := []string{"--comm", comm, "--port", strconv.Itoa(port)}
	if bind {
		args = append(args, "--bind")
	}
	out, _ := exec.Command(dialerBin, args...).CombinedOutput()
	return strings.TrimSpace(string(out))
}

func runDialerUDP(t *testing.T, comm string, port int) string {
	t.Helper()
	out, _ := exec.Command(dialerBin, "--comm", comm, "--port", strconv.Itoa(port), "--udp").CombinedOutput()
	return strings.TrimSpace(string(out))
}

// serveUDP starts a UDP listener and returns its port.
func serveUDP(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("udp listen: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			_, _, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr).Port
}

func assertP2Denied(t *testing.T, objs *p2bpf.P2Objects, want uint64) {
	t.Helper()
	var denied uint64
	if err := objs.P2Stats.Lookup(uint32(1), &denied); err != nil {
		t.Fatalf("stats denied: %v", err)
	}
	if denied < want {
		t.Fatalf("stats denied=%d, want at least %d", denied, want)
	}
}
