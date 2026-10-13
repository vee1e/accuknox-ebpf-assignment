// Command dialer is an e2e/demo helper: it sets its own comm name
// (via /proc/self/comm, no special syscalls needed) and then makes a
// single TCP connection attempt, reporting OK or FAIL.
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	comm := flag.String("comm", "myprocess", "name to set as own comm")
	host := flag.String("host", "127.0.0.1", "server address")
	port := flag.Int("port", 4040, "server port")
	bind := flag.Bool("bind", false, "bind the port instead of dialing it")
	serve := flag.Bool("serve", false, "listen forever (TCP server for demos/tests)")
	timeout := flag.Duration("timeout", 3*time.Second, "dial timeout")
	flag.Parse()

	if *comm != "" {
		f, err := os.OpenFile("/proc/self/comm", os.O_WRONLY, 0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "set comm: %v\n", err)
			os.Exit(2)
		}
		if _, err := f.WriteString(*comm); err != nil {
			fmt.Fprintf(os.Stderr, "set comm: %v\n", err)
			os.Exit(2)
		}
		_ = f.Close()
	}

	if *serve {
		l, err := net.Listen("tcp", fmt.Sprintf("%s:%d", *host, *port))
		if err != nil {
			fmt.Fprintf(os.Stderr, "serve: %v\n", err)
			os.Exit(1)
		}
		defer l.Close()
		fmt.Printf("serving %s:%d\n", *host, *port)
		for {
			c, err := l.Accept()
			if err != nil {
				os.Exit(0)
			}
			_ = c.Close()
		}
	}

	if *bind {
		l, err := net.Listen("tcp", fmt.Sprintf("%s:%d", *host, *port))
		if err != nil {
			fmt.Printf("FAIL bind %s:%d comm=%s err=%v\n", *host, *port, *comm, err)
			os.Exit(1)
		}
		_ = l.Close()
		fmt.Printf("OK bind %s:%d comm=%s\n", *host, *port, *comm)
		return
	}

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", *host, *port), *timeout)
	if err != nil {
		fmt.Printf("FAIL %s:%d comm=%s err=%v\n", *host, *port, *comm, err)
		os.Exit(1)
	}
	_ = conn.Close()
	fmt.Printf("OK %s:%d comm=%s\n", *host, *port, *comm)
}
