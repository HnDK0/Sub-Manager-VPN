package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"vpn-sub-manager/internal/mihomo"
	"vpn-sub-manager/internal/model"
)

// dbgmihomo is a tiny debug helper that probes a single node through the
// embedded mihomo engine (no external binary, no xray). Usage:
//
//	dbgmihomo <protocol> <host> <port> [user] [security]
//
// e.g. dbgmihomo vless example.com 443 my-uuid tls
func main() {
	if len(os.Args) < 4 {
		fmt.Fprintln(os.Stderr, "usage: dbgmihomo <protocol> <host> <port> [user] [security]")
		os.Exit(2)
	}
	proto := model.Scheme(os.Args[1])
	host := os.Args[2]
	port, err := strconv.Atoi(os.Args[3])
	if err != nil {
		fmt.Fprintf(os.Stderr, "bad port: %v\n", err)
		os.Exit(2)
	}
	user := ""
	if len(os.Args) > 4 {
		user = os.Args[4]
	}
	security := ""
	if len(os.Args) > 5 {
		security = os.Args[5]
	}

	node := model.Node{
		Protocol: proto,
		Host:     host,
		Port:     port,
		User:     user,
		Security: security,
		Name:     "dbg",
	}

	eng := mihomo.New(mihomo.Options{Workers: 1})
	eng.Start()
	defer eng.Close()

	if err := eng.SyncNodes([]model.Node{node}); err != nil {
		fmt.Printf("SYNC ERR: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	r, err := eng.Probe(ctx, node)
	if err != nil {
		fmt.Printf("PROBE ERR: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("alive=%v latencyMs=%d speedKbps=%d probes=%d\n", r.Alive, r.LatencyMs, r.SpeedKbps, r.ProbeCount)
}
