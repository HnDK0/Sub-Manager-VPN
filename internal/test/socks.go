package test

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"time"

	"vpn-sub-manager/internal/model"
)

// probeThrough measures a node's liveness and real latency/speed THROUGH the
// node. The SOCKS5 proxy at proxyAddr now has the node as its outbound (set by
// worker.configureForNode on the real xray path), so HTTP traffic egresses via
// the node — this is what makes the latency/speed real (node→internet) rather
// than host→internet.
//
// Reachability and RTT differ between the real and fake/test paths:
//   - Real path: reachability is a DIRECT host TCP connect (the proxy outbound
//     is the node, so a SOCKS5 CONNECT to the node would be node→node, wrong).
//     RTT is the median of several HTTP GETs tunneled through the node.
//   - Fake/test path (realBackend == false): reachability is a SOCKS5 CONNECT
//     through the proxy (unchanged), so injected-fake tests stay green.
func (e *Engine) probeThrough(proxyAddr string, n model.Node, ctx context.Context) (Result, error) {
	r := Result{ProbeCount: e.opts.Probes}

	// 1) Reachability + baseline TCP latency.
	var tcpLatency int64
	var reachable bool
	if e.realBackend {
		if isTCPProtocol(n.Protocol) {
			// Direct host TCP connect (proxy outbound is the node, so a SOCKS5
			// CONNECT to the node would be node→node, wrong).
			start := time.Now()
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", n.Host, n.Port), e.opts.Timeout)
			if err == nil {
				conn.Close()
				reachable = true
				tcpLatency = time.Since(start).Milliseconds()
			}
			// For TCP transports the direct connect is the reachability gate:
			// if it fails the node is dead.
			if !reachable {
				return r, nil
			}
		} else {
			// UDP transports (hysteria2/tuic): a TCP connect is meaningless, so
			// reachability is established by the tunnel RTT below.
			reachable = true
		}
	} else {
		// Unchanged test path: reachability through the SOCKS5 proxy.
		var tcpSum int64
		var tcpN int
		for i := 0; i < e.opts.Probes; i++ {
			select {
			case <-ctx.Done():
				return Result{}, ctx.Err()
			default:
			}
			start := time.Now()
			conn, err := dialSOCKS5(proxyAddr, n.Host, n.Port, e.opts.Timeout)
			elapsed := time.Since(start)
			if err != nil {
				continue
			}
			conn.Close()
			tcpN++
			tcpSum += elapsed.Milliseconds()
		}
		if tcpN == 0 {
			return r, nil // unreachable -> dead
		}
		reachable = true
		tcpLatency = tcpSum / int64(tcpN)
	}
	r.Alive = true

	// 2) Real RTT: HTTP GET through the proxy (node outbound on the real path),
	//    e.opts.Probes times; take the MEDIAN of successful measurements.
	var lats []int64
	if client := proxyClient(proxyAddr, e.opts.Timeout); client != nil {
		for i := 0; i < e.opts.Probes; i++ {
			select {
			case <-ctx.Done():
				return Result{}, ctx.Err()
			default:
			}
			if lat := httpRTT(ctx, client, e.opts.ProbeURL); lat >= 0 {
				lats = append(lats, lat)
			}
		}
	}
	// Require a majority of probes to actually tunnel through the node: a single
	// lucky success out of 3 (flaky/dead backend, cached edge answer) must not
	// mark a node alive. ponytail: one extra guard, no new knob.
	required := (e.opts.Probes + 1) / 2
	if len(lats) >= required {
		r.LatencyMs = medianInt64(lats)
	} else if e.realBackend {
		// On the real path, liveness requires a majority of HTTP probes
		// tunneled THROUGH the node. The direct host TCP connect above only
		// proves the port is open, not that VLESS/VMESS/Trojan actually
		// tunnels — a dead server with an open port (CDN/firewall/anycast)
		// would otherwise read as "alive 1ms". Mark it dead instead of
		// falling back to the TCP latency.
		r.Alive = false
		return r, nil
	} else {
		// Test/fake path (no real egress): keep the proxy TCP latency so
		// injected-fake tests stay green.
		r.LatencyMs = tcpLatency
	}

	// 3) Throughput: download SpeedTestURL through the proxy (node outbound on
	//    the real path).
	if e.opts.SpeedTestURL != "" && speedWanted(ctx) {
		if client := proxyClient(proxyAddr, speedTimeout(e.opts.Timeout)); client != nil {
			r.SpeedKbps = httpSpeed(ctx, client, e.opts.SpeedTestURL, e.opts.SpeedTestTopN, e.opts.MinSpeedMbps)
		}
	}
	return r, nil
}

// isTCPProtocol reports whether the node's transport is TCP-based (vmess/vless/
// trojan), so a direct host TCP connect is a meaningful reachability check.
// hysteria2 and tuic are UDP and must be probed via the tunnel instead.
func isTCPProtocol(p model.Scheme) bool {
	switch p {
	case model.SchemeVMess, model.SchemeVLESS, model.SchemeTrojan:
		return true
	}
	return false
}

// medianInt64 returns the median of xs (assumed non-empty). For an even count it
// averages the two middle values.
func medianInt64(xs []int64) int64 {
	s := make([]int64, len(xs))
	copy(s, xs)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	m := len(s) / 2
	if len(s)%2 == 1 {
		return s[m]
	}
	return (s[m-1] + s[m]) / 2
}

// speedTimeout gives the download probe a longer budget than a single connect
// so throughput is measured over a meaningful window.
func speedTimeout(base time.Duration) time.Duration {
	t := base * 3
	if t < 15*time.Second {
		t = 15 * time.Second
	}
	return t
}

// proxyClient returns an *http.Client that routes requests through the SOCKS5
// proxy at proxyAddr. Returns nil if proxyAddr is empty.
func proxyClient(proxyAddr string, timeout time.Duration) *http.Client {
	if proxyAddr == "" {
		return nil
	}
	u := &url.URL{Scheme: "socks5", Host: proxyAddr}
	return &http.Client{
		Timeout:   timeout,
		Transport: &http.Transport{Proxy: http.ProxyURL(u)},
	}
}

// httpRTT performs a single HTTP GET and returns the round-trip time in ms, or
// -1 on failure. It measures time-to-headers (like Throne) and closes the
// response body immediately without downloading it, so the measurement reflects
// the node's latency rather than its throughput.
func httpRTT(ctx context.Context, client *http.Client, target string) int64 {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return -1
	}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return -1
	}
	// Time-to-headers: the response is usable once headers arrive. Close the
	// body immediately without reading it.
	resp.Body.Close()
	return time.Since(start).Milliseconds()
}

// httpSpeed downloads target through client and returns throughput in kbps.
// It uses an adaptive early-exit: stop once enough bytes are read or, when
// minMbps>0 and the running rate already clears the floor, stop early.
// Returns 0 on failure.
func httpSpeed(ctx context.Context, client *http.Client, target string, topNMB int, minMbps int) int64 {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return 0
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return 0
	}
	limit := int64(topNMB) * 1024 * 1024
	if limit <= 0 {
		limit = 5 * 1024 * 1024
	}
	floorKbps := int64(minMbps) * 1000
	start := time.Now()
	var read int64
	buf := make([]byte, 32*1024)
	for read < limit {
		if ctx.Err() != nil {
			break
		}
		n, err := resp.Body.Read(buf)
		if n > 0 {
			read += int64(n)
			elapsed := time.Since(start).Seconds()
			if elapsed > 0 && floorKbps > 0 {
				kb := (float64(read) * 8 / 1000) / elapsed
				if kb > float64(floorKbps)*1.2 && read >= 256*1024 {
					break // already comfortably above the floor
				}
			}
		}
		if err != nil {
			break
		}
	}
	elapsed := time.Since(start).Seconds()
	if elapsed <= 0 || read <= 0 {
		return 0
	}
	kbps := int64((float64(read) * 8 / 1000) / elapsed)
	if kbps < 0 {
		kbps = 0
	}
	return kbps
}

// dialSOCKS5 performs a SOCKS5 (no-auth) CONNECT to targetHost:targetPort via
// the SOCKS5 proxy at proxyAddr and returns the established connection. It is a
// minimal stdlib implementation so no external dependency is required.
func dialSOCKS5(proxyAddr, targetHost string, targetPort int, timeout time.Duration) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", proxyAddr, timeout)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			conn.Close()
		}
	}()
	if err = conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	// Greeting: version 5, 1 method, no authentication.
	if _, err = conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return nil, err
	}
	rep := make([]byte, 2)
	if _, err = io.ReadFull(conn, rep); err != nil {
		return nil, err
	}
	if rep[0] != 0x05 || rep[1] != 0x00 {
		return nil, fmt.Errorf("test: socks5 auth rejected (method %d)", rep[1])
	}
	// CONNECT request: ver, cmd=connect, rsv, then atyp+addr+port. IP literals
	// MUST be sent as atyp 0x01/0x04, never 0x03 (domain): a domain-type address
	// forces the proxy to DNS-resolve the string, which fails for an IP literal
	// and marks every IP-host node dead. (ponytail: one switch, no SOCKS5 lib.)
	req := make([]byte, 0, 7+len(targetHost)+15)
	req = append(req, 0x05, 0x01, 0x00)
	if ip := net.ParseIP(targetHost); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			req = append(req, 0x01)
			req = append(req, ip4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		req = append(req, 0x03, byte(len(targetHost)))
		req = append(req, targetHost...)
	}
	req = append(req, byte(targetPort>>8), byte(targetPort&0xff))
	if _, err = conn.Write(req); err != nil {
		return nil, err
	}
	resp := make([]byte, 4)
	if _, err = io.ReadFull(conn, resp); err != nil {
		return nil, err
	}
	if resp[1] != 0x00 {
		return nil, fmt.Errorf("test: socks5 connect failed (rep %d)", resp[1])
	}
	// Consume the bound address/port the server echoes back.
	var n int
	switch resp[3] {
	case 0x01:
		n = 4
	case 0x04:
		n = 16
	case 0x03:
		l := make([]byte, 1)
		if _, err = io.ReadFull(conn, l); err != nil {
			return nil, err
		}
		n = int(l[0])
	default:
		return nil, fmt.Errorf("test: socks5 bad address type %d", resp[3])
	}
	if _, err = io.ReadFull(conn, make([]byte, n+2)); err != nil {
		return nil, err
	}
	if err = conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	return conn, nil
}
