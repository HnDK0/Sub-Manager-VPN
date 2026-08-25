package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"vpn-sub-manager/internal/core"
)

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
	if _, err = conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return nil, err
	}
	rep := make([]byte, 2)
	if _, err = io.ReadFull(conn, rep); err != nil {
		return nil, err
	}
	if rep[0] != 0x05 || rep[1] != 0x00 {
		return nil, fmt.Errorf("auth rejected (method %d)", rep[1])
	}
	host := targetHost
	req := make([]byte, 0, 7+len(host))
	req = append(req, 0x05, 0x01, 0x00, 0x03, byte(len(host)))
	req = append(req, host...)
	req = append(req, byte(targetPort>>8), byte(targetPort&0xff))
	if _, err = conn.Write(req); err != nil {
		return nil, err
	}
	resp := make([]byte, 4)
	if _, err = io.ReadFull(conn, resp); err != nil {
		return nil, err
	}
	if resp[1] != 0x00 {
		return nil, fmt.Errorf("connect failed (rep %d)", resp[1])
	}
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
		return nil, fmt.Errorf("bad address type %d", resp[3])
	}
	if _, err = io.ReadFull(conn, make([]byte, n+2)); err != nil {
		return nil, err
	}
	if err = conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	return conn, nil
}

func main() {
	dir, _ := os.MkdirTemp("", "dbgxray-*")
	mgr, _ := core.New(dir)
	if err := mgr.Ensure("xray"); err != nil {
		panic(err)
	}
	bin, _ := mgr.BinaryPath("xray")

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	mockPort := ln.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	proxyPort := 13999
	cfg := fmt.Sprintf(`{
  "log": {"loglevel": "debug"},
  "inbounds": [{
    "listen": "127.0.0.1",
    "port": %d,
    "protocol": "socks",
    "settings": {"auth": "noauth", "udp": false}
  }],
  "outbounds": [{"protocol": "freedom", "settings": {}}]
}`, proxyPort)
	cfgPath := filepath.Join(dir, "xray.json")
	os.WriteFile(cfgPath, []byte(cfg), 0o600)

	cmd := exec.Command(bin, "-c", cfgPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		panic(err)
	}
	defer cmd.Process.Kill()
	time.Sleep(2 * time.Second)

	conn, err := dialSOCKS5(fmt.Sprintf("127.0.0.1:%d", proxyPort), "127.0.0.1", mockPort, 5*time.Second)
	if err != nil {
		fmt.Println("SOCKS5 DIAL ERR:", err)
		return
	}
	fmt.Println("SOCKS5 DIAL OK")
	conn.Close()
}
