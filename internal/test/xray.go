package test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// spawnXray launches a real xray-core subprocess as a SOCKS5 proxy on port.
func (e *Engine) spawnXray(ctx context.Context, port int) (*exec.Cmd, error) {
	if err := e.mgr.Ensure("xray"); err != nil {
		return nil, fmt.Errorf("test: ensure xray: %w", err)
	}
	bin, err := e.mgr.BinaryPath("xray")
	if err != nil {
		return nil, err
	}
	if e.tempDir == "" {
		d, err := os.MkdirTemp("", "submgr-test-*")
		if err != nil {
			return nil, err
		}
		e.tempDir = d
	}
	cfgPath := filepath.Join(e.tempDir, fmt.Sprintf("xray-%d.json", port))
	if err := os.WriteFile(cfgPath, xrayConfigJSON(port), 0o600); err != nil {
		return nil, err
	}
	cmd := exec.Command(bin, "-c", cfgPath)
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd, nil
}

// xrayConfigJSON returns an xray config that listens for SOCKS5 (no-auth) on
// 127.0.0.1:port and forwards via the freedom outbound (direct egress). It is
// the placeholder backend spawned by ensureProxy; configureForNode replaces it
// with a per-node outbound before each probe.
func xrayConfigJSON(port int) []byte {
	return []byte(fmt.Sprintf(`{
  "log": {"loglevel": "warning"},
  "inbounds": [{
    "listen": "127.0.0.1",
    "port": %d,
    "protocol": "socks",
    "settings": {"auth": "noauth", "udp": false}
  }],
  "outbounds": [{"protocol": "freedom", "settings": {}}]
}`, port))
}

// spawnXrayForNode launches a real xray-core subprocess as a SOCKS5 proxy on
// port whose single outbound is the supplied node outbound (built by
// nodeXrayOutbound), so probe traffic is tunneled THROUGH the candidate node.
func (e *Engine) spawnXrayForNode(ctx context.Context, port int, outbound map[string]any) (*exec.Cmd, error) {
	if err := e.mgr.Ensure("xray"); err != nil {
		return nil, fmt.Errorf("test: ensure xray: %w", err)
	}
	bin, err := e.mgr.BinaryPath("xray")
	if err != nil {
		return nil, err
	}
	if e.tempDir == "" {
		d, err := os.MkdirTemp("", "submgr-test-*")
		if err != nil {
			return nil, err
		}
		e.tempDir = d
	}
	cfgPath := filepath.Join(e.tempDir, fmt.Sprintf("xray-%d.json", port))
	if err := os.WriteFile(cfgPath, xrayConfigForNode(port, outbound), 0o600); err != nil {
		return nil, err
	}
	cmd := exec.Command(bin, "-c", cfgPath)
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd, nil
}

// xrayConfigForNode returns an xray config that listens for SOCKS5 (no-auth) on
// 127.0.0.1:port and forwards via the given node outbound.
func xrayConfigForNode(port int, outbound map[string]any) []byte {
	cfg := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []map[string]any{
			{
				"listen":   "127.0.0.1",
				"port":     port,
				"protocol": "socks",
				"settings": map[string]any{"auth": "noauth", "udp": false},
			},
		},
		"outbounds": []map[string]any{outbound},
	}
	b, _ := json.Marshal(cfg)
	return b
}
