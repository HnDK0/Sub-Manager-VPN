package mihomo

import (
	"context"
	"errors"
	"io"
	"net/http"
	"time"
)

// ErrClosed is returned by all engine methods after Close.
var ErrClosed = errors.New("mihomo: engine closed")

// httpSpeed downloads url through client and returns throughput in kbps.
// It mirrors the legacy test.httpSpeed helper but routes via the mixed-port
// client instead of a SOCKS5 subprocess.
func httpSpeed(ctx context.Context, client *http.Client, url string, topN, minMbps int) int64 {
	if topN <= 0 {
		topN = 1
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0
	}

	start := time.Now()
	buf := make([]byte, 32*1024)
	var total int64
	deadline := start.Add(8 * time.Second)
	for {
		if time.Now().After(deadline) {
			break
		}
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			total += int64(n)
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			break
		}
	}
	elapsed := time.Since(start).Seconds()
	if elapsed <= 0 {
		return 0
	}
	kbps := int64((float64(total) * 8) / elapsed / 1000)
	if minMbps > 0 && kbps < int64(minMbps*1000) {
		return 0
	}
	return kbps
}
