package web

import (
	"strings"
	"sync"
)

// Event is a single pub/sub message delivered over SSE. Type is the SSE event
// name; Payload is JSON-encoded as the data line.
type Event struct {
	Type    string `json:"type"`
	Payload any    `json:"payload"`
}

// Hub is an in-process pub/sub broadcaster. Subscribers receive a buffered
// channel; slow subscribers are dropped (their queued event is skipped) so a
// stuck SSE connection can never block the publisher or other clients.
type Hub struct {
	mu   sync.Mutex
	subs map[chan Event]struct{}
}

// NewHub builds an empty hub.
func NewHub() *Hub {
	return &Hub{subs: make(map[chan Event]struct{})}
}

// Subscribe returns a receive channel for events and an unsubscribe function.
// The channel is buffered (16); call the returned func to detach.
func (h *Hub) Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, 16)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	unsub := func() {
		h.mu.Lock()
		if _, ok := h.subs[ch]; ok {
			delete(h.subs, ch)
			close(ch)
		}
		h.mu.Unlock()
	}
	return ch, unsub
}

// Publish broadcasts e to every subscriber, dropping it for any subscriber whose
// buffer is full.
func (h *Hub) Publish(e Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs {
		select {
		case ch <- e:
		default:
		}
	}
}

// ringBuffer is a fixed-capacity, goroutine-safe log of recent lines (oldest
// dropped when full).
type ringBuffer struct {
	mu   sync.Mutex
	buf  []string
	size int
}

func newRingBuffer(size int) *ringBuffer {
	if size <= 0 {
		size = 256
	}
	return &ringBuffer{buf: make([]string, 0, size), size: size}
}

func (r *ringBuffer) append(line string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf = append(r.buf, line)
	if len(r.buf) > r.size {
		r.buf = r.buf[len(r.buf)-r.size:]
	}
}

// Recent returns up to n of the most recent lines (all when n <= 0).
func (r *ringBuffer) Recent(n int) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if n <= 0 || n >= len(r.buf) {
		out := make([]string, len(r.buf))
		copy(out, r.buf)
		return out
	}
	out := make([]string, n)
	copy(out, r.buf[len(r.buf)-n:])
	return out
}

// logCapture is an io.Writer that splits the global log stream into complete
// lines, appends each to the ring buffer, and publishes it as a "log" event.
// It is installed via log.SetOutput so the web UI can show a live log without
// disturbing the original stderr writer (restored on Stop).
type logCapture struct {
	mu      sync.Mutex
	ring    *ringBuffer
	hub     *Hub
	partial string
}

func newLogCapture(hub *Hub, size int) *logCapture {
	return &logCapture{ring: newRingBuffer(size), hub: hub}
}

func (l *logCapture) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.partial += string(p)
	for {
		idx := strings.IndexByte(l.partial, '\n')
		if idx < 0 {
			break
		}
		line := strings.TrimRight(l.partial[:idx], "\r")
		l.partial = l.partial[idx+1:]
		l.ring.append(line)
		if l.hub != nil {
			l.hub.Publish(Event{Type: "log", Payload: line})
		}
	}
	return len(p), nil
}

func (l *logCapture) Recent(n int) []string {
	if l == nil {
		return nil
	}
	return l.ring.Recent(n)
}
