# vpn-sub-manager — developer tasks
# Target platform: Linux (Ubuntu 22+). Dev also runs on Windows/macOS (code is cross-platform).

.PHONY: build vet test test-race run clean

build:
	go build ./...

vet:
	go vet ./...

# Full consolidated unit/integration suite.
test:
	go test ./...

# With the race detector (slower; use before releases).
test-race:
	go test -race ./...

run:
	go run .

clean:
	go clean ./...
