#!/usr/bin/env bash
# smoke.sh — minimal local smoke test for vpn-sub-manager.
#
# Builds, vets, and runs the full unit/integration suite. No network is
# required: the integration test's real-xray path skips cleanly when GitHub is
# unreachable, and the fake-SOCKS5 path exercises the full pool+probe+persist
# flow in-process.
#
# For a real end-to-end run on Linux (after building), add your whitelisted
# source(s) via the TUI or by editing the sources file, then run:
#   go run . -interval 10m
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== build =="
go build ./...

echo "== vet =="
go vet ./...

echo "== test =="
go test ./...

echo "== smoke OK =="
