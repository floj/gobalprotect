#!/usr/bin/env bash
set -euo pipefail
export CGO_ENABLED=0
go build -v -ldflags "-X main.version=$(git describe --tags --always) -X main.buildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ)" -o gobalprotect ./cmd/gobalprotect