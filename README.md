# 🦇 DirFuzz v2.3

A high-performance, feature-rich directory and endpoint fuzzer for bug bounty
hunting and web application penetration testing.

> **v2.3** ships with 6 performance improvements and 9 new features.

DirFuzz is a high-performance directory/endpoint fuzzing engine and set of
runners focused on reliable, memory-efficient scanning and automation. This
repository contains the core engine and two runtime binaries you can build and
run: a continuous **monitor** runner and an **MCP** server for AI integration.

Note: A standalone interactive `dirfuzz` CLI is not included in this
repository. The scanning engine is implemented in `pkg/engine` and can be
embedded by downstream CLIs or services.

---

## Key Features

- Raw TCP/TLS request control (low-level `httpclient` without `net/http`)
- Connection pooling and TLS cipher shuffling for performance and evasion
- Bloom-filter deduplication and per-host rate limiting
- Wildcard/soft-404 detection and smart auto-filtering
- Recursive scanning with bounded concurrency and recursion depth control
- Eagle Mode (differential scans against a previous JSONL baseline)
- Lua plugin system with parallel VM pool (matchers + mutators)
- Proxy rotation (SOCKS5 + HTTP) and outbound proxy replay (Burp/ZAP)
- Resume support, multiple output formats (JSONL/CSV/URL) and optional raw
  request/response capture (`--save-raw`)

---

## Binaries in this repository

- `cmd/monitor` — Continuous monitor runner that executes scheduled scans,
  stores state as JSONL, and sends Discord alerts for new or changed
  endpoints.
- `cmd/mcp` — MCP (Model Context Protocol) server exposing `dirfuzz_scan` to
  AI assistants. The server runs scans using the same engine and enforces a
  scope safety boundary.

---

## Installation

Requirements: Go 1.22+

```bash
git clone https://github.com/tobiasGuta/DirFuzzMcp.git
cd DirFuzzMcp
# Build the monitor (continuous runner)
go build -o dirfuzz-monitor ./cmd/monitor

# Build the MCP server (AI tool)
go build -o dirfuzz-mcp ./cmd/mcp
```

You can also run directly during development:

```bash
go run ./cmd/monitor
go run ./cmd/mcp
```

There is no packaged `dirfuzz` CLI in this repository; if you need an
interactive CLI you can embed the engine from `pkg/engine` and add a small
`main` wrapper.

---

## Quick Start

Monitor (example):

```bash
export TARGET="https://target.example.com"
export WORDLIST="/path/to/wordlist.txt"
export DISCORD_WEBHOOK="https://discordapp/api/webhooks/..."
export STATE_FILE="/data/site-state.jsonl"   # optional
export SCAN_INTERVAL="1h"                    # optional
export WORKERS=50                             # optional
./dirfuzz-monitor
```

Run the monitor via the included `docker-compose.yml` as well (it builds the
monitor binary and mounts your wordlists/state):

```bash
docker-compose up --build
```

MCP server (AI integration):

```bash
# The MCP server requires two environment variables:
export DIRFUZZ_WORDLIST_DIR="/absolute/path/to/wordlists"
export DIRFUZZ_SCOPE_DIR="/absolute/path/to/scope-jsons"
./dirfuzz-mcp
```

See `cmd/mcp/main.go` for the exact MCP tool parameters and `cmd/monitor`
for monitor environment variables.

---

## Engine Capabilities (summary)

The engine (`pkg/engine`) exposes a rich configuration surface. Key features
you will commonly use when embedding or integrating the engine:

- Status-code matching / filtering (match lists, ranges)
- Response-size and size-range filters
- Content-Type match/filter substrings
- Body match / filter regular expressions
- Word/line count matching and filtering
- Multi-method fuzzing and a `SmartAPI` mode for API-style paths
- Smart mutation and an extensible mutator list
- Recursive scanning with configurable max depth
- Per-host rate limiting, proxy rotation, and proxy replay
- Lua matcher and mutator plugins (see `plugins/`)
- Resume, save/load previous scan baselines (Eagle Mode), and output
  format control

For exact field names, data types and code-level behavior see
`pkg/engine/engine.go` and `pkg/engine/plugins.go`.

---

## Lua Plugins

Place Lua scripts in `plugins/` (examples included). Mutators must define
`mutate(original)` and matchers must define `match(response)`; the engine
runs plugins using a pool of Lua VMs so they do not become a global bottleneck.

Example usage from code:

```bash
./dirfuzz-mcp   # MCP server uses wordlists provided to it
# or when embedding the engine pass -plugin-match plugins/example_matcher.lua
```

---

## MCP Server

The MCP server (`cmd/mcp`) exposes a simple `dirfuzz_scan` tool for AI
assistants. See `MCP_README.md` for exact MCP parameters and security notes.

---

## Project Structure

```
DirFuzzMcp/
├── cmd/
│   ├── monitor/          # Continuous monitor runner (dirfuzz-monitor)
│   └── mcp/              # MCP server (dirfuzz-mcp)
├── pkg/
│   ├── engine/           # Core scan engine
│   ├── httpclient/       # Raw HTTP/TLS client + pooling
│   └── tui/              # TUI components (used by potential CLI)
├── plugins/              # Example Lua plugins
├── wordlists/            # Sample wordlists
├── dirfuzz.yaml.example  # Example config file
├── docker-compose.yml
├── Dockerfile
├── README.md
└── MCP_README.md
```

---

## License

MIT
