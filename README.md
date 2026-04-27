# 🦇 DirFuzz v2.3

DirFuzz is a memory-efficient, high-performance directory/endpoint fuzzing
engine and set of runnable tools useful for large-scale scans, continuous
monitoring and safe AI-driven automation. This repository contains the core
engine (embeddable), a CLI runner with an optional TUI, a continuous
monitoring runner and an MCP (Model Context Protocol) server for AI
integration.

This README summarises what the code in this repository actually provides
and where to look for exact flags and configuration.

---

## Highlights

- High-performance raw HTTP/1.1 client with pooling, TLS cipher randomisation
  and SOCKS5/HTTP proxy support.
- Memory-efficient deduplication using a Bloom filter and per-host rate
  limiting.
- Rich matching and filtering (status codes, content-type, size, regex,
  word/line counts, response time ranges).
- Recursive scanning with bounded concurrency and soft-404 / wildcard
  detection.
- Lua plugin system (parallel VM pool) for custom matchers and mutators.
- Resume / Eagle Mode (differential scans against a previous JSONL baseline).
- Multiple output formats (`jsonl`, `csv`, `url`) and optional raw request/
  response capture (`--save-raw`).
- Safe AI tooling via an MCP server that validates targets against live
  scope JSON files before running scans.

---

## Provided binaries / runners

- `cmd/dirfuzz` — CLI runner with an optional TUI. The CLI exposes the full
  engine surface (methods, filters, proxies, plugins, resume, eagle mode,
  output formats). See [cmd/dirfuzz/flags.go](cmd/dirfuzz/flags.go#L1-L220)
  for the canonical list of flags.
- `cmd/monitor` — Continuous monitor runner: executes scheduled scans,
  persists state as JSONL, compares against previous state (Eagle Mode)
  and can send Discord webhooks for new/changed endpoints. See
  [cmd/monitor/main.go](cmd/monitor/main.go#L1-L220).
- `cmd/mcp` — MCP server exposing a `dirfuzz_scan` tool for AI assistants.
  The server validates targets against H1-style scope JSON files (see
  `pkg/scope`) and constrains wordlist selection to a configured directory.
  See [cmd/mcp/main.go](cmd/mcp/main.go#L1-L260) and `MCP_README.md`.

---

## Build

Requirements: Go 1.22+

Build locally:

```bash
git clone https://github.com/tobiasGuta/DirFuzzMcp.git
cd DirFuzzMcp
go build -o dirfuzz ./cmd/dirfuzz
go build -o dirfuzz-monitor ./cmd/monitor
go build -o dirfuzz-mcp ./cmd/mcp
```

Run during development:

```bash
go run ./cmd/dirfuzz --help
go run ./cmd/monitor
go run ./cmd/mcp
```

Docker / compose: the included `docker-compose.yml` can build and run the
monitor image and mount your wordlists and state files.

---

## Example usage

CLI (TUI):

```bash
./dirfuzz -u https://api.example.com -w wordlists/common.txt -t 50 -r -depth 3
```

CLI (non-TUI, save JSONL):

```bash
./dirfuzz --no-tui -u https://example.com -w wordlists/common.txt -o results.jsonl
```

Monitor (env-driven):

```bash
export TARGET=https://target.example.com
export WORDLIST=/data/wordlists/common.txt
export DISCORD_WEBHOOK=https://discordapp/api/webhooks/...
export STATE_FILE=/data/state.jsonl
export SCAN_INTERVAL=1h
./dirfuzz-monitor
```

MCP server (AI integration):

```bash
export DIRFUZZ_WORDLIST_DIR=/srv/dirfuzz/wordlists
export DIRFUZZ_SCOPE_DIR=/srv/dirfuzz/scopes   # directory of H1-style JSON scope files
./dirfuzz-mcp
```

The MCP tool also accepts parameters (wordlist filename, extensions,
match codes) — see [cmd/mcp/main.go](cmd/mcp/main.go#L1-L260).

---

## Engine & embedding

The scanning engine is implemented in `pkg/engine`. It is designed to be
embedded by other programs and exposes a `Config` struct that controls the
runtime behaviour. Notable capabilities (see code for exact field names):

- Status code matching & filtering (individual codes and ranges).
- Response-size filtering and inclusive size ranges.
- Content-Type inclusion/exclusion filters.
- Body match / filter regular expressions.
- Word/line count filters and response time filters.
- Multi-method fuzzing and `SmartAPI` mode to treat API-like paths
  specially.
- Recursive scanning with `MaxDepth`, bounded concurrency and wildcard
  detection.
- Proxy rotation (HTTP & SOCKS5) and an outbound `proxy-out` mode for
  forwarding interesting hits to a proxy for manual inspection.
- Resume support and `LoadPreviousScan` for Eagle Mode differential
  comparison.
- Lua plugin hooks: `PluginMatcher` and `PluginMutator` pools (see
  [pkg/engine/plugins.go](pkg/engine/plugins.go#L1-L200)).

For exact API and field names see [pkg/engine/engine.go](pkg/engine/engine.go#L1-L240).

---

## Lua plugins

Place Lua scripts in the `plugins/` directory or point the CLI at a plugin
file with `--plugin-match` / `--plugin-mutate`.

- Matchers must expose a `match(tbl)` function that receives a table with
  `status_code`, `size`, `words`, `lines`, `body`, and `content_type` and
  must return a boolean.
- Mutators must expose a `mutate(original)` function that returns an array
  of payload variants.

Plugins are executed inside a pool of Lua VMs so they can run in parallel
without serialising all workers.

---

## HTTP client

The engine uses the raw client in `pkg/httpclient` which implements:

- Raw HTTP/1.1 request sending with optional pooling.
- TLS cipher shuffling and configurable TLS options (min/max TLS).
- SOCKS5 and HTTP proxy support (including Basic auth for HTTP proxies).
- Automatic handling of chunked responses and common encodings (gzip, zlib,
  deflate). Maximum body read size protects against very large responses.

See [pkg/httpclient/client.go](pkg/httpclient/client.go#L1-L260) for details.

---

## Safety & scope validation

When running as an MCP tool the server validates every requested target
against a live directory of H1-style scope JSON files (`pkg/scope`). The
server denies scans that are not covered by the scope files to prevent
accidental out-of-scope scanning. See
[pkg/scope/validator.go](pkg/scope/validator.go#L1-L200).

---

## Output formats & Eagle Mode

- `jsonl` (one JSON result per line) — good for resumes and diffs.
- `csv` — tabular export.
- `url` — print only matching URLs (good for piping into other tools).

Eagle Mode loads a previous JSONL state file and highlights changed or new
endpoints when comparing scan results. Engines expose `LoadPreviousScan()`
to populate the baseline.

---

## Configuration examples

- Example config: [dirfuzz.yaml.example](dirfuzz.yaml.example)
- MCP notes: [MCP_README.md](MCP_README.md)

---

## Where to look for flags and behaviour

- CLI flags: [cmd/dirfuzz/flags.go](cmd/dirfuzz/flags.go#L1-L220)
- Monitor runner: [cmd/monitor/main.go](cmd/monitor/main.go#L1-L240)
- MCP server: [cmd/mcp/main.go](cmd/mcp/main.go#L1-L260)
- Engine internals: [pkg/engine/engine.go](pkg/engine/engine.go#L1-L240)
- Lua plugin pool: [pkg/engine/plugins.go](pkg/engine/plugins.go#L1-L120)
- Raw HTTP client: [pkg/httpclient/client.go](pkg/httpclient/client.go#L1-L260)

---

## Contributing

Contributions are welcome. Please open issues for bugs or feature requests
before sending PRs. The project follows small, focused changes — avoid
big refactors without prior discussion.

---

## License

MIT
