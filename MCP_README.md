# DirFuzz MCP Server

This repository includes an MCP (Model Context Protocol) server binary located
at `cmd/mcp`. The server exposes a single tool (`dirfuzz_scan`) an AI assistant
(Claude, etc.) can call to run a controlled directory-fuzzing scan using the
internal engine.

The MCP server enforces runtime safety boundaries (wordlist directory sandboxing
and scope validation) so the AI cannot accidentally scan out-of-scope or
private targets.

---

## Building

```bash
# Build the MCP server binary
go build -o dirfuzz-mcp ./cmd/mcp
```

The MCP server binary is small and self-contained. You may also build the
monitor runner in this repository with `go build -o dirfuzz-monitor ./cmd/monitor`.

---

## MCP Server setup

Required environment variables (the server refuses to start without them):

- `DIRFUZZ_WORDLIST_DIR` — directory that contains wordlist `.txt` files. The
  server only serves filenames from this directory (no path traversal allowed).
- `DIRFUZZ_SCOPE_DIR` — directory that contains H1-Scope-Watcher JSON files. A
  target is validated against the live scope files before any scan is allowed.

Optional environment variables:

- `DIRFUZZ_MAX_THREADS` — positive integer cap on concurrent workers per scan
  (default 15).
- `DIRFUZZ_MAX_RESULTS` — maximum number of results returned to the AI per
  scan (default 200).

Example:

```bash
export DIRFUZZ_WORDLIST_DIR=/absolute/path/to/wordlists
export DIRFUZZ_SCOPE_DIR=/absolute/path/to/scope-jsons
export DIRFUZZ_MAX_THREADS=15
export DIRFUZZ_MAX_RESULTS=200
./dirfuzz-mcp
```

### Claude / Copilot Config

```bash
"dirfuzz": {
  "command": "D:\\projects\\DirFuzzMcp\\dirfuzz-mcp.exe",
  "args": [],
  "env": {
    "DIRFUZZ_WORDLIST_DIR": "D:\\projects\\DirFuzzMcp\\wordlists",
    "DIRFUZZ_SCOPE_DIR": "D:\\projects\\H1-Scope-Watcher\\snapshots",
    "DIRFUZZ_MAX_THREADS": "15",
    "DIRFUZZ_MAX_RESULTS": "200"
  }
}
```

---

## What the server does (runtime flow)

1. Reloads scope files from `DIRFUZZ_SCOPE_DIR` on every request and validates
   the requested `target` is within scope. If no scope files are present the
   server denies scans (fail-safe).
2. Resolves the `wordlist` argument against `DIRFUZZ_WORDLIST_DIR` and rejects
   requests that try path traversal or reference non-existent files.
3. Runs the scan with the configured worker cap and match codes, collects
   hits up to `max_results`, then returns a plain-text summary table to the AI.

The server intentionally returns human-readable text rather than raw request
bytes to reduce risk of leaking secrets.

---

## MCP Tool: `dirfuzz_scan`

Parameters exposed by the tool (see `cmd/mcp/main.go` for exact behavior):

- `target` (string, required): Full target URL, e.g. `https://example.com/`.
- `wordlist` (string, required): Wordlist filename located inside
  `DIRFUZZ_WORDLIST_DIR` (plain filename only; path components are rejected).
- `extensions` (string, optional): Comma-separated extensions to append, e.g.
  `php,html,js`.
- `match_codes` (string, optional): Comma-separated HTTP status codes to
  treat as hits. Default: `200,204,301,302,401,403`.

The server parses and sanitizes these inputs, validates the target against the
live scope, runs the scan, and returns a formatted text result table.

---

## Wordlist handling

The MCP server expects wordlists to be regular `.txt` files placed within
`DIRFUZZ_WORDLIST_DIR`. The tool accepts only a filename (no `../` or path
components). This keeps the AI confined to a known set of wordlists.

To enumerate available wordlists the MCP client can implement a separate
helper that lists `.txt` files in the server's wordlist directory.

---

## Output and security

- The MCP server returns a plain-text summary (table) of hits, up to
  `DIRFUZZ_MAX_RESULTS`. If the cap is reached the output notes the cap and
  suggests re-running with a tighter wordlist.
- Raw request/response bytes are never returned by the MCP API. The engine
  only populates `request` and `response` JSON fields when locally run with
  `--save-raw`, which is deliberately excluded from the MCP tool to avoid
  leaking credentials or session tokens.

---

## Example usage (AI conversation)

The AI can first list available wordlists (client-side action), then call
`dirfuzz_scan` with `wordlist=common.txt` and `target=https://testphp.vulnweb.com`.

The server will reply with a short table like:

```
DirFuzz scan results for: https://testphp.vulnweb.com
Total hits: 12

Status  Method    Size       URL
------------------------------------------------------------
200     GET       4821       https://testphp.vulnweb.com/admin
301     GET       0          https://testphp.vulnweb.com/images
200     GET       4600       https://testphp.vulnweb.com/login.php
```

---

## Implementation notes (for maintainers)

- Scope validation uses `pkg/scope` and is reloaded on every request so the
  server picks up changes made by `H1-Scope-Watcher` without restart.
- Wordlist names are validated to contain no path separators and must exist
  under `DIRFUZZ_WORDLIST_DIR`.
- `cmd/mcp` builds an `engine.Engine`, configures match codes and extensions,
  runs the scanner, collects results up to the configured cap, and returns a
  formatted text result.

See `cmd/mcp/main.go` for exact environment variables, parsing rules and
error-handling behavior.
`--save-raw` is enabled on the CLI, and exposing that option to remote MCP
callers would risk leaking sensitive tokens or cookies. If you need raw
request/response data for debugging, run the CLI locally with `--save-raw`.

### `dirfuzz_scan`

Runs a directory fuzzing scan. Parameters:

| Parameter | Type | Required | Description |
|---|---|---|---|
| `target` | string | ✅ | Target URL, e.g. `https://example.com/` |
| `wordlist` | string | | Wordlist selector. Can be filename (`common.txt`) or relative path (`Discovery/Web-Content/common.txt`). Default: `common.txt` |
| `threads` | number | | Concurrent threads (1–MAX_THREADS). Default: 10 |
| `match_codes` | string | | Comma-separated status codes to treat as hits. Default: `200,204,301,302,307,308,401,403,405,500` |
| `extensions` | string | | Extensions to append, e.g. `php,html,js` |
| `recursive` | boolean | | Recursive directory scanning. Default: false |
| `max_depth` | number | | Max recursion depth. Default: 2 |
| `timeout_seconds` | number | | Per-request timeout (1–30). Default: 5 |
| `match_regex` | string | | Only include results whose body matches this regex |
| `filter_regex` | string | | Exclude results whose body matches this regex |
| `insecure` | boolean | | Skip TLS verification. Default: false |
| `max_results` | number | | Result cap per scan. Default: server's MAX_RESULTS |

### `dirfuzz_list_wordlists`

Lists all available `.txt` wordlist files on the server (recursive), returned as relative paths. No parameters.

---

## Example Claude Conversation

```
You: Can you check what directories are exposed on https://testphp.vulnweb.com?

Claude: [calls dirfuzz_list_wordlists]
        Found: common.txt (185,098 bytes)

        [calls dirfuzz_scan with target=https://testphp.vulnweb.com, wordlist=common.txt, threads=10]
        
        Found 12 paths:
        - /admin (200, 1.2KB)
        - /images (301)
        - /login.php (200, 4.5KB)
        ...
```

## Example 

#### Out of Scope:

<img width="1093" height="297" alt="image" src="https://github.com/user-attachments/assets/5efb9671-2e40-4185-a68b-4bda7c6b0c1f" />

----

#### Scope

<img width="1101" height="303" alt="Screenshot 2026-04-26 215930" src="https://github.com/user-attachments/assets/daed41e8-90d1-4ed1-bc3c-9b9d448e497f" />

---

## Changes vs Original DirFuzz

### Bug Fixes Applied
1. **Lua VM pool** (`pkg/engine/plugins.go`) — replaced single mutex-serialised Lua VM with a per-CPU pool. Under 50 threads, the old design bottlenecked all workers through one VM. The pool lets up to 16 VMs run in parallel.

2. **Context-aware rate limiter** (`pkg/engine/engine.go`) — the per-host rate limiter `Wait` now uses `scannerCtx` instead of `context.Background()`. Previously, cancelling a scan left workers blocked in the rate limiter indefinitely.

3. **TUI dropped-result counter** (`pkg/engine/engine.go`, `pkg/tui/tui.go`, `cmd/dirfuzz/scan.go`) — the TUI channel drop was silently discarding hits under high load. The engine now counts drops via `TUIDropped int64`. The TUI header shows `⚠ TUI-dropped:N` and a post-scan warning is printed. **File output is never affected.**

4. **SSRF protection in `SetTarget`** (`pkg/engine/engine.go`) — when the engine is driven programmatically (MCP server), it now rejects private/loopback IP ranges (10.x, 172.16.x, 192.168.x, 127.x, ::1, fc00::/7, fe80::/10) and `localhost`. The CLI is unaffected since you control the binary yourself.

5. **main.go refactored** — the original 818-line monolith split into `cmd/dirfuzz/main.go`, `flags.go`, `scan.go`, and `types.go`. Functionality is identical.
