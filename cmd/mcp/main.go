// DirFuzz MCP server.
//
// Exposes a single MCP tool — dirfuzz_scan — that lets an AI assistant
// (Claude, etc.) launch directory-fuzzing scans.  Before starting any scan the
// server validates the target against live H1-Scope-Watcher JSON files so the
// AI cannot accidentally fuzz out-of-scope assets.
//
// Required environment variables:
//
//	DIRFUZZ_WORDLIST_DIR   directory that contains wordlist .txt files
//	DIRFUZZ_SCOPE_DIR      directory that contains H1-Scope-Watcher .json files
//
// Optional environment variables:
//
//	DIRFUZZ_MAX_THREADS    max concurrent workers per scan      (default 15)
//	DIRFUZZ_MAX_RESULTS    max results returned to the AI       (default 200)
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"dirfuzz/pkg/engine"
	"dirfuzz/pkg/scope"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// ── startup constants & defaults ─────────────────────────────────────────────

const (
	defaultMaxThreads = 15
	defaultMaxResults = 200

	serverName    = "DirFuzz"
	serverVersion = "2.3.0"
	toolName      = "dirfuzz_scan"
)

// ── server config (loaded once at startup) ───────────────────────────────────

type mcpConfig struct {
	wordlistDir string
	scopeDir    string
	maxThreads  int
	maxResults  int
}

func loadConfig() (mcpConfig, error) {
	cfg := mcpConfig{
		maxThreads: defaultMaxThreads,
		maxResults: defaultMaxResults,
	}

	cfg.wordlistDir = strings.TrimSpace(os.Getenv("DIRFUZZ_WORDLIST_DIR"))
	if cfg.wordlistDir == "" {
		return mcpConfig{}, fmt.Errorf("DIRFUZZ_WORDLIST_DIR is required")
	}
	if info, err := os.Stat(cfg.wordlistDir); err != nil || !info.IsDir() {
		return mcpConfig{}, fmt.Errorf("DIRFUZZ_WORDLIST_DIR %q is not a readable directory", cfg.wordlistDir)
	}

	cfg.scopeDir = strings.TrimSpace(os.Getenv("DIRFUZZ_SCOPE_DIR"))
	if cfg.scopeDir == "" {
		return mcpConfig{}, fmt.Errorf("DIRFUZZ_SCOPE_DIR is required — set it to the directory containing H1-Scope-Watcher JSON files")
	}
	if info, err := os.Stat(cfg.scopeDir); err != nil || !info.IsDir() {
		return mcpConfig{}, fmt.Errorf("DIRFUZZ_SCOPE_DIR %q is not a readable directory", cfg.scopeDir)
	}

	if raw := strings.TrimSpace(os.Getenv("DIRFUZZ_MAX_THREADS")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			return mcpConfig{}, fmt.Errorf("DIRFUZZ_MAX_THREADS must be a positive integer, got %q", raw)
		}
		cfg.maxThreads = n
	}

	if raw := strings.TrimSpace(os.Getenv("DIRFUZZ_MAX_RESULTS")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			return mcpConfig{}, fmt.Errorf("DIRFUZZ_MAX_RESULTS must be a positive integer, got %q", raw)
		}
		cfg.maxResults = n
	}

	return cfg, nil
}

// ── main ─────────────────────────────────────────────────────────────────────

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("dirfuzz-mcp: configuration error: %v", err)
	}

	s := server.NewMCPServer(serverName, serverVersion)

	scanTool := mcp.NewTool(toolName,
		mcp.WithDescription(
			"Run a DirFuzz directory-fuzzing scan against a target URL. "+
				"The target must be in the live H1 scope and bounty-eligible; "+
				"the server will block scans that fall outside the loaded scope files.",
		),
		mcp.WithString("target",
			mcp.Required(),
			mcp.Description("Full target URL to fuzz, e.g. https://api.example.com"),
		),
		mcp.WithString("wordlist",
			mcp.Required(),
			mcp.Description("Wordlist filename (without path) from the server's wordlist directory, e.g. common.txt"),
		),
		mcp.WithString("extensions",
			mcp.Description("Comma-separated extensions to append to every path, e.g. php,html,js (optional)"),
		),
		mcp.WithString("match_codes",
			mcp.Description("Comma-separated HTTP status codes to report, e.g. 200,301,403 (default: 200,204,301,302,401,403)"),
		),
	)

	s.AddTool(scanTool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return handleScan(ctx, req, cfg)
	})

	log.Printf("dirfuzz-mcp: starting (wordlist_dir=%s scope_dir=%s max_threads=%d max_results=%d)",
		cfg.wordlistDir, cfg.scopeDir, cfg.maxThreads, cfg.maxResults)

	if err := server.ServeStdio(s); err != nil {
		log.Fatalf("dirfuzz-mcp: stdio server error: %v", err)
	}
}

// ── tool handler ─────────────────────────────────────────────────────────────

func handleScan(_ context.Context, req mcp.CallToolRequest, cfg mcpConfig) (*mcp.CallToolResult, error) {
	// ── 1. Parse arguments ────────────────────────────────────────────────────
	// Use req.GetString (mcp-go v0.47.1) which safely handles type assertion
	// from the Arguments map and returns the default on any miss.

	target := strings.TrimSpace(req.GetString("target", ""))
	if target == "" {
		return mcp.NewToolResultError("target is required and must be a non-empty string"), nil
	}

	wordlistName := strings.TrimSpace(req.GetString("wordlist", ""))
	if wordlistName == "" {
		return mcp.NewToolResultError("wordlist is required and must be a non-empty string"), nil
	}

	// ── 2. Dynamic scope validation ───────────────────────────────────────────
	//
	// Reload scope files on every request so that additions/removals made by
	// H1-Scope-Watcher are picked up without restarting the MCP server.

	assets, err := scope.LoadDir(cfg.scopeDir)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to read scope directory: %v", err)), nil
	}

	if len(assets) == 0 {
		// No scope files present at all — fail-safe: deny everything.
		return mcp.NewToolResultError(
			"Error: no scope files found in DIRFUZZ_SCOPE_DIR. " +
				"Cannot validate target. Scan blocked.",
		), nil
	}

	if !scope.IsAllowed(target, assets) {
		return mcp.NewToolResultError(
			"Error: Target is not in the live scope or is not bounty eligible. Scan blocked.",
		), nil
	}

	// ── 3. Resolve & sanitise wordlist path ───────────────────────────────────
	//
	// Reject any path-traversal attempt in the wordlist name before filepath.Join.
	// The AI must only be able to reach files inside DIRFUZZ_WORDLIST_DIR.

	if strings.Contains(wordlistName, "..") || strings.ContainsAny(wordlistName, "/\\") {
		return mcp.NewToolResultError("wordlist name must be a plain filename, not a path"), nil
	}
	wordlistPath := filepath.Join(cfg.wordlistDir, wordlistName)
	if _, err := os.Stat(wordlistPath); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("wordlist %q not found in wordlist directory", wordlistName)), nil
	}

	// ── 4. Parse optional parameters ─────────────────────────────────────────

	matchCodesRaw := "200,204,301,302,401,403"
	if raw := strings.TrimSpace(req.GetString("match_codes", "")); raw != "" {
		matchCodesRaw = raw
	}
	matchCodes, err := parseMatchCodes(matchCodesRaw)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("invalid match_codes: %v", err)), nil
	}

	var extensions []string
	if raw := strings.TrimSpace(req.GetString("extensions", "")); raw != "" {
		extensions = parseExtensions(raw)
	}

	// ── 5. Run the scan ───────────────────────────────────────────────────────

	results, err := runScan(target, wordlistPath, cfg.maxThreads, cfg.maxResults, matchCodes, extensions)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("scan failed: %v", err)), nil
	}

	// ── 6. Return results ─────────────────────────────────────────────────────

	return mcp.NewToolResultText(formatResults(target, results, cfg.maxResults)), nil
}

// ── scan runner ───────────────────────────────────────────────────────────────

func runScan(
	target, wordlistPath string,
	threads, maxResults int,
	matchCodes []int,
	extensions []string,
) ([]engine.Result, error) {
	eng := engine.NewEngine(threads, engine.DefaultBloomFilterSize, engine.DefaultBloomFilterFP)
	eng.ConfigureFilters(matchCodes, nil)

	for _, ext := range extensions {
		eng.AddExtension(ext)
	}

	if err := eng.SetTarget(target); err != nil {
		return nil, fmt.Errorf("invalid target: %w", err)
	}

	eng.Start()
	eng.KickoffScanner(wordlistPath, 0)

	go func() {
		eng.Wait()
		eng.Shutdown()
	}()

	collected := make([]engine.Result, 0, 64)
	for res := range eng.Results {
		if res.IsAutoFilter {
			continue
		}
		collected = append(collected, res)
		if len(collected) >= maxResults {
			// Cap reached — shut the engine down and drain so workers don't leak.
			eng.Shutdown()
			for range eng.Results { //nolint:revive // intentional drain
			}
			break
		}
	}

	return collected, nil
}

// ── output formatting ─────────────────────────────────────────────────────────

// formatResults renders collected scan hits as a plain-text table for the AI.
func formatResults(target string, results []engine.Result, maxResults int) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "DirFuzz scan results for: %s\n", target)
	fmt.Fprintf(&sb, "Total hits: %d", len(results))
	if len(results) >= maxResults {
		fmt.Fprintf(&sb, " (capped at %d — re-run with a tighter wordlist to see more)", maxResults)
	}
	sb.WriteString("\n\n")

	if len(results) == 0 {
		sb.WriteString("No findings.\n")
		return sb.String()
	}

	fmt.Fprintf(&sb, "%-6s  %-8s  %-10s  %s\n", "Status", "Method", "Size", "URL")
	sb.WriteString(strings.Repeat("-", 72) + "\n")
	for _, r := range results {
		method := r.Method
		if method == "" {
			method = "GET"
		}
		u := r.URL
		if u == "" {
			u = r.Path
		}
		fmt.Fprintf(&sb, "%-6d  %-8s  %-10d  %s\n", r.StatusCode, method, r.Size, u)
	}
	return sb.String()
}

// ── parameter parsers ─────────────────────────────────────────────────────────

// parseMatchCodes parses a comma-separated status code list into []int.
func parseMatchCodes(raw string) ([]int, error) {
	parts := strings.Split(raw, ",")
	codes := make([]int, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("invalid code %q", p)
		}
		if n < 100 || n > 599 {
			return nil, fmt.Errorf("code %d out of range 100-599", n)
		}
		codes = append(codes, n)
	}
	if len(codes) == 0 {
		return nil, fmt.Errorf("at least one status code is required")
	}
	return codes, nil
}

// parseExtensions splits a comma-separated extension list, stripping leading
// dots and deduplicating entries.
func parseExtensions(raw string) []string {
	parts := strings.Split(raw, ",")
	exts := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, p := range parts {
		ext := strings.TrimPrefix(strings.TrimSpace(p), ".")
		if ext == "" {
			continue
		}
		if _, exists := seen[ext]; exists {
			continue
		}
		seen[ext] = struct{}{}
		exts = append(exts, ext)
	}
	return exts
}
