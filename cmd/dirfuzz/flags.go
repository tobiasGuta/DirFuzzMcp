package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"dirfuzz/pkg/engine"
)

const (
	cliVersion        = "2.3.0"
	defaultMatchCodes = "200,204,301,302,307,308,401,403,405,500"
	defaultResumeFile = ".dirfuzz-resume.json"
)

func parseFlags() cliConfig {
	// ── Meta ─────────────────────────────────────────────────────────────────
	showVersion := flag.Bool("version", false, "Print version and exit")
	noTUI       := flag.Bool("no-tui", false, "Disable the TUI — print results to stdout (good for piping)")
	verbose     := flag.Bool("v", false, "Verbose: log every request, not only hits (no-tui mode only)")

	// ── Required ─────────────────────────────────────────────────────────────
	target   := flag.String("u", "", "Target URL to fuzz  (required)")
	wordlist := flag.String("w", "", "Path to wordlist file  (required, unless -resume)")
	profile  := flag.String("profile", "", "Path to YAML/JSON scan profile; explicit CLI flags override profile values")

	// ── Workers / throttle ────────────────────────────────────────────────────
	threads := flag.Int("t", engine.DefaultWorkerCount, "Number of concurrent workers")
	delay   := flag.Duration("delay", 0, "Fixed delay between requests per worker (e.g. 100ms)")
	rps     := flag.Int("rps", 0, "Global requests-per-second cap  (0 = unlimited)")

	// ── HTTP ─────────────────────────────────────────────────────────────────
	ua           := flag.String("ua", "", "Override the User-Agent header")
	cookie       := flag.String("b", "", "Cookie header value  (shorthand for -H 'Cookie: …')")
	methods      := flag.String("m", "", "HTTP methods, comma-separated  (default: GET)")
	body         := flag.String("d", "", "Request body for POST / PUT")
	follow       := flag.Bool("follow", false, "Follow HTTP redirects")
	maxRedirects := flag.Int("max-redirects", engine.DefaultMaxRedirects, "Maximum redirects to follow")
	timeout      := flag.Duration("timeout", engine.DefaultHTTPTimeout, "Per-request timeout  (e.g. 5s)")
	insecure     := flag.Bool("k", false, "Skip TLS certificate verification")

	// ── Matching / filtering ─────────────────────────────────────────────────
	matchCodes  := flag.String("mc", defaultMatchCodes, "Status codes to treat as hits, comma-separated")
	filterSizes := flag.String("fs", "", "Response sizes to filter out (bytes), comma-separated")
	extensions  := flag.String("e", "", "Extensions to append, comma-separated  (e.g. php,html,js)")
	matchRegex  := flag.String("mr", "", "Only surface results whose body matches this regex")
	filterRegex := flag.String("fr", "", "Discard results whose body matches this regex")
	filterWords := flag.Int("fw", -1, "Filter results with exactly N words  (-1 = off)")
	filterLines := flag.Int("fl", -1, "Filter results with exactly N lines  (-1 = off)")
	matchWords  := flag.Int("mw", -1, "Only surface results with exactly N words  (-1 = off)")
	matchLines  := flag.Int("ml", -1, "Only surface results with exactly N lines  (-1 = off)")
	rtMin       := flag.Duration("rt-min", 0, "Filter responses faster than this  (e.g. 200ms)")
	rtMax       := flag.Duration("rt-max", 0, "Filter responses slower than this  (e.g. 5s)")

	// ── Output ───────────────────────────────────────────────────────────────
	outputFormat := flag.String("of", "", "Output format: jsonl | csv | url  (default: jsonl when -o is set)")
	outputFile   := flag.String("o", "", "Write results to this file")
	reportFile   := flag.String("report", "", "Write a Markdown/HTML summary report to this file")
	reportFormat := flag.String("report-format", "", "Report format: markdown | html  (inferred from -report extension when empty)")
	saveRaw      := flag.Bool("save-raw", false, "Save raw HTTP request/response bytes in results")

	// ── Scan modes ───────────────────────────────────────────────────────────
	recursive           := flag.Bool("r", false, "Recursive directory scanning")
	maxDepth            := flag.Int("depth", engine.DefaultMaxDepth, "Maximum recursion depth  (requires -r)")
	mutate              := flag.Bool("mutate", false, "Append backup/swap suffixes to every hit (.bak, .old, ~, …)")
	smartAPI            := flag.Bool("smart-api", false, "Multi-method fuzzing only on API-style paths (/api/, /v1/, …)")
	autoFilterThreshold := flag.Int("af", engine.DefaultAutoFilterThreshold,
		"Auto-filter: suppress repeated same-size responses after N occurrences")
	maxRetries := flag.Int("retry", 0, "Retry failed requests up to N times on connection error")
	dryRun     := flag.Bool("dry-run", false, "Estimate request volume and exit without sending traffic")

	// ── Eagle mode ───────────────────────────────────────────────────────────
	eagleFile := flag.String("eagle", "",
		"Eagle mode: path to a previous scan JSONL — highlights changed/new endpoints")

	// ── Resume ───────────────────────────────────────────────────────────────
	resume     := flag.Bool("resume", false, "Resume a previous scan from the saved state file")
	resumeFile := flag.String("resume-file", defaultResumeFile, "Path of the resume-state JSON file")

	// ── Calibration ──────────────────────────────────────────────────────────
	calibrate := flag.Bool("calibrate", false,
		"Auto-calibrate: probe random paths to detect wildcard / soft-404 responses")

	// ── Proxy ────────────────────────────────────────────────────────────────
	proxyFile := flag.String("proxy", "", "Path to proxy list  (HTTP / SOCKS5 URLs, one per line)")
	proxyOut  := flag.String("proxy-out", "",
		"Forward every hit to this proxy for manual review  (e.g. http://127.0.0.1:8080)")

	// ── Lua plugins ──────────────────────────────────────────────────────────
	pluginMatch  := flag.String("plugin-match", "",
		"Lua plugin providing match(r) for custom hit logic")
	pluginMutate := flag.String("plugin-mutate",
		"", "Lua plugin providing mutate(word) for custom payload generation")

	// ── Multi-value ──────────────────────────────────────────────────────────
	var headers multiFlag
	flag.Var(&headers, "H", "Add a custom header  (format: 'Key: Value', repeatable)")

	flag.Usage = printUsage
	flag.Parse()
	setFlags := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) { setFlags[f.Name] = true })

	if *showVersion {
		fmt.Fprintf(os.Stderr, "DirFuzz v%s\n", cliVersion)
		os.Exit(0)
	}

	// Infer output format when -o is provided without -of.
	outFmt := *outputFormat
	if outFmt == "" && *outputFile != "" {
		outFmt = engine.DefaultOutputFormat // "jsonl"
	}

	cfg := cliConfig{
		Target:   *target,
		Wordlist: *wordlist,
		Profile:  *profile,

		Threads: *threads,
		Delay:   *delay,
		RPS:     *rps,

		UserAgent:    *ua,
		Headers:      []string(headers),
		Cookie:       *cookie,
		Methods:      *methods,
		Body:         *body,
		Follow:       *follow,
		MaxRedirects: *maxRedirects,
		Timeout:      *timeout,
		Insecure:     *insecure,

		MatchCodes:  *matchCodes,
		FilterSizes: *filterSizes,
		Extensions:  *extensions,
		MatchRegex:  *matchRegex,
		FilterRegex: *filterRegex,
		FilterWords: *filterWords,
		FilterLines: *filterLines,
		MatchWords:  *matchWords,
		MatchLines:  *matchLines,
		RTMin:       *rtMin,
		RTMax:       *rtMax,

		OutputFormat: outFmt,
		OutputFile:   *outputFile,
		ReportFile:   *reportFile,
		ReportFormat: *reportFormat,
		SaveRaw:      *saveRaw,

		Recursive:           *recursive,
		MaxDepth:            *maxDepth,
		Mutate:              *mutate,
		SmartAPI:            *smartAPI,
		AutoFilterThreshold: *autoFilterThreshold,
		MaxRetries:          *maxRetries,
		DryRun:              *dryRun,

		EagleFile: *eagleFile,

		Resume:     *resume,
		ResumeFile: *resumeFile,

		Calibrate: *calibrate,

		ProxyFile: *proxyFile,
		ProxyOut:  *proxyOut,

		PluginMatch:  *pluginMatch,
		PluginMutate: *pluginMutate,

		NoTUI:   *noTUI,
		Verbose: *verbose,
	}

	if cfg.Profile != "" {
		if err := applyProfile(&cfg, setFlags); err != nil {
			fmt.Fprintf(os.Stderr, "error: loading profile: %v\n", err)
			os.Exit(1)
		}
	}
	if cfg.OutputFormat == "" && cfg.OutputFile != "" {
		cfg.OutputFormat = engine.DefaultOutputFormat
	}
	if cfg.ReportFormat == "" && cfg.ReportFile != "" {
		cfg.ReportFormat = inferReportFormat(cfg.ReportFile)
	}
	if cfg.Target == "" {
		fmt.Fprintln(os.Stderr, "error: -u <target> is required")
		fmt.Fprintln(os.Stderr)
		flag.Usage()
		os.Exit(1)
	}
	if cfg.Wordlist == "" && !cfg.Resume {
		fmt.Fprintln(os.Stderr, "error: -w <wordlist> is required (or pass -resume to resume a previous scan)")
		fmt.Fprintln(os.Stderr)
		flag.Usage()
		os.Exit(1)
	}
	if cfg.Threads < 1 {
		fmt.Fprintln(os.Stderr, "error: -t must be >= 1")
		os.Exit(1)
	}
	return cfg
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `DirFuzz v%s — high-performance directory fuzzer

Usage:
  dirfuzz -u <target> -w <wordlist> [options]

Quick examples:
  dirfuzz -u https://example.com -w wordlists/common.txt
  dirfuzz -u https://example.com -w wordlists/common.txt -e php,html -mc 200,301,403
  dirfuzz -u https://example.com -w wordlists/common.txt --no-tui -o results.jsonl
  dirfuzz -u https://example.com -w wordlists/common.txt -r -depth 3 --calibrate
  dirfuzz -u https://example.com -w wordlists/common.txt --eagle prev.jsonl

All flags:
`, cliVersion)
	flag.PrintDefaults()
}

// csvInts splits a comma-separated string of integers. Returns nil, nil for
// empty input. Returns an error for any non-integer token.
func csvInts(raw string) ([]int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	parts := splitTrimmed(raw)
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		var n int
		if _, err := fmt.Sscanf(p, "%d", &n); err != nil {
			return nil, fmt.Errorf("invalid integer %q in list", p)
		}
		out = append(out, n)
	}
	return out, nil
}

// splitTrimmed splits s on commas, trims whitespace from each token, and
// drops empty tokens.
func splitTrimmed(s string) []string {
	raw := strings.Split(s, ",")
	out := make([]string, 0, len(raw))
	for _, p := range raw {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// mustCSVInts wraps csvInts and exits on error.
func mustCSVInts(raw, flagName string) []int {
	vals, err := csvInts(raw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid value for %s: %v\n", flagName, err)
		os.Exit(1)
	}
	return vals
}
