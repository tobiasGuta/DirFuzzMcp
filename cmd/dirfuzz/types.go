package main

import (
	"strings"
	"time"
)

// multiFlag lets the same flag be specified multiple times.
// e.g. -H "Authorization: Bearer tok" -H "X-Custom: val"
type multiFlag []string

func (f *multiFlag) String() string        { return strings.Join(*f, ", ") }
func (f *multiFlag) Set(s string) error    { *f = append(*f, s); return nil }

// cliConfig holds all values parsed from command-line flags.
// It is built once in parseFlags() and passed to run().
type cliConfig struct {
	// ── Required ─────────────────────────────────────────────────────────────
	Target   string
	Wordlist string

	// ── Workers / throttle ────────────────────────────────────────────────────
	Threads int
	Delay   time.Duration
	RPS     int

	// ── HTTP behaviour ───────────────────────────────────────────────────────
	UserAgent    string
	Headers      []string // raw "Key: Value" strings from -H
	Cookie       string   // shorthand for -H "Cookie: …"
	Methods      string   // comma-separated HTTP verbs
	Body         string   // request body for POST / PUT
	Follow       bool
	MaxRedirects int
	Timeout      time.Duration
	Insecure     bool

	// ── Matching / filtering ─────────────────────────────────────────────────
	MatchCodes  string // comma-separated, e.g. "200,301,403"
	FilterSizes string // comma-separated response byte sizes to drop
	Extensions  string // comma-separated extensions to append
	MatchRegex  string
	FilterRegex string
	FilterWords int
	FilterLines int
	MatchWords  int
	MatchLines  int
	RTMin       time.Duration
	RTMax       time.Duration

	// ── Output ───────────────────────────────────────────────────────────────
	OutputFormat string // jsonl | csv | url
	OutputFile   string
	SaveRaw      bool

	// ── Scan modes ───────────────────────────────────────────────────────────
	Recursive           bool
	MaxDepth            int
	Mutate              bool
	SmartAPI            bool
	AutoFilterThreshold int
	MaxRetries          int

	// ── Eagle mode (differential scan) ───────────────────────────────────────
	EagleFile string // path to previous JSONL baseline

	// ── Resume ───────────────────────────────────────────────────────────────
	Resume     bool
	ResumeFile string

	// ── Auto-calibration ─────────────────────────────────────────────────────
	Calibrate bool

	// ── Proxy ────────────────────────────────────────────────────────────────
	ProxyFile string // path to proxy list (SOCKS5 / HTTP, one per line)
	ProxyOut  string // forward every hit to this proxy (Burp / ZAP)

	// ── Lua plugins ──────────────────────────────────────────────────────────
	PluginMatch  string // Lua script: match(r) → bool
	PluginMutate string // Lua script: mutate(word) → []string

	// ── Display ──────────────────────────────────────────────────────────────
	NoTUI   bool // disable TUI, print to stdout
	Verbose bool // print every request, not only hits
}
