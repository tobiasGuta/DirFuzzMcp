package main

import (
	"fmt"
	"html"
	"os"
	"sort"
	"strings"
	"time"

	"dirfuzz/pkg/engine"
)

func printDryRunEstimate(cfg cliConfig, est engine.Estimate) {
	fmt.Printf("DirFuzz dry run for: %s\n", cfg.Target)
	fmt.Printf("Wordlist: %s\n", cfg.Wordlist)
	fmt.Printf("Base words: %d\n", est.BaseWords)
	fmt.Printf("Extensions: %d\n", est.Extensions)
	fmt.Printf("Methods: %d\n", est.Methods)
	fmt.Printf("Estimated requests: %d\n", est.EstimatedJobs)
	if est.Recursive {
		suffix := ""
		if est.RecursiveCapped {
			suffix = " (capped estimate)"
		}
		fmt.Printf("Recursive worst-case through depth %d: %d%s\n", est.MaxDepth, est.RecursiveWorst, suffix)
	}
}

func writeReportIfRequested(cfg cliConfig, results []engine.Result) error {
	if cfg.ReportFile == "" {
		return nil
	}
	var body string
	switch strings.ToLower(cfg.ReportFormat) {
	case "html":
		body = renderHTMLReport(cfg, results)
	case "", "markdown", "md":
		body = renderMarkdownReport(cfg, results)
	default:
		return fmt.Errorf("unsupported report format %q", cfg.ReportFormat)
	}
	return os.WriteFile(cfg.ReportFile, []byte(body), 0o644)
}

func renderMarkdownReport(cfg cliConfig, results []engine.Result) string {
	sortResults(results)
	var sb strings.Builder
	fmt.Fprintf(&sb, "# DirFuzz Report\n\n")
	fmt.Fprintf(&sb, "- Target: `%s`\n", cfg.Target)
	fmt.Fprintf(&sb, "- Generated: `%s`\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(&sb, "- Findings: `%d`\n\n", len(results))
	if len(results) == 0 {
		sb.WriteString("No findings.\n")
		return sb.String()
	}
	sb.WriteString("| Status | Method | Size | URL |\n")
	sb.WriteString("| --- | --- | ---: | --- |\n")
	for _, r := range results {
		method := r.Method
		if method == "" {
			method = "GET"
		}
		u := r.URL
		if u == "" {
			u = r.Path
		}
		fmt.Fprintf(&sb, "| %d | %s | %d | `%s` |\n", r.StatusCode, method, r.Size, u)
	}
	return sb.String()
}

func renderHTMLReport(cfg cliConfig, results []engine.Result) string {
	sortResults(results)
	var sb strings.Builder
	sb.WriteString("<!doctype html><html><head><meta charset=\"utf-8\"><title>DirFuzz Report</title>")
	sb.WriteString("<style>body{font-family:system-ui,sans-serif;margin:2rem;background:#f7f3ea;color:#241f1a}table{border-collapse:collapse;width:100%;background:white}td,th{border:1px solid #ddd;padding:.5rem;text-align:left}th{background:#1f3d36;color:white}.pill{display:inline-block;padding:.15rem .45rem;border-radius:999px;background:#e8b44b;color:#241f1a}</style>")
	sb.WriteString("</head><body>")
	fmt.Fprintf(&sb, "<h1>DirFuzz Report</h1><p><strong>Target:</strong> <code>%s</code></p>", html.EscapeString(cfg.Target))
	fmt.Fprintf(&sb, "<p><strong>Generated:</strong> <code>%s</code> <span class=\"pill\">%d findings</span></p>", time.Now().Format(time.RFC3339), len(results))
	if len(results) == 0 {
		sb.WriteString("<p>No findings.</p></body></html>")
		return sb.String()
	}
	sb.WriteString("<table><thead><tr><th>Status</th><th>Method</th><th>Size</th><th>URL</th></tr></thead><tbody>")
	for _, r := range results {
		method := r.Method
		if method == "" {
			method = "GET"
		}
		u := r.URL
		if u == "" {
			u = r.Path
		}
		fmt.Fprintf(&sb, "<tr><td>%d</td><td>%s</td><td>%d</td><td><code>%s</code></td></tr>",
			r.StatusCode, html.EscapeString(method), r.Size, html.EscapeString(u))
	}
	sb.WriteString("</tbody></table></body></html>")
	return sb.String()
}

func sortResults(results []engine.Result) {
	sort.SliceStable(results, func(i, j int) bool {
		if results[i].StatusCode != results[j].StatusCode {
			return results[i].StatusCode < results[j].StatusCode
		}
		return results[i].Path < results[j].Path
	})
}
