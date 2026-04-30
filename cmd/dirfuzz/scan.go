package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"dirfuzz/pkg/engine"
	"dirfuzz/pkg/tui"

	tea "github.com/charmbracelet/bubbletea"
)

// tuiResultBufSize mirrors engine.ResultsChannelSize so the fanout goroutine
// is never the bottleneck between the engine and the TUI.
const tuiResultBufSize = engine.ResultsChannelSize

// run builds the engine from cfg, starts a scan, and hands off to either the
// Bubble Tea TUI (default) or a plain stdout loop (--no-tui).
func run(cfg cliConfig) error {
	// ── 1. Engine ─────────────────────────────────────────────────────────────
	eng := engine.NewEngine(cfg.Threads, engine.DefaultBloomFilterSize, engine.DefaultBloomFilterFP)

	// ── 2. Match / filter codes ───────────────────────────────────────────────
	matchCodes := mustCSVInts(cfg.MatchCodes, "-mc")
	filterSizes := mustCSVInts(cfg.FilterSizes, "-fs")
	eng.ConfigureFilters(matchCodes, filterSizes)

	// ── 3. Extensions ─────────────────────────────────────────────────────────
	for _, ext := range splitTrimmed(cfg.Extensions) {
		eng.AddExtension(strings.TrimPrefix(ext, "."))
	}

	// ── 4. HTTP settings ──────────────────────────────────────────────────────
	if cfg.UserAgent != "" {
		eng.UpdateUserAgent(cfg.UserAgent)
	}
	if cfg.Cookie != "" {
		eng.AddHeader("Cookie", cfg.Cookie)
	}
	for _, h := range cfg.Headers {
		if parts := strings.SplitN(h, ":", 2); len(parts) == 2 {
			eng.AddHeader(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}
	if cfg.Delay > 0 {
		eng.SetDelay(cfg.Delay)
	}
	if cfg.RPS > 0 {
		eng.SetRPS(cfg.RPS)
	}
	if cfg.Follow {
		eng.SetFollowRedirects(true)
	}

	eng.UpdateConfig(func(c *engine.Config) {
		c.Timeout = cfg.Timeout
		c.Insecure = cfg.Insecure
		c.MaxRedirects = cfg.MaxRedirects
		c.RequestBody = cfg.Body
		c.SaveRaw = cfg.SaveRaw
		c.Recursive = cfg.Recursive
		c.MaxDepth = cfg.MaxDepth
		c.SmartAPI = cfg.SmartAPI
		c.Mutate = cfg.Mutate
		c.FilterWords = cfg.FilterWords
		c.FilterLines = cfg.FilterLines
		c.MatchWords = cfg.MatchWords
		c.MatchLines = cfg.MatchLines
		c.FilterRTMin = cfg.RTMin
		c.FilterRTMax = cfg.RTMax
		c.ProxyOut = cfg.ProxyOut
		c.AutoFilterThreshold = cfg.AutoFilterThreshold
		c.MaxRetries = cfg.MaxRetries
		if cfg.OutputFile != "" {
			c.OutputFile = cfg.OutputFile
			c.OutputFormat = cfg.OutputFormat
		}
		for _, m := range splitTrimmed(cfg.Methods) {
			c.Methods = append(c.Methods, strings.ToUpper(m))
		}
	})

	// ── 5. Regex filters ──────────────────────────────────────────────────────
	if cfg.MatchRegex != "" {
		if err := eng.SetMatchRegex(cfg.MatchRegex); err != nil {
			return fmt.Errorf("invalid -mr regex: %w", err)
		}
	}
	if cfg.FilterRegex != "" {
		if err := eng.SetFilterRegex(cfg.FilterRegex); err != nil {
			return fmt.Errorf("invalid -fr regex: %w", err)
		}
	}

	// ── 6. Lua plugins ────────────────────────────────────────────────────────
	if cfg.PluginMatch != "" {
		pm, err := engine.NewPluginMatcher(cfg.PluginMatch)
		if err != nil {
			return fmt.Errorf("plugin-match: %w", err)
		}
		defer pm.Close()
		eng.SetMatchPlugin(pm)
	}
	if cfg.PluginMutate != "" {
		pm, err := engine.NewPluginMutator(cfg.PluginMutate)
		if err != nil {
			return fmt.Errorf("plugin-mutate: %w", err)
		}
		defer pm.Close()
		eng.SetMutatePlugin(pm)
	}

	// ── 7. Proxy rotation ─────────────────────────────────────────────────────
	if cfg.ProxyFile != "" {
		if err := eng.LoadProxies(cfg.ProxyFile); err != nil {
			return fmt.Errorf("loading proxy list: %w", err)
		}
	}

	// ── 8. Eagle mode ─────────────────────────────────────────────────────────
	if cfg.EagleFile != "" {
		if err := eng.LoadPreviousScan(cfg.EagleFile); err != nil {
			return fmt.Errorf("loading eagle baseline: %w", err)
		}
	}

	// ── 9. Target ─────────────────────────────────────────────────────────────
	if err := eng.SetTarget(cfg.Target); err != nil {
		return fmt.Errorf("invalid target: %w", err)
	}

	// ── 10. Auto-calibration ──────────────────────────────────────────────────
	if cfg.Calibrate {
		fmt.Fprintln(os.Stderr, "[*] Auto-calibrating…")
		if err := eng.AutoCalibrate(); err != nil {
			fmt.Fprintf(os.Stderr, "[!] Calibration warning: %v\n", err)
		}
	}

	// ── 11. Resume ────────────────────────────────────────────────────────────
	wordlistPath := cfg.Wordlist
	var startLine int64

	if cfg.Resume {
		wl, line, err := eng.LoadResumeState(cfg.ResumeFile)
		if err != nil {
			return fmt.Errorf("loading resume state from %s: %w", cfg.ResumeFile, err)
		}
		wordlistPath = wl
		startLine = line
		fmt.Fprintf(os.Stderr, "[*] Resuming %s from line %d\n", wordlistPath, startLine)
	}

	eng.Config.Lock()
	eng.Config.WordlistPath = wordlistPath
	eng.Config.Unlock()
	eng.RefreshConfigSnapshot()

	if cfg.DryRun {
		est, err := eng.EstimateWordlist(wordlistPath, startLine)
		if err != nil {
			return fmt.Errorf("estimating scan: %w", err)
		}
		printDryRunEstimate(cfg, est)
		return nil
	}

	// ── 12. Output file ───────────────────────────────────────────────────────
	var (
		outFile   *os.File
		csvW      *csv.Writer
	)

	if cfg.OutputFile != "" {
		f, err := os.Create(cfg.OutputFile)
		if err != nil {
			return fmt.Errorf("creating output file %s: %w", cfg.OutputFile, err)
		}
		defer func() {
			if csvW != nil {
				csvW.Flush()
			}
			f.Close()
		}()
		outFile = f

		if cfg.OutputFormat == "csv" {
			csvW = csv.NewWriter(outFile)
			engine.WriteCSVHeader(csvW)
		}
	}

	// writeResult writes one result to the output file. It is always called
	// from the fanout goroutine (never dropped) and never from the TUI path.
	var reportResults []engine.Result
	var reportMu sync.Mutex
	writeResult := func(r engine.Result) {
		if cfg.ReportFile != "" && !r.IsAutoFilter {
			reportMu.Lock()
			reportResults = append(reportResults, r)
			reportMu.Unlock()
		}
		if outFile == nil {
			return
		}
		switch cfg.OutputFormat {
		case "csv":
			_ = csvW.Write(r.ToCSV())
		case "url":
			u := r.URL
			if u == "" {
				u = r.Path
			}
			fmt.Fprintln(outFile, u)
		default: // jsonl
			b, _ := json.Marshal(r)
			_, _ = outFile.Write(b)
			_, _ = outFile.Write([]byte("\n"))
		}
	}

	// ── 13. Start engine ──────────────────────────────────────────────────────
	eng.Start()
	eng.KickoffScanner(wordlistPath, startLine)

	// ── 14. Display mode ──────────────────────────────────────────────────────
	if cfg.NoTUI {
		if err := runPlain(eng, cfg, writeResult); err != nil {
			return err
		}
		reportMu.Lock()
		defer reportMu.Unlock()
		return writeReportIfRequested(cfg, reportResults)
	}
	if err := runTUI(eng, cfg, writeResult); err != nil {
		return err
	}
	reportMu.Lock()
	defer reportMu.Unlock()
	return writeReportIfRequested(cfg, reportResults)
}

// ── Plain / no-TUI mode ───────────────────────────────────────────────────────

func runPlain(eng *engine.Engine, cfg cliConfig, writeResult func(engine.Result)) error {
	go func() {
		eng.Wait()
		eng.Shutdown()
	}()

	for res := range eng.Results {
		if res.IsAutoFilter {
			if cfg.Verbose {
				msg := ""
				if res.Headers != nil {
					msg = res.Headers["Msg"]
				}
				if msg != "" {
					fmt.Fprintf(os.Stderr, "[AF] %s: %s\n", res.Path, msg)
				}
			}
			continue
		}
		if res.IsEagleAlert {
			line := fmt.Sprintf("[EAGLE] %s  %d → %d", res.Path, res.OldStatusCode, res.StatusCode)
			fmt.Println(line)
		} else {
			fmt.Println(res.String())
		}
		writeResult(res)
	}

	dropped := atomic.LoadInt64(&eng.TUIDropped)
	if dropped > 0 {
		fmt.Fprintf(os.Stderr,
			"[!] %d result(s) were dropped from display (TUI backpressure — file output unaffected)\n",
			dropped,
		)
	}

	return nil
}

// ── TUI mode (default) ────────────────────────────────────────────────────────

// runTUI launches the Bubble Tea TUI. It creates a fanout goroutine between
// the engine's Results channel and the TUI so that:
//
//   - File output always receives every result (never dropped).
//   - The TUI channel is fed with a non-blocking send; if full, the result is
//     counted in eng.TUIDropped and shown in the TUI header as ⚠ TUI-dropped:N.
func runTUI(eng *engine.Engine, cfg cliConfig, writeResult func(engine.Result)) error {
	tuiCh := make(chan engine.Result, tuiResultBufSize)

	// Fanout goroutine.
	go func() {
		defer close(tuiCh)

		go func() {
			eng.Wait()
			eng.Shutdown()
		}()

		for res := range eng.Results {
			// File write is guaranteed — happens before the non-blocking TUI send.
			if !res.IsAutoFilter {
				writeResult(res)
			}

			// TUI receive is best-effort.
			select {
			case tuiCh <- res:
			default:
				atomic.AddInt64(&eng.TUIDropped, 1)
			}
		}
	}()

	model := tui.NewModel(eng, tuiCh)
	p := tea.NewProgram(model, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		return fmt.Errorf("TUI error: %w", err)
	}

	// Post-scan warning printed after the terminal is restored.
	dropped := atomic.LoadInt64(&eng.TUIDropped)
	if dropped > 0 {
		fmt.Fprintf(os.Stderr,
			"\n[!] Warning: %d result(s) were dropped from the TUI display due to backpressure.\n"+
				"    All hits were written to the output file (if -o was specified).\n",
			dropped,
		)
	}

	return nil
}
