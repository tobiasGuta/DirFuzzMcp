package main

import (
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

type scanProfile struct {
	Target              string        `yaml:"target" json:"target"`
	Wordlist            string        `yaml:"wordlist" json:"wordlist"`
	Threads             int           `yaml:"threads" json:"threads"`
	Delay               time.Duration `yaml:"delay" json:"delay"`
	RPS                 int           `yaml:"rps" json:"rps"`
	UserAgent           string        `yaml:"user_agent" json:"user_agent"`
	Headers             []string      `yaml:"headers" json:"headers"`
	Cookie              string        `yaml:"cookie" json:"cookie"`
	Methods             string        `yaml:"methods" json:"methods"`
	Body                string        `yaml:"body" json:"body"`
	Follow              bool          `yaml:"follow" json:"follow"`
	MaxRedirects        int           `yaml:"max_redirects" json:"max_redirects"`
	Timeout             time.Duration `yaml:"timeout" json:"timeout"`
	Insecure            bool          `yaml:"insecure" json:"insecure"`
	MatchCodes          string        `yaml:"match_codes" json:"match_codes"`
	FilterSizes         string        `yaml:"filter_sizes" json:"filter_sizes"`
	Extensions          string        `yaml:"extensions" json:"extensions"`
	MatchRegex          string        `yaml:"match_regex" json:"match_regex"`
	FilterRegex         string        `yaml:"filter_regex" json:"filter_regex"`
	FilterWords         int           `yaml:"filter_words" json:"filter_words"`
	FilterLines         int           `yaml:"filter_lines" json:"filter_lines"`
	MatchWords          int           `yaml:"match_words" json:"match_words"`
	MatchLines          int           `yaml:"match_lines" json:"match_lines"`
	RTMin               time.Duration `yaml:"rt_min" json:"rt_min"`
	RTMax               time.Duration `yaml:"rt_max" json:"rt_max"`
	OutputFormat        string        `yaml:"output_format" json:"output_format"`
	OutputFile          string        `yaml:"output_file" json:"output_file"`
	ReportFile          string        `yaml:"report_file" json:"report_file"`
	ReportFormat        string        `yaml:"report_format" json:"report_format"`
	SaveRaw             bool          `yaml:"save_raw" json:"save_raw"`
	Recursive           bool          `yaml:"recursive" json:"recursive"`
	MaxDepth            int           `yaml:"max_depth" json:"max_depth"`
	Mutate              bool          `yaml:"mutate" json:"mutate"`
	SmartAPI            bool          `yaml:"smart_api" json:"smart_api"`
	AutoFilterThreshold int           `yaml:"auto_filter_threshold" json:"auto_filter_threshold"`
	MaxRetries          int           `yaml:"max_retries" json:"max_retries"`
	DryRun              bool          `yaml:"dry_run" json:"dry_run"`
	EagleFile           string        `yaml:"eagle_file" json:"eagle_file"`
	Resume              bool          `yaml:"resume" json:"resume"`
	ResumeFile          string        `yaml:"resume_file" json:"resume_file"`
	Calibrate           bool          `yaml:"calibrate" json:"calibrate"`
	ProxyFile           string        `yaml:"proxy_file" json:"proxy_file"`
	ProxyOut            string        `yaml:"proxy_out" json:"proxy_out"`
	PluginMatch         string        `yaml:"plugin_match" json:"plugin_match"`
	PluginMutate        string        `yaml:"plugin_mutate" json:"plugin_mutate"`
	NoTUI               bool          `yaml:"no_tui" json:"no_tui"`
	Verbose             bool          `yaml:"verbose" json:"verbose"`
}

func applyProfile(cfg *cliConfig, set map[string]bool) error {
	data, err := os.ReadFile(cfg.Profile)
	if err != nil {
		return err
	}
	var p scanProfile
	if err := yaml.Unmarshal(data, &p); err != nil {
		return err
	}

	if !set["u"] && p.Target != "" { cfg.Target = p.Target }
	if !set["w"] && p.Wordlist != "" { cfg.Wordlist = p.Wordlist }
	if !set["t"] && p.Threads > 0 { cfg.Threads = p.Threads }
	if !set["delay"] && p.Delay > 0 { cfg.Delay = p.Delay }
	if !set["rps"] && p.RPS > 0 { cfg.RPS = p.RPS }
	if !set["ua"] && p.UserAgent != "" { cfg.UserAgent = p.UserAgent }
	if !set["H"] && len(p.Headers) > 0 { cfg.Headers = p.Headers }
	if !set["b"] && p.Cookie != "" { cfg.Cookie = p.Cookie }
	if !set["m"] && p.Methods != "" { cfg.Methods = p.Methods }
	if !set["d"] && p.Body != "" { cfg.Body = p.Body }
	if !set["follow"] && p.Follow { cfg.Follow = true }
	if !set["max-redirects"] && p.MaxRedirects > 0 { cfg.MaxRedirects = p.MaxRedirects }
	if !set["timeout"] && p.Timeout > 0 { cfg.Timeout = p.Timeout }
	if !set["k"] && p.Insecure { cfg.Insecure = true }
	if !set["mc"] && p.MatchCodes != "" { cfg.MatchCodes = p.MatchCodes }
	if !set["fs"] && p.FilterSizes != "" { cfg.FilterSizes = p.FilterSizes }
	if !set["e"] && p.Extensions != "" { cfg.Extensions = p.Extensions }
	if !set["mr"] && p.MatchRegex != "" { cfg.MatchRegex = p.MatchRegex }
	if !set["fr"] && p.FilterRegex != "" { cfg.FilterRegex = p.FilterRegex }
	if !set["fw"] && p.FilterWords != 0 { cfg.FilterWords = p.FilterWords }
	if !set["fl"] && p.FilterLines != 0 { cfg.FilterLines = p.FilterLines }
	if !set["mw"] && p.MatchWords != 0 { cfg.MatchWords = p.MatchWords }
	if !set["ml"] && p.MatchLines != 0 { cfg.MatchLines = p.MatchLines }
	if !set["rt-min"] && p.RTMin > 0 { cfg.RTMin = p.RTMin }
	if !set["rt-max"] && p.RTMax > 0 { cfg.RTMax = p.RTMax }
	if !set["of"] && p.OutputFormat != "" { cfg.OutputFormat = p.OutputFormat }
	if !set["o"] && p.OutputFile != "" { cfg.OutputFile = p.OutputFile }
	if !set["report"] && p.ReportFile != "" { cfg.ReportFile = p.ReportFile }
	if !set["report-format"] && p.ReportFormat != "" { cfg.ReportFormat = p.ReportFormat }
	if !set["save-raw"] && p.SaveRaw { cfg.SaveRaw = true }
	if !set["r"] && p.Recursive { cfg.Recursive = true }
	if !set["depth"] && p.MaxDepth > 0 { cfg.MaxDepth = p.MaxDepth }
	if !set["mutate"] && p.Mutate { cfg.Mutate = true }
	if !set["smart-api"] && p.SmartAPI { cfg.SmartAPI = true }
	if !set["af"] && p.AutoFilterThreshold > 0 { cfg.AutoFilterThreshold = p.AutoFilterThreshold }
	if !set["retry"] && p.MaxRetries > 0 { cfg.MaxRetries = p.MaxRetries }
	if !set["dry-run"] && p.DryRun { cfg.DryRun = true }
	if !set["eagle"] && p.EagleFile != "" { cfg.EagleFile = p.EagleFile }
	if !set["resume"] && p.Resume { cfg.Resume = true }
	if !set["resume-file"] && p.ResumeFile != "" { cfg.ResumeFile = p.ResumeFile }
	if !set["calibrate"] && p.Calibrate { cfg.Calibrate = true }
	if !set["proxy"] && p.ProxyFile != "" { cfg.ProxyFile = p.ProxyFile }
	if !set["proxy-out"] && p.ProxyOut != "" { cfg.ProxyOut = p.ProxyOut }
	if !set["plugin-match"] && p.PluginMatch != "" { cfg.PluginMatch = p.PluginMatch }
	if !set["plugin-mutate"] && p.PluginMutate != "" { cfg.PluginMutate = p.PluginMutate }
	if !set["no-tui"] && p.NoTUI { cfg.NoTUI = true }
	if !set["v"] && p.Verbose { cfg.Verbose = true }
	return nil
}

func inferReportFormat(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".html", ".htm":
		return "html"
	default:
		return "markdown"
	}
}
