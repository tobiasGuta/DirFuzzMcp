package engine

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"dirfuzz/pkg/httpclient"

	"github.com/bits-and-blooms/bloom/v3"
	"golang.org/x/time/rate"
)

// ─── Config types ─────────────────────────────────────────────────────────────

// SizeRange represents an inclusive min–max byte-size range used for filtering.
type SizeRange struct {
	Min int
	Max int
}

// Config holds all runtime configuration for the engine.
type Config struct {
	sync.RWMutex
	UserAgent           string
	Headers             map[string]string
	MatchCodes          map[int]bool
	FilterSizes         map[int]bool
	FilterSizeRanges    []SizeRange // NEW: filter responses whose size falls in any of these ranges
	MatchContentTypes   []string    // NEW: only surface responses whose Content-Type contains one of these strings
	FilterContentTypes  []string    // NEW: discard responses whose Content-Type contains any of these strings
	MatchRegex          string
	FilterRegex         string
	Extensions          []string
	Methods             []string
	SmartAPI            bool
	Mutate              bool
	Recursive           bool
	MaxDepth            int
	IsPaused            bool
	Delay               time.Duration
	MaxWorkers          int
	FollowRedirects     bool
	MaxRedirects        int
	AllowPrivateTargets bool
	RequestBody         string
	FilterWords         int
	FilterLines         int
	MatchWords          int
	MatchLines          int
	OutputFormat        string
	FilterRTMin         time.Duration
	FilterRTMax         time.Duration
	ProxyOut            string
	WordlistPath        string
	OutputFile          string
	Timeout             time.Duration
	Insecure            bool
	AutoFilterThreshold int
	MaxRetries          int
	SaveRaw             bool // NEW: include raw request/response bytes in Result
}

// configSnapshot is an immutable view of the frequently-read configuration
// fields used by workers. Workers load a pointer to this snapshot once per
// job to avoid repeatedly allocating and copying maps on hot paths.
type configSnapshot struct {
	MaxWorkers         int
	IsPaused           bool
	UserAgent          string
	Headers            map[string]string
	MatchCodes         map[int]bool
	FilterSizes        map[int]bool
	FilterSizeRanges   []SizeRange
	MatchContentTypes  []string
	FilterContentTypes []string
	FollowRedirects    bool
	MaxRedirects       int
	RequestBody        string
	FilterWords        int
	FilterLines        int
	MatchWords         int
	MatchLines         int
	FilterRTMin        time.Duration
	FilterRTMax        time.Duration
	ProxyOut           string
	SaveRaw            bool
	Methods            []string
	SmartAPI           bool
	Extensions         []string
	// HeadersTemplate is the pre-built header block (with any {PAYLOAD}
	// placeholders intact) that workers can quickly clone and substitute
	// the payload into without reconstructing the header map each job.
	HeadersTemplate string
}

// ─── Job & Result ─────────────────────────────────────────────────────────────

// Job represents a single scan task.
type Job struct {
	Path   string
	Depth  int
	Method string
	RunID  int64
}

// Result holds the details of a successful fuzzing hit.
type Result struct {
	Path             string            `json:"path"`
	Method           string            `json:"method,omitempty"`
	StatusCode       int               `json:"status"`
	Forbidden403Type string            `json:"forbidden_403_type,omitempty"`
	Size             int               `json:"length"`
	Words            int               `json:"words,omitempty"`
	Lines            int               `json:"lines,omitempty"`
	ContentType      string            `json:"content_type,omitempty"`
	Duration         time.Duration     `json:"duration,omitempty"`
	Redirect         string            `json:"redirect,omitempty"`
	Headers          map[string]string `json:"headers,omitempty"`
	IsEagleAlert     bool              `json:"eagle_alert,omitempty"`
	OldStatusCode    int               `json:"old_status,omitempty"`
	IsAutoFilter     bool              `json:"auto_filter,omitempty"`
	URL              string            `json:"url,omitempty"`
	Request          string            `json:"request,omitempty"`  // only populated when SaveRaw=true
	Response         string            `json:"response,omitempty"` // only populated when SaveRaw=true
}

// replayTask carries everything needed to replay a hit through an outbound proxy.
type replayTask struct {
	proxyAddr   string
	fullURL     string
	method      string
	ua          string
	headers     map[string]string
	requestBody string
	payload     string
}

// ─── Engine ───────────────────────────────────────────────────────────────────

// Engine represents the core memory-queue system for the brute-forcer.
type Engine struct {
	RunID         int64
	jobs          chan Job
	wg            sync.WaitGroup
	filter        *bloom.BloomFilter
	filterLock    sync.Mutex
	numWorkers    int
	targetLock    sync.RWMutex
	baseURL       string
	host          string
	Config        *Config
	scannerCtx    context.Context
	scannerCancel context.CancelFunc
	scannerWg     sync.WaitGroup
	activeJobs    sync.WaitGroup
	Results       chan Result

	// Eagle Mode State
	PreviousState map[string]int

	// Proxy Rotation
	proxies     []string
	proxyIndex  uint64
	proxyDialer bool

	// Rate Limiters (Per-Host)
	limiters     map[string]*rate.Limiter
	limitersLock sync.RWMutex
	currentLimit rate.Limit
	currentBurst int

	// Progress tracking
	TotalLines     int64
	ProcessedLines int64

	// Worker management
	workerLock sync.Mutex

	// Telemetry (Atomic counters)
	Count200     int64
	Count403     int64
	Count404     int64
	Count429     int64
	Count500     int64
	CountConnErr int64

	// RPS calculation
	// `lastProcessed` and `lastTick` are accessed concurrently; use
	// atomic operations on the int64 fields to avoid data races.
	lastProcessed int64 // atomic: last processed count snapshot
	lastTick      int64 // atomic: unixNano timestamp of last tick
	CurrentRPS    int64

	// Smart Filter State
	fpMutex           sync.RWMutex
	fpCounts          map[string]int
	manualFilterSizes map[int]bool
	autoFilterSizes   map[int]bool

	// Auto-throttle state
	autoThrottle     bool
	throttleRestore  int32 // atomic: stores previous worker count for restore
	alreadyThrottled int32 // atomic: prevents repeated firing

	// Per-host HEAD rejection cache (replaces the single global headRejected flag)
	headRejectedHosts sync.Map // map[string]*int32

	// TUIDropped counts results the TUI channel dropped due to backpressure.
	TUIDropped int64

	// Resume support
	ResumeFile string

	// Compiled regexes (cached)
	matchRe  *regexp.Regexp
	filterRe *regexp.Regexp

	// Lua plugins
	matchPlugin  *PluginMatcher
	mutatePlugin *PluginMutator

	// Scope domain for recursion
	scopeDomain string

	// Bounded concurrency for recursive wordlist scanners
	recursiveSem chan struct{}

	// Bounded outbound proxy replay queue + workers
	replayCh chan replayTask
	// Cached immutable config snapshot read by workers.
	configSnap atomic.Pointer[configSnapshot]
	// Cached outbound HTTP clients for proxy replay to avoid creating a new
	// Transport/Client per replay task (reduces GC pressure and enables
	// connection/TLS session reuse).
	replayClients sync.Map // map[string]*http.Client
	// Ensure Shutdown only runs once to avoid double-closing channels.
	shutdownOnce sync.Once
}

// ─── Constant classification strings ─────────────────────────────────────────

const (
	Forbidden403TypeCFWAFBlock = "CF_WAF_BLOCK"
	Forbidden403TypeCFAdmin403 = "CF_ADMIN_403"
	Forbidden403TypeNginx403   = "NGINX_403"
	Forbidden403TypeGeneric403 = "GENERIC_403"
)

// ─── Result helpers ───────────────────────────────────────────────────────────

// String returns a string representation of the result for CLI output.
func (r Result) String() string {
	extras := ""
	if r.Redirect != "" {
		extras += fmt.Sprintf(" -> %s", r.Redirect)
	}
	if val, ok := r.Headers["Server"]; ok {
		extras += fmt.Sprintf(" [Server: %s]", val)
	}
	if val, ok := r.Headers["X-Powered-By"]; ok {
		extras += fmt.Sprintf(" [X-Powered-By: %s]", val)
	}
	if r.Forbidden403Type != "" {
		extras += fmt.Sprintf(" [%s]", r.Forbidden403Type)
	}
	if r.ContentType != "" {
		extras += fmt.Sprintf(" [%s]", r.ContentType)
	}
	if r.Duration > 0 {
		extras += fmt.Sprintf(" [%s]", r.Duration.Round(time.Millisecond))
	}
	methodStr := r.Method
	if methodStr == "" {
		methodStr = "HEAD/GET"
	}
	return fmt.Sprintf("[+] [%s] HIT: %s (Status: %d, Size: %d, Words: %d, Lines: %d)%s",
		methodStr, r.Path, r.StatusCode, r.Size, r.Words, r.Lines, extras)
}

// ToCSV returns a CSV-formatted line for the result.
func (r Result) ToCSV() []string {
	methodStr := r.Method
	if methodStr == "" {
		methodStr = "GET"
	}
	return []string{
		methodStr,
		r.URL,
		r.Path,
		strconv.Itoa(r.StatusCode),
		strconv.Itoa(r.Size),
		strconv.Itoa(r.Words),
		strconv.Itoa(r.Lines),
		r.ContentType,
		r.Redirect,
		r.Duration.Round(time.Millisecond).String(),
	}
}

// Classify403 identifies known types of 403 responses based on body/header signals.
func Classify403(body []byte, headers string) string {
	// Only scan the first N bytes for known WAF signatures to avoid
	// allocating a lowercase copy of very large bodies.
	const maxScan = 8 * 1024
	limit := maxScan
	if len(body) < limit {
		limit = len(body)
	}
	lowerBody := bytes.ToLower(body[:limit])
	hasCFWAFBlock := bytes.Contains(lowerBody, []byte("attention required! | cloudflare")) ||
		bytes.Contains(lowerBody, []byte("sorry, you have been blocked")) ||
		bytes.Contains(lowerBody, []byte("cf-error-details"))
	if hasCFWAFBlock {
		return Forbidden403TypeCFWAFBlock
	}

	hasCFAdmin403 := bytes.Contains(lowerBody, []byte("request forbidden by administrative rules"))
	hasNginx403 := bytes.Contains(lowerBody, []byte("<center>nginx</center>"))

	normalizedHeaders := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(headers, "\r\n", "\n"), "\r", "\n"))
	headerLines := strings.Split(normalizedHeaders, "\n")
	hasCfRay := false
	hasCfCacheStatus := false
	for _, line := range headerLines {
		idx := strings.Index(line, ":")
		if idx == -1 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		switch key {
		case "cf-ray":
			hasCfRay = true
		case "cf-cache-status":
			hasCfCacheStatus = true
		}
	}

	if hasCFAdmin403 && (hasCfRay || hasCfCacheStatus) {
		return Forbidden403TypeCFAdmin403
	}
	if hasNginx403 && !hasCfRay {
		return Forbidden403TypeNginx403
	}
	return Forbidden403TypeGeneric403
}

// WriteCSVHeader writes a CSV header to the given writer.
func WriteCSVHeader(w *csv.Writer) {
	w.Write([]string{"Method", "URL", "Path", "Status", "Size", "Words", "Lines", "ContentType", "Redirect", "Duration"})
}

// ─── Engine constructor ───────────────────────────────────────────────────────

// NewEngine initialises a new Engine with a worker pool and a Bloom filter.
func NewEngine(numWorkers int, expectedItems uint, falsePositiveRate float64) *Engine {
	burst := numWorkers
	if burst < MinRateLimitBurst {
		burst = MinRateLimitBurst
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Create bounded replay queue and start workers.
	replayCh := make(chan replayTask, ReplayQueueSize)

	e := &Engine{
		jobs:         make(chan Job, DefaultJobQueueSize),
		filter:       bloom.NewWithEstimates(expectedItems, falsePositiveRate),
		numWorkers:   numWorkers,
		limiters:     make(map[string]*rate.Limiter),
		currentLimit: rate.Inf,
		currentBurst: burst,
		Config: &Config{
			UserAgent:           "DirFuzz/2.0",
			Headers:             make(map[string]string),
			MatchCodes:          make(map[int]bool),
			FilterSizes:         make(map[int]bool),
			IsPaused:            false,
			Delay:               0,
			MaxWorkers:          numWorkers,
			MaxRedirects:        DefaultMaxRedirects,
			FilterWords:         -1,
			FilterLines:         -1,
			MatchWords:          -1,
			MatchLines:          -1,
			OutputFormat:        DefaultOutputFormat,
			Timeout:             DefaultHTTPTimeout,
			Insecure:            false,
			AllowPrivateTargets: false,
		},
		scannerCtx:        ctx,
		scannerCancel:     cancel,
		Results:           make(chan Result, ResultsChannelSize),
		fpCounts:          make(map[string]int),
		manualFilterSizes: make(map[int]bool),
		autoFilterSizes:   make(map[int]bool),
		lastTick:          time.Now().UnixNano(),
		autoThrottle:      true,
		recursiveSem:      make(chan struct{}, MaxConcurrentRecursions),
		replayCh:          replayCh,
	}

	// Launch bounded replay workers.
	for i := 0; i < ReplayWorkers; i++ {
		go func() {
			for task := range replayCh {
				e.execReplay(task)
			}
		}()
	}

	// Initialize worker-facing immutable config snapshot.
	e.buildAndStoreConfigSnapshot()

	return e
}

// ─── Proxy helpers ────────────────────────────────────────────────────────────

// LoadProxies loads a list of proxies from a file (SOCKS5 or HTTP).
func (e *Engine) LoadProxies(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	var proxies []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			proxies = append(proxies, line)
		}
	}
	e.proxies = proxies
	if len(proxies) > 0 {
		e.proxyDialer = true
		fmt.Printf("[*] Loaded %d proxies from %s\n", len(proxies), path)
	}
	return scanner.Err()
}

// GetNextProxy returns the next proxy in the list using round-robin.
func (e *Engine) GetNextProxy() string {
	if len(e.proxies) == 0 {
		return ""
	}
	idx := atomic.AddUint64(&e.proxyIndex, 1)
	return e.proxies[(idx-1)%uint64(len(e.proxies))]
}

// ─── Scan state / Eagle Mode ─────────────────────────────────────────────────

// LoadPreviousScan loads a previous JSONL scan file for differential scanning.
func (e *Engine) LoadPreviousScan(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	if e.PreviousState == nil {
		e.PreviousState = make(map[string]int)
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var res Result
		if err := json.Unmarshal(scanner.Bytes(), &res); err != nil {
			continue
		}
		e.PreviousState[res.Path] = res.StatusCode
	}
	return scanner.Err()
}

// ─── Rate limiting ────────────────────────────────────────────────────────────

// SetRPS updates the rate limiter settings dynamically.
func (e *Engine) SetRPS(rps int) {
	var limit rate.Limit
	if rps <= 0 {
		limit = rate.Inf
	} else {
		limit = rate.Limit(rps)
	}
	e.limitersLock.Lock()
	e.currentLimit = limit
	for _, l := range e.limiters {
		l.SetLimit(limit)
	}
	e.limitersLock.Unlock()
}

// UpdateRateLimiterFromDelay updates the rate limiter based on the delay setting.
func (e *Engine) UpdateRateLimiterFromDelay() {
	e.Config.RLock()
	d := e.Config.Delay
	workers := e.Config.MaxWorkers
	e.Config.RUnlock()

	var limit rate.Limit
	var b int
	if d <= 0 {
		limit = rate.Inf
		b = workers
		if b < 10 {
			b = 10
		}
	} else {
		rps := float64(workers) / d.Seconds()
		if rps < 1 {
			rps = 1
		}
		limit = rate.Limit(rps)
		b = workers
	}

	e.limitersLock.Lock()
	e.currentLimit = limit
	e.currentBurst = b
	for _, l := range e.limiters {
		l.SetLimit(limit)
		l.SetBurst(b)
	}
	e.limitersLock.Unlock()
}

func (e *Engine) getLimiter(host string) *rate.Limiter {
	e.limitersLock.RLock()
	l, exists := e.limiters[host]
	e.limitersLock.RUnlock()
	if exists {
		return l
	}

	e.limitersLock.Lock()
	defer e.limitersLock.Unlock()
	if l, exists := e.limiters[host]; exists {
		return l
	}
	newLimiter := rate.NewLimiter(e.currentLimit, e.currentBurst)
	e.limiters[host] = newLimiter
	return newLimiter
}

// buildAndStoreConfigSnapshot creates an immutable snapshot of the fields
// that workers read on the hot path and stores it atomically.
func (e *Engine) buildAndStoreConfigSnapshot() {
	e.Config.RLock()
	s := &configSnapshot{
		MaxWorkers:         e.Config.MaxWorkers,
		IsPaused:           e.Config.IsPaused,
		UserAgent:          e.Config.UserAgent,
		Headers:            make(map[string]string, len(e.Config.Headers)),
		MatchCodes:         make(map[int]bool, len(e.Config.MatchCodes)),
		FilterSizes:        make(map[int]bool, len(e.Config.FilterSizes)),
		FilterSizeRanges:   make([]SizeRange, len(e.Config.FilterSizeRanges)),
		MatchContentTypes:  make([]string, len(e.Config.MatchContentTypes)),
		FilterContentTypes: make([]string, len(e.Config.FilterContentTypes)),
		FollowRedirects:    e.Config.FollowRedirects,
		MaxRedirects:       e.Config.MaxRedirects,
		RequestBody:        e.Config.RequestBody,
		FilterWords:        e.Config.FilterWords,
		FilterLines:        e.Config.FilterLines,
		MatchWords:         e.Config.MatchWords,
		MatchLines:         e.Config.MatchLines,
		FilterRTMin:        e.Config.FilterRTMin,
		FilterRTMax:        e.Config.FilterRTMax,
		ProxyOut:           e.Config.ProxyOut,
		SaveRaw:            e.Config.SaveRaw,
		Methods:            make([]string, len(e.Config.Methods)),
		SmartAPI:           e.Config.SmartAPI,
		Extensions:         make([]string, len(e.Config.Extensions)),
	}
	// Honor User-Agent header override: worker formerly extracted UA from
	// headers if present and removed it from the header map.
	ua := s.UserAgent
	for k, v := range e.Config.Headers {
		if strings.EqualFold(k, "User-Agent") {
			ua = normalizeUserAgent(v)
			continue
		}
		s.Headers[k] = v
	}
	s.UserAgent = ua

	// Pre-build a headers template string so workers don't reconstruct the
	// header block on every job. Use a deterministic key order to keep
	// output stable.
	var hdrKeys []string
	for k := range s.Headers {
		hdrKeys = append(hdrKeys, k)
	}
	sort.Strings(hdrKeys)
	var hb strings.Builder
	for _, k := range hdrKeys {
		v := s.Headers[k]
		hb.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
	}
	s.HeadersTemplate = hb.String()

	for k, v := range e.Config.MatchCodes {
		s.MatchCodes[k] = v
	}
	for k, v := range e.Config.FilterSizes {
		s.FilterSizes[k] = v
	}
	copy(s.FilterSizeRanges, e.Config.FilterSizeRanges)
	copy(s.MatchContentTypes, e.Config.MatchContentTypes)
	copy(s.FilterContentTypes, e.Config.FilterContentTypes)
	copy(s.Methods, e.Config.Methods)
	copy(s.Extensions, e.Config.Extensions)
	e.Config.RUnlock()

	e.configSnap.Store(s)
}

// ─── Config helpers ───────────────────────────────────────────────────────────

// ConfigureFilters sets the matching status codes and filtering sizes.
func (e *Engine) ConfigureFilters(mc []int, fs []int) {
	e.Config.Lock()
	for _, code := range mc {
		e.Config.MatchCodes[code] = true
	}
	for _, size := range fs {
		e.Config.FilterSizes[size] = true
		e.manualFilterSizes[size] = true
	}
	e.Config.Unlock()
	e.buildAndStoreConfigSnapshot()
}

func (e *Engine) SetMatchRegex(pattern string) error {
	if pattern == "" {
		e.matchRe = nil
		return nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}
	e.matchRe = re
	e.Config.Lock()
	e.Config.MatchRegex = pattern
	e.Config.Unlock()
	e.buildAndStoreConfigSnapshot()
	return nil
}

func (e *Engine) SetFilterRegex(pattern string) error {
	if pattern == "" {
		e.filterRe = nil
		return nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}
	e.filterRe = re
	e.Config.Lock()
	e.Config.FilterRegex = pattern
	e.Config.Unlock()
	e.buildAndStoreConfigSnapshot()
	return nil
}

func (e *Engine) SetMatchPlugin(plugin *PluginMatcher)  { e.matchPlugin = plugin }
func (e *Engine) SetMutatePlugin(plugin *PluginMutator) { e.mutatePlugin = plugin }

func (e *Engine) UpdateUserAgent(ua string) {
	e.Config.Lock()
	normalized := normalizeUserAgent(ua)
	if normalized == "" {
		normalized = "DirFuzz/2.0"
	}
	e.Config.UserAgent = normalized
	e.Config.Unlock()
	e.buildAndStoreConfigSnapshot()
}

func normalizeUserAgent(ua string) string {
	ua = strings.TrimSpace(ua)
	const prefix = "User-Agent:"
	if len(ua) >= len(prefix) && strings.EqualFold(ua[:len(prefix)], prefix) {
		ua = strings.TrimSpace(ua[len(prefix):])
	}
	return ua
}

func (e *Engine) SetDelay(d time.Duration) {
	e.Config.Lock()
	e.Config.Delay = d
	e.Config.Unlock()
	e.buildAndStoreConfigSnapshot()
	e.UpdateRateLimiterFromDelay()
}

func (e *Engine) AddHeader(key, val string) {
	e.Config.Lock()
	if strings.EqualFold(strings.TrimSpace(key), "User-Agent") {
		e.Config.UserAgent = normalizeUserAgent(val)
		if e.Config.UserAgent == "" {
			e.Config.UserAgent = "DirFuzz/2.0"
		}
		for hk := range e.Config.Headers {
			if strings.EqualFold(hk, "User-Agent") {
				delete(e.Config.Headers, hk)
			}
		}
		e.Config.Unlock()
		e.buildAndStoreConfigSnapshot()
		return
	}
	e.Config.Headers[key] = val
	e.Config.Unlock()
	e.buildAndStoreConfigSnapshot()
}

func (e *Engine) RemoveHeader(key string) {
	e.Config.Lock()
	delete(e.Config.Headers, key)
	e.Config.Unlock()
	e.buildAndStoreConfigSnapshot()
}

func (e *Engine) ConfigSnapshot() (ua string, filters []int, headers map[string]string, delay time.Duration, exts []string, follow bool) {
	e.Config.RLock()
	defer e.Config.RUnlock()
	ua = e.Config.UserAgent
	delay = e.Config.Delay
	for size := range e.Config.FilterSizes {
		filters = append(filters, size)
	}
	headers = make(map[string]string)
	for k, v := range e.Config.Headers {
		headers[k] = v
	}
	exts = make([]string, len(e.Config.Extensions))
	copy(exts, e.Config.Extensions)
	follow = e.Config.FollowRedirects
	return
}

func (e *Engine) AddFilterSize(size int) {
	e.Config.Lock()
	e.Config.FilterSizes[size] = true
	e.manualFilterSizes[size] = true
	delete(e.autoFilterSizes, size)
	e.Config.Unlock()
	e.buildAndStoreConfigSnapshot()
}

func (e *Engine) AddAutoFilterSize(size int) {
	e.Config.Lock()
	e.Config.FilterSizes[size] = true
	if !e.manualFilterSizes[size] {
		e.autoFilterSizes[size] = true
	}
	e.Config.Unlock()
	e.buildAndStoreConfigSnapshot()
}

func (e *Engine) RemoveFilterSize(size int) {
	e.Config.Lock()
	delete(e.Config.FilterSizes, size)
	delete(e.manualFilterSizes, size)
	delete(e.autoFilterSizes, size)
	e.Config.Unlock()
	e.buildAndStoreConfigSnapshot()
}

func (e *Engine) clearAutoFilterSizes() {
	e.Config.Lock()
	for size := range e.autoFilterSizes {
		if !e.manualFilterSizes[size] {
			delete(e.Config.FilterSizes, size)
		}
	}
	e.autoFilterSizes = make(map[int]bool)
	e.Config.Unlock()
	e.buildAndStoreConfigSnapshot()
}

func (e *Engine) AddMatchCode(code int) {
	e.Config.Lock()
	e.Config.MatchCodes[code] = true
	e.Config.Unlock()
	e.buildAndStoreConfigSnapshot()
}

func (e *Engine) RemoveMatchCode(code int) {
	e.Config.Lock()
	delete(e.Config.MatchCodes, code)
	e.Config.Unlock()
	e.buildAndStoreConfigSnapshot()
}

func (e *Engine) AddExtension(ext string) {
	e.Config.Lock()
	for _, x := range e.Config.Extensions {
		if x == ext {
			e.Config.Unlock()
			return
		}
	}
	e.Config.Extensions = append(e.Config.Extensions, ext)
	e.Config.Unlock()
	e.buildAndStoreConfigSnapshot()
}

func (e *Engine) RemoveExtension(ext string) {
	e.Config.Lock()
	var newExts []string
	for _, x := range e.Config.Extensions {
		if x != ext {
			newExts = append(newExts, x)
		}
	}
	e.Config.Extensions = newExts
	e.Config.Unlock()
	e.buildAndStoreConfigSnapshot()
}

func (e *Engine) SetMutation(active bool) {
	e.Config.Lock()
	e.Config.Mutate = active
	e.Config.Unlock()
	e.buildAndStoreConfigSnapshot()
}

func (e *Engine) SetPaused(paused bool) {
	e.Config.Lock()
	e.Config.IsPaused = paused
	e.Config.Unlock()
	e.buildAndStoreConfigSnapshot()
}

func (e *Engine) SetFollowRedirects(follow bool) {
	e.Config.Lock()
	e.Config.FollowRedirects = follow
	e.Config.Unlock()
	e.buildAndStoreConfigSnapshot()
}

// ─── Per-host HEAD rejection ──────────────────────────────────────────────────

// headRejectedForHost returns the per-host atomic flag for HEAD rejection.
func (e *Engine) headRejectedForHost(host string) *int32 {
	val, _ := e.headRejectedHosts.LoadOrStore(host, new(int32))
	return val.(*int32)
}

func (e *Engine) isHeadRejected(host string) bool {
	return atomic.LoadInt32(e.headRejectedForHost(host)) == 1
}

func (e *Engine) markHeadRejected(host string) {
	atomic.StoreInt32(e.headRejectedForHost(host), 1)
}

// ─── Target management ────────────────────────────────────────────────────────

// SetTarget sets the target URL and extracts the host.
// It rejects private/loopback IP ranges to prevent SSRF when driven via MCP.
func (e *Engine) SetTarget(targetURL string) error {
	targetURL = strings.ReplaceAll(targetURL, "{payload}", "{PAYLOAD}")

	u, err := url.Parse(targetURL)
	if err != nil {
		return err
	}
	if u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("invalid URL: missing scheme or host")
	}

	hostname := u.Hostname()
	// Respect engine-level override to allow private/loopback targets.
	e.Config.RLock()
	allow := e.Config.AllowPrivateTargets
	e.Config.RUnlock()
	if !allow && isPrivateHost(hostname) {
		return fmt.Errorf("SSRF protection: target %q resolves to a private or loopback address", hostname)
	}

	e.targetLock.Lock()
	e.baseURL = targetURL
	e.host = u.Host
	if e.scopeDomain == "" {
		e.scopeDomain = hostname
	}
	e.targetLock.Unlock()
	return nil
}

// Simple in-memory cache for DNS lookups to avoid repeated syscalls for the
// same host during redirect chains. Maps lowercased hostname -> isPrivate.
var privateHostCache sync.Map

// isPrivateHost returns true when host is a loopback/private IP or resolves to one.
func isPrivateHost(host string) bool {
	lower := strings.ToLower(host)
	if lower == "localhost" || strings.HasSuffix(lower, ".localhost") {
		return true
	}

	if v, ok := privateHostCache.Load(lower); ok {
		return v.(bool)
	}

	ip := net.ParseIP(host)
	if ip == nil {
		addrs, err := net.LookupHost(host)
		if err != nil || len(addrs) == 0 {
			privateHostCache.Store(lower, false)
			return false
		}
		ip = net.ParseIP(addrs[0])
	}
	if ip == nil {
		privateHostCache.Store(lower, false)
		return false
	}

	for _, cidr := range []string{
		"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10",
	} {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			privateHostCache.Store(lower, true)
			return true
		}
	}
	privateHostCache.Store(lower, false)
	return false
}

func (e *Engine) BaseURL() string {
	e.targetLock.RLock()
	defer e.targetLock.RUnlock()
	return e.baseURL
}

func (e *Engine) Host() string {
	e.targetLock.RLock()
	defer e.targetLock.RUnlock()
	return e.host
}

// ─── Wordlist scanner ─────────────────────────────────────────────────────────

// Restart restarts the scanner with the current wordlist.
func (e *Engine) Restart() error {
	e.Config.RLock()
	path := e.Config.WordlistPath
	e.Config.RUnlock()
	if path == "" {
		return fmt.Errorf("no wordlist currently loaded to restart")
	}
	return e.ChangeWordlist(path)
}

// ChangeWordlist cancels the current scanner and starts a new one.
func (e *Engine) ChangeWordlist(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return fmt.Errorf("wordlist file does not exist: %s", path)
	}
	e.scannerCancel()

	e.filterLock.Lock()
	e.filter = bloom.NewWithEstimates(DefaultBloomFilterSize, DefaultBloomFilterFP)
	e.filterLock.Unlock()

	atomic.StoreInt64(&e.ProcessedLines, 0)
	atomic.StoreInt64(&e.TotalLines, 0)
	atomic.StoreInt64(&e.Count200, 0)
	atomic.StoreInt64(&e.Count403, 0)
	atomic.StoreInt64(&e.Count404, 0)
	atomic.StoreInt64(&e.Count429, 0)
	atomic.StoreInt64(&e.Count500, 0)
	atomic.StoreInt64(&e.CountConnErr, 0)
	atomic.StoreInt64(&e.CurrentRPS, 0)
	atomic.StoreInt32(&e.alreadyThrottled, 0)
	e.headRejectedHosts.Range(func(k, _ interface{}) bool {
		e.headRejectedHosts.Delete(k)
		return true
	})

	e.fpMutex.Lock()
	e.fpCounts = make(map[string]int)
	e.fpMutex.Unlock()
	e.clearAutoFilterSizes()

	e.drainJobs()

	e.scannerCtx, e.scannerCancel = context.WithCancel(context.Background())
	atomic.AddInt64(&e.RunID, 1)

	e.KickoffScanner(path, 0)
	return nil
}

// drainJobs safely drains all pending jobs from the jobs channel.
func (e *Engine) drainJobs() {
	for {
		select {
		case _, ok := <-e.jobs:
			if !ok {
				return
			}
			e.activeJobs.Done()
		default:
			return
		}
	}
}

// KickoffScanner starts the wordlist scanner.
func (e *Engine) KickoffScanner(path string, startLine int64) {
	e.AddScanner()
	go e.StartWordlistScanner(e.scannerCtx, atomic.LoadInt64(&e.RunID), path, startLine)
}

func (e *Engine) AddScanner() { e.scannerWg.Add(1) }

// StartWordlistScanner reads from a wordlist and submits payloads to the engine
// in a SINGLE pass, updating TotalLines atomically as it goes.
func (e *Engine) StartWordlistScanner(ctx context.Context, runID int64, path string, startLine int64) {
	defer e.scannerWg.Done()
	e.Config.Lock()
	e.Config.WordlistPath = path
	e.Config.Unlock()
	e.buildAndStoreConfigSnapshot()

	file, err := os.Open(path)
	if err != nil {
		res := Result{
			Path:         path,
			StatusCode:   0,
			IsAutoFilter: true,
			Headers:      map[string]string{"Msg": "Error opening wordlist: " + err.Error()},
		}
		select {
		case e.Results <- res:
		case <-ctx.Done():
		}
		return
	}
	defer file.Close()

	atomic.StoreInt64(&e.ProcessedLines, 0)
	atomic.StoreInt64(&e.TotalLines, 0)

	lineNum := int64(0)
	scanner := bufio.NewScanner(file)

	// Load methods/smartAPI/extensions from the immutable snapshot once and
	// refresh only when the snapshot pointer changes. This avoids taking
	// the config RLock for every wordlist line.
	snap := e.configSnap.Load()
	var methods []string
	var smartAPI bool
	var exts []string
	if snap != nil {
		methods = snap.Methods
		smartAPI = snap.SmartAPI
		exts = make([]string, len(snap.Extensions))
		copy(exts, snap.Extensions)
	} else {
		e.Config.RLock()
		methods = e.Config.Methods
		smartAPI = e.Config.SmartAPI
		exts = make([]string, len(e.Config.Extensions))
		copy(exts, e.Config.Extensions)
		e.Config.RUnlock()
	}

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			e.saveResumeState(path, lineNum)
			return
		default:
		}

		// Respect pause. Use the snapshot first; fall back to the lock if
		// the snapshot isn't available.
		var paused bool
		if s := e.configSnap.Load(); s != nil {
			paused = s.IsPaused
		} else {
			e.Config.RLock()
			paused = e.Config.IsPaused
			e.Config.RUnlock()
		}
		for paused {
			time.Sleep(100 * time.Millisecond)
			select {
			case <-ctx.Done():
				e.saveResumeState(path, lineNum)
				return
			default:
			}
			if s := e.configSnap.Load(); s != nil {
				paused = s.IsPaused
			} else {
				e.Config.RLock()
				paused = e.Config.IsPaused
				e.Config.RUnlock()
			}
		}

		line := scanner.Text()
		if line == "" {
			continue
		}
		lineNum++
		if lineNum <= startLine {
			continue
		}

		// Refresh locals if the global snapshot changed.
		if cur := e.configSnap.Load(); cur != snap && cur != nil {
			snap = cur
			methods = snap.Methods
			smartAPI = snap.SmartAPI
			exts = make([]string, len(snap.Extensions))
			copy(exts, snap.Extensions)
		}

		methodsToUse := resolveMethodsForPath(line, methods, smartAPI)
		for _, method := range methodsToUse {
			// Increment total for this base path.
			atomic.AddInt64(&e.TotalLines, 1)
			e.Submit(Job{Path: line, Depth: 0, Method: method, RunID: runID})
			for _, ext := range exts {
				cleanExt := strings.TrimSpace(ext)
				if !strings.HasPrefix(cleanExt, ".") {
					cleanExt = "." + cleanExt
				}
				atomic.AddInt64(&e.TotalLines, 1)
				e.Submit(Job{Path: line + cleanExt, Depth: 0, Method: method, RunID: runID})
			}
		}
	}
}

// resolveMethodsForPath returns the HTTP methods to use for a given path,
// taking into account SmartAPI mode.
func resolveMethodsForPath(line string, methods []string, smartAPI bool) []string {
	if len(methods) == 0 {
		return []string{""}
	}
	if !smartAPI || isAPIPath(line) {
		return methods
	}
	return []string{""}
}

// isAPIPath returns true when the path segment looks like an API endpoint.
// Uses segment-boundary matching to avoid false positives like /overview1.
var apiPathRe = regexp.MustCompile(`(?i)(^|/)(v\d+|api|rest|graphql)(/|$)`)

func isAPIPath(line string) bool {
	return apiPathRe.MatchString(line)
}

// ─── Resume support ───────────────────────────────────────────────────────────

func (e *Engine) saveResumeState(wordlist string, lineNum int64) {
	if e.ResumeFile == "" {
		return
	}
	state := map[string]interface{}{
		"wordlist":  wordlist,
		"line":      lineNum,
		"processed": atomic.LoadInt64(&e.ProcessedLines),
		"total":     atomic.LoadInt64(&e.TotalLines),
		"target":    e.BaseURL(),
	}
	data, err := json.Marshal(state)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to marshal resume state: %v\n", err)
		return
	}
	if err := os.WriteFile(e.ResumeFile, data, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to write resume file: %v\n", err)
	}
}

func (e *Engine) LoadResumeState(path string) (string, int64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", 0, err
	}
	var state map[string]interface{}
	if err := json.Unmarshal(data, &state); err != nil {
		return "", 0, err
	}
	wordlist, _ := state["wordlist"].(string)
	lineF, _ := state["line"].(float64)
	return wordlist, int64(lineF), nil
}

// ─── Calibration ─────────────────────────────────────────────────────────────

// AutoCalibrate detects wildcard responses using randomised paths.
// Body comparison uses a normalised hash so that path-reflecting wildcard
// pages (which vary in size) are still detected correctly.
func (e *Engine) AutoCalibrate() error {
	randPaths := make([]string, CalibrationTestCount)
	randoms := make([]string, CalibrationTestCount)
	for i := range randPaths {
		randoms[i] = randomString(CalibrationRandomStringLen)
		randPaths[i] = "/" + randoms[i]
	}

	type sample struct {
		statusCode int
		bodyHash   [32]byte
		bodySize   int
	}

	var first *sample
	consistent := true

	for i, path := range randPaths {
		rawRequest := []byte(fmt.Sprintf(
			"GET %s HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\nUser-Agent: %s\r\nAccept: */*\r\n\r\n",
			path, e.Host(), e.Config.UserAgent,
		))

		var proxyAddr string
		if e.proxyDialer {
			proxyAddr = e.GetNextProxy()
		}

		resp, err := e.executeRequestWithRetry(e.scannerCtx, e.BaseURL(), rawRequest, CalibrationTimeout, proxyAddr)
		if err != nil {
			return fmt.Errorf("calibration request failed: %v", err)
		}

		// Normalise: replace the random string in the body before hashing so
		// that path-reflecting pages hash identically across requests.
		normBody := bytes.ReplaceAll(resp.Body, []byte(randoms[i]), []byte("FUZZ"))
		h := sha256.Sum256(normBody)

		s := &sample{
			statusCode: resp.StatusCode,
			bodyHash:   h,
			bodySize:   len(resp.Body),
		}

		if first == nil {
			first = s
		} else if s.statusCode != first.statusCode || s.bodyHash != first.bodyHash {
			consistent = false
			break
		}
	}

	if consistent && first != nil && first.statusCode > 0 {
		fmt.Printf("[+] Wildcard detected! Status: %d, normalised body hash consistent — filtering size: %d\n",
			first.statusCode, first.bodySize)
		e.AddFilterSize(first.bodySize)
	}

	return nil
}

func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.IntN(len(letters))]
	}
	return string(b)
}

func (e *Engine) checkRecursiveWildcard(dirPath string) bool {
	e.Config.RLock()
	delay := e.Config.Delay
	e.Config.RUnlock()
	if delay > 0 {
		time.Sleep(delay)
	}

	randPath := strings.TrimSuffix(dirPath, "/") + "/" + randomString(RecursiveWildcardTestLen)

	rawRequest := []byte(fmt.Sprintf(
		"GET %s HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\nUser-Agent: %s\r\nAccept: */*\r\n\r\n",
		randPath, e.Host(), e.Config.UserAgent,
	))

	var proxyAddr string
	if e.proxyDialer {
		proxyAddr = e.GetNextProxy()
	}
	resp, err := e.executeRequestWithRetry(e.scannerCtx, e.BaseURL(), rawRequest, RecursiveWildcardTimeout, proxyAddr)
	if err != nil {
		return false
	}
	// Treat 200, 403 and common redirect responses as wildcard indicators.
	// Some servers redirect unknown paths (e.g. /*) with 301/302 — these
	// should be treated as wildcard directories to avoid unbounded
	// recursive scanning.
	if resp.StatusCode == 200 || resp.StatusCode == 403 || resp.StatusCode == 301 || resp.StatusCode == 302 {
		return true
	}
	return false
}

// ─── Worker management ────────────────────────────────────────────────────────

func (e *Engine) QueueSize() int { return len(e.jobs) }

func (e *Engine) Start() {
	e.workerLock.Lock()
	defer e.workerLock.Unlock()
	for i := 0; i < e.numWorkers; i++ {
		e.wg.Add(1)
		go e.worker(i)
	}
}

func (e *Engine) SetWorkerCount(n int) {
	if n < MinWorkerCount {
		n = MinWorkerCount
	}
	e.Config.Lock()
	e.Config.MaxWorkers = n
	e.Config.Unlock()
	e.buildAndStoreConfigSnapshot()

	e.workerLock.Lock()
	defer e.workerLock.Unlock()
	if n > e.numWorkers {
		diff := n - e.numWorkers
		for i := 0; i < diff; i++ {
			e.wg.Add(1)
			go e.worker(e.numWorkers + i)
		}
	}
	e.numWorkers = n
	e.UpdateRateLimiterFromDelay()
}

// autoThrottleCheck reduces workers/increases delay on repeated 429s.
// A guard prevents it from firing again once throttling is already applied.
func (e *Engine) autoThrottleCheck() {
	if !e.autoThrottle {
		return
	}
	count429 := atomic.LoadInt64(&e.Count429)
	if count429 > 0 && count429%AutoThrottleInterval == 0 {
		// Only fire once per AutoThrottleInterval batch.
		if !atomic.CompareAndSwapInt32(&e.alreadyThrottled, 0, 1) {
			return
		}
		// Reset so the next batch can trigger again.
		go func() {
			time.Sleep(5 * time.Second)
			atomic.StoreInt32(&e.alreadyThrottled, 0)
		}()

		e.Config.RLock()
		currentWorkers := e.Config.MaxWorkers
		currentDelay := e.Config.Delay
		e.Config.RUnlock()

		if atomic.LoadInt32(&e.throttleRestore) == 0 {
			atomic.CompareAndSwapInt32(&e.throttleRestore, 0, int32(currentWorkers))
		}

		newWorkers := currentWorkers * ThrottleWorkerPercent / 100
		if newWorkers < MinThrottledWorkers {
			newWorkers = MinThrottledWorkers
		}
		newDelay := currentDelay + ThrottleDelayIncrease
		if newDelay > MaxThrottleDelay {
			newDelay = MaxThrottleDelay
		}

		e.SetWorkerCount(newWorkers)
		e.SetDelay(newDelay)

		res := Result{
			Path:         "AUTO-THROTTLE",
			StatusCode:   429,
			IsAutoFilter: true,
			Headers:      map[string]string{"Msg": fmt.Sprintf("429 spike! Workers: %d→%d, Delay: %s", currentWorkers, newWorkers, newDelay)},
		}
		select {
		case e.Results <- res:
		default:
		}
	}
}

// ─── Redirect following ───────────────────────────────────────────────────────

func (e *Engine) followRedirectChain(
	initialResp *httpclient.RawResponse,
	targetURL, reqHost, ua string,
	headers map[string]string,
	maxRedirects int,
	proxyAddr string,
) (*httpclient.RawResponse, string) {
	resp := initialResp
	finalURL := ""
	currentURL := targetURL
	ua = normalizeUserAgent(ua)
	if ua == "" {
		ua = "DirFuzz/2.0"
	}

	for i := 0; i < maxRedirects; i++ {
		if resp.StatusCode < 300 || resp.StatusCode >= 400 {
			break
		}
		location := resp.GetHeader("Location")
		if location == "" {
			break
		}

		baseURL, err := url.Parse(currentURL)
		if err == nil {
			if locURL, err := url.Parse(location); err == nil {
				location = baseURL.ResolveReference(locURL).String()
			}
		}

		parsedLoc, err := url.Parse(location)
		if err != nil {
			break
		}

		// SSRF guard on redirect destinations — allow override via config.
		e.Config.RLock()
		allow := e.Config.AllowPrivateTargets
		e.Config.RUnlock()
		if !allow && isPrivateHost(parsedLoc.Hostname()) {
			break
		}

		reqPath := parsedLoc.Path
		if parsedLoc.RawQuery != "" {
			reqPath += "?" + parsedLoc.RawQuery
		}
		if reqPath == "" {
			reqPath = "/"
		}

		var headersStr strings.Builder
		for k, v := range headers {
			if strings.EqualFold(k, "User-Agent") {
				continue
			}
			headersStr.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
		}

		rawReq := []byte(fmt.Sprintf(
			"GET %s HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\nUser-Agent: %s\r\n%sAccept: */*\r\n\r\n",
			reqPath, parsedLoc.Host, ua, headersStr.String(),
		))

		nextResp, err := e.executeRequestWithRetry(e.scannerCtx, location, rawReq, DefaultHTTPTimeout, proxyAddr)
		if err != nil {
			break
		}
		resp = nextResp
		finalURL = location
		currentURL = location
	}

	return resp, finalURL
}

// ─── RPS tracking ─────────────────────────────────────────────────────────────

func (e *Engine) UpdateRPS() {
	nowNano := time.Now().UnixNano()
	lastTick := atomic.LoadInt64(&e.lastTick)
	elapsed := float64(nowNano-lastTick) / 1e9
	if elapsed < 0.1 {
		return
	}
	current := atomic.LoadInt64(&e.ProcessedLines)
	lastProcessed := atomic.LoadInt64(&e.lastProcessed)
	delta := current - lastProcessed
	atomic.StoreInt64(&e.CurrentRPS, int64(float64(delta)/elapsed))
	atomic.StoreInt64(&e.lastProcessed, current)
	atomic.StoreInt64(&e.lastTick, nowNano)
}

// ─── HTTP request execution ───────────────────────────────────────────────────

func (e *Engine) executeRequestWithRetry(ctx context.Context, targetURL string, rawRequest []byte, timeout time.Duration, proxyAddr string) (*httpclient.RawResponse, error) {
	e.Config.RLock()
	retries := e.Config.MaxRetries
	insecure := e.Config.Insecure
	e.Config.RUnlock()

	if ctx == nil {
		ctx = context.Background()
	}

	backoff := 1 * time.Second
	var (
		resp *httpclient.RawResponse
		err  error
	)
	for attempt := 0; attempt <= retries; attempt++ {
		resp, err = httpclient.SendRawRequestWithContext(ctx, targetURL, rawRequest, timeout, proxyAddr, insecure)
		if err == nil {
			return resp, nil
		}
		if attempt < retries {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
				backoff *= 2
			}
		}
	}
	return resp, err
}

// ─── Worker ───────────────────────────────────────────────────────────────────

// buildRequest constructs a raw HTTP request byte slice.
func buildRequest(method, reqPath, reqHost, ua, headersStr, bodyContent string) []byte {
	if bodyContent != "" {
		return []byte(fmt.Sprintf(
			"%s %s HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\nUser-Agent: %s\r\n%sAccept: */*\r\n\r\n%s",
			method, reqPath, reqHost, ua, headersStr, bodyContent,
		))
	}
	return []byte(fmt.Sprintf(
		"%s %s HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\nUser-Agent: %s\r\n%sAccept: */*\r\n\r\n",
		method, reqPath, reqHost, ua, headersStr,
	))
}

// applyFilters returns true when the result should be kept (not filtered).
func (e *Engine) applyFilters(
	resp *httpclient.RawResponse,
	bodySize, wordCount, lineCount int,
	contentType string,
	filterSizes map[int]bool,
	filterSizeRanges []SizeRange,
	matchCodes map[int]bool,
	filterWords, filterLines, matchWords, matchLines int,
	matchContentTypes, filterContentTypes []string,
	filterRTMin, filterRTMax time.Duration,
) bool {
	// 1. Status code.
	if len(matchCodes) > 0 && !matchCodes[resp.StatusCode] {
		return false
	}
	// 2. Exact size filter.
	if len(filterSizes) > 0 && filterSizes[bodySize] {
		return false
	}
	// 3. Size range filter (NEW).
	for _, r := range filterSizeRanges {
		// If bodySize is unknown (-1) do not match any size ranges.
		if bodySize >= 0 && bodySize >= r.Min && bodySize <= r.Max {
			return false
		}
	}
	// 4. Word / line counts.
	if filterWords >= 0 && wordCount == filterWords {
		return false
	}
	if filterLines >= 0 && lineCount == filterLines {
		return false
	}
	if matchWords >= 0 && wordCount != matchWords {
		return false
	}
	if matchLines >= 0 && lineCount != matchLines {
		return false
	}
	// 5. Body regex.
	if e.matchRe != nil && !e.matchRe.Match(resp.Body) {
		return false
	}
	if e.filterRe != nil && e.filterRe.Match(resp.Body) {
		return false
	}
	// 6. Response time.
	if filterRTMin > 0 && resp.Duration < filterRTMin {
		return false
	}
	if filterRTMax > 0 && resp.Duration > filterRTMax {
		return false
	}
	// 7. Content-type match (NEW).
	if len(matchContentTypes) > 0 {
		matched := false
		for _, ct := range matchContentTypes {
			if strings.Contains(strings.ToLower(contentType), strings.ToLower(ct)) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	// 8. Content-type filter (NEW).
	for _, ct := range filterContentTypes {
		if strings.Contains(strings.ToLower(contentType), strings.ToLower(ct)) {
			return false
		}
	}
	return true
}

func (e *Engine) cleanupJob(shouldExit bool) bool {
	e.activeJobs.Done()
	return shouldExit
}

func (e *Engine) worker(id int) {
	defer e.wg.Done()

	for job := range e.jobs {
		if job.RunID != atomic.LoadInt64(&e.RunID) {
			e.activeJobs.Done()
			continue
		}

		// Load immutable snapshot for this job (cheap atomic pointer load).
		snap := e.configSnap.Load()
		if snap == nil {
			// Lazily initialize if not present.
			e.buildAndStoreConfigSnapshot()
			snap = e.configSnap.Load()
			if snap == nil {
				// Fallback to original locking behavior if snapshot still missing.
				e.Config.RLock()
				local := &configSnapshot{
					MaxWorkers:         e.Config.MaxWorkers,
					IsPaused:           e.Config.IsPaused,
					UserAgent:          e.Config.UserAgent,
					Headers:            make(map[string]string, len(e.Config.Headers)),
					MatchCodes:         make(map[int]bool, len(e.Config.MatchCodes)),
					FilterSizes:        make(map[int]bool, len(e.Config.FilterSizes)),
					FilterSizeRanges:   make([]SizeRange, len(e.Config.FilterSizeRanges)),
					MatchContentTypes:  make([]string, len(e.Config.MatchContentTypes)),
					FilterContentTypes: make([]string, len(e.Config.FilterContentTypes)),
					FollowRedirects:    e.Config.FollowRedirects,
					MaxRedirects:       e.Config.MaxRedirects,
					RequestBody:        e.Config.RequestBody,
					FilterWords:        e.Config.FilterWords,
					FilterLines:        e.Config.FilterLines,
					MatchWords:         e.Config.MatchWords,
					MatchLines:         e.Config.MatchLines,
					FilterRTMin:        e.Config.FilterRTMin,
					FilterRTMax:        e.Config.FilterRTMax,
					ProxyOut:           e.Config.ProxyOut,
					SaveRaw:            e.Config.SaveRaw,
				}
				ua := local.UserAgent
				for k, v := range e.Config.Headers {
					if strings.EqualFold(k, "User-Agent") {
						ua = normalizeUserAgent(v)
						continue
					}
					local.Headers[k] = v
				}
				local.UserAgent = ua
				for k, v := range e.Config.MatchCodes {
					local.MatchCodes[k] = v
				}
				for k, v := range e.Config.FilterSizes {
					local.FilterSizes[k] = v
				}
				copy(local.FilterSizeRanges, e.Config.FilterSizeRanges)
				copy(local.MatchContentTypes, e.Config.MatchContentTypes)
				copy(local.FilterContentTypes, e.Config.FilterContentTypes)
				e.Config.RUnlock()
				snap = local
			}
		}
		// Copy snapshot values into local variables used below.
		maxWorkers := snap.MaxWorkers
		paused := snap.IsPaused
		ua := snap.UserAgent
		headers := snap.Headers
		matchCodes := snap.MatchCodes
		filterSizes := snap.FilterSizes
		filterSizeRanges := snap.FilterSizeRanges
		matchContentTypes := snap.MatchContentTypes
		filterContentTypes := snap.FilterContentTypes
		followRedirects := snap.FollowRedirects
		maxRedirects := snap.MaxRedirects
		requestBody := snap.RequestBody
		filterWords := snap.FilterWords
		filterLines := snap.FilterLines
		matchWords := snap.MatchWords
		matchLines := snap.MatchLines
		filterRTMin := snap.FilterRTMin
		filterRTMax := snap.FilterRTMax
		proxyOut := snap.ProxyOut
		saveRaw := snap.SaveRaw

		shouldExit := id >= maxWorkers

		// Pause loop — re-check the immutable snapshot to avoid frequent
		// locking on the hot path. Fall back to the config lock if the
		// snapshot is temporarily unavailable.
		for paused {
			select {
			case <-e.scannerCtx.Done():
				e.activeJobs.Done()
				return
			case <-time.After(100 * time.Millisecond):
			}
			if s := e.configSnap.Load(); s != nil {
				paused = s.IsPaused
			} else {
				e.Config.RLock()
				paused = e.Config.IsPaused
				e.Config.RUnlock()
			}
		}

		payload := job.Path
		depth := job.Depth

		e.targetLock.RLock()
		currentBaseURL := e.baseURL
		e.targetLock.RUnlock()

		// Build full URL.
		var fullURL string
		word := payload
		if strings.Contains(currentBaseURL, "{PAYLOAD}") {
			fullURL = strings.Replace(currentBaseURL, "{PAYLOAD}", word, 1)
		} else {
			if !strings.HasPrefix(word, "/") {
				word = "/" + word
			}
			fullURL = strings.TrimRight(currentBaseURL, "/") + word
		}

		parsedURL, errURL := url.Parse(fullURL)
		if errURL != nil {
			if e.cleanupJob(shouldExit) {
				return
			}
			continue
		}

		reqHost := parsedURL.Host

		// Per-host rate limiter.
		if err := e.getLimiter(reqHost).Wait(e.scannerCtx); err != nil {
			if e.cleanupJob(shouldExit) {
				return
			}
			continue
		}

		reqPath := parsedURL.Path
		if parsedURL.RawQuery != "" {
			reqPath += "?" + parsedURL.RawQuery
		}
		if reqPath == "" {
			reqPath = "/"
		}

		// Inject payload into User-Agent.
		ua = normalizeUserAgent(strings.ReplaceAll(ua, "{PAYLOAD}", payload))
		if ua == "" {
			ua = "DirFuzz/2.0"
		}

		// Build headers string by substituting the payload into the pre-built
		// headers template from the snapshot. This avoids rebuilding the
		// header block on every job.
		headersStr := strings.ReplaceAll(snap.HeadersTemplate, "{PAYLOAD}", payload)

		var proxyAddr string
		if e.proxyDialer {
			proxyAddr = e.GetNextProxy()
		}

		// ── Execute request ────────────────────────────────────────────────
		var resp *httpclient.RawResponse
		var err error
		var successfulMethod string
		var rawRequest []byte

		if job.Method == "" {
			bodyFilterActive := e.matchRe != nil || e.filterRe != nil ||
				filterWords >= 0 || filterLines >= 0 || matchWords >= 0 || matchLines >= 0 ||
				len(matchContentTypes) > 0 || len(filterContentTypes) > 0

			if bodyFilterActive || e.isHeadRejected(reqHost) || followRedirects {
				successfulMethod = "GET"
				rawRequest = buildRequest("GET", reqPath, reqHost, ua, headersStr, "")
				resp, err = e.executeRequestWithRetry(e.scannerCtx, currentBaseURL, rawRequest, DefaultHTTPTimeout, proxyAddr)
			} else {
				successfulMethod = "HEAD"
				rawRequest = buildRequest("HEAD", reqPath, reqHost, ua, headersStr, "")
				resp, err = e.executeRequestWithRetry(e.scannerCtx, currentBaseURL, rawRequest, DefaultHTTPTimeout, proxyAddr)

				if err == nil && (resp.StatusCode == 405 || resp.StatusCode == 501) {
					e.markHeadRejected(reqHost)
					successfulMethod = "GET"
					rawRequest = buildRequest("GET", reqPath, reqHost, ua, headersStr, "")
					if fbResp, fbErr := e.executeRequestWithRetry(e.scannerCtx, currentBaseURL, rawRequest, DefaultHTTPTimeout, proxyAddr); fbErr == nil {
						resp = fbResp
					} else {
						successfulMethod = "HEAD"
					}
				}
			}
			atomic.AddInt64(&e.ProcessedLines, 1)
		} else {
			successfulMethod = job.Method
			bodyContent := ""
			var methodHdrBuf strings.Builder
			methodHdrBuf.WriteString(headersStr)
			if requestBody != "" && (job.Method == "POST" || job.Method == "PUT" || job.Method == "PATCH") {
				bodyContent = strings.ReplaceAll(requestBody, "{PAYLOAD}", payload)
				methodHdrBuf.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(bodyContent)))
			} else if job.Method == "POST" || job.Method == "PUT" || job.Method == "PATCH" || job.Method == "DELETE" {
				methodHdrBuf.WriteString("Content-Length: 0\r\n")
			}
			rawRequest = buildRequest(job.Method, reqPath, reqHost, ua, methodHdrBuf.String(), bodyContent)
			resp, err = e.executeRequestWithRetry(e.scannerCtx, currentBaseURL, rawRequest, 5*time.Second, proxyAddr)
			atomic.AddInt64(&e.ProcessedLines, 1)
		}

		if err != nil {
			atomic.AddInt64(&e.CountConnErr, 1)
			if e.cleanupJob(shouldExit) {
				return
			}
			continue
		}

		// Update stats counters.
		switch {
		case resp.StatusCode == 200:
			atomic.AddInt64(&e.Count200, 1)
		case resp.StatusCode == 403:
			atomic.AddInt64(&e.Count403, 1)
		case resp.StatusCode == 404:
			atomic.AddInt64(&e.Count404, 1)
		case resp.StatusCode == 429:
			atomic.AddInt64(&e.Count429, 1)
			e.autoThrottleCheck()
		case resp.StatusCode >= 500:
			atomic.AddInt64(&e.Count500, 1)
		}

		// Follow redirects.
		var finalRedirectURL string
		originalStatusCode := resp.StatusCode
		if followRedirects && resp.StatusCode >= 300 && resp.StatusCode < 400 {
			resp, finalRedirectURL = e.followRedirectChain(resp, fullURL, reqHost, ua, headers, maxRedirects, proxyAddr)
			if resp.StatusCode != originalStatusCode {
				switch {
				case resp.StatusCode == 200:
					atomic.AddInt64(&e.Count200, 1)
				case resp.StatusCode == 403:
					atomic.AddInt64(&e.Count403, 1)
				case resp.StatusCode == 404:
					atomic.AddInt64(&e.Count404, 1)
				}
			}
		}

		// Determine body metrics. If the body is encoded with an unsupported
		// algorithm (e.g. Brotli) or decompression failed, the RawResponse
		// will have BodyEncoded=true. In that case skip content-based metrics
		// and report unknown size/counts as -1 so filters don't operate on
		// misleading numbers.
		bodySize := len(resp.Body)

		// Initialize counts to -1 (unknown) to make intent explicit.
		wordCount := -1
		lineCount := -1

		if resp.BodyEncoded {
			bodySize = -1
		} else {
			// Use the decoded body length (after dechunk/gunzip). Only use the
			// Content-Length header for HEAD responses where no body is present.
			if successfulMethod == "HEAD" {
				clVal := resp.GetHeader("Content-Length")
				if clVal != "" {
					if s, parseErr := strconv.Atoi(clVal); parseErr == nil {
						bodySize = s
					}
				}
			}

			// Count words and lines without allocating large intermediate strings.
			// Use rune-wise decoding so we correctly detect Unicode whitespace
			// without converting the entire body into a string.
			if len(resp.Body) == 0 {
				wordCount = 0
				lineCount = 0
			} else {
				wordCount = 0
				lineCount = 0
				inWord := false
				for i := 0; i < len(resp.Body); {
					r, size := utf8.DecodeRune(resp.Body[i:])
					i += size
					if r == '\n' {
						lineCount++
					}
					if unicode.IsSpace(r) {
						if inWord {
							inWord = false
						}
					} else {
						if !inWord {
							wordCount++
							inWord = true
						}
					}
				}
				// Match previous behaviour: lines = count('\n') + 1 when non-empty.
				lineCount = lineCount + 1
			}
		}

		contentType := resp.GetHeader("Content-Type")
		if idx := strings.Index(contentType, ";"); idx != -1 {
			contentType = strings.TrimSpace(contentType[:idx])
		}

		// Apply all filters.
		if !e.applyFilters(resp, bodySize, wordCount, lineCount, contentType,
			filterSizes, filterSizeRanges, matchCodes,
			filterWords, filterLines, matchWords, matchLines,
			matchContentTypes, filterContentTypes,
			filterRTMin, filterRTMax) {
			if e.cleanupJob(shouldExit) {
				return
			}
			continue
		}

		// 403 classification.
		forbidden403Type := ""
		if resp.StatusCode == 403 {
			classifyBody := resp.Body
			classifyHeaders := resp.Headers
			if successfulMethod == "HEAD" {
				followupReq := buildRequest("GET", reqPath, reqHost, ua, headersStr, "")
				if followupResp, followupErr := e.executeRequestWithRetry(e.scannerCtx, currentBaseURL, followupReq, 3*time.Second, proxyAddr); followupErr == nil {
					classifyBody = followupResp.Body
					classifyHeaders = followupResp.Headers
				}
			}
			forbidden403Type = Classify403(classifyBody, classifyHeaders)
		}

		// Smart Filter.
		if resp.StatusCode == 200 || resp.StatusCode == 301 || resp.StatusCode == 302 || resp.StatusCode == 403 {
			fpKey := fmt.Sprintf("%d:%d", resp.StatusCode, bodySize)
			if resp.StatusCode == 403 {
				fpKey = fmt.Sprintf("403:%s:%d", forbidden403Type, bodySize)
			}

			e.fpMutex.Lock()
			e.fpCounts[fpKey]++
			count := e.fpCounts[fpKey]
			e.fpMutex.Unlock()

			threshold := e.Config.AutoFilterThreshold
			if threshold > 0 && count == threshold {
				e.AddAutoFilterSize(bodySize)
				select {
				case e.Results <- Result{
					Path:         "AUTO-FILTER",
					Method:       successfulMethod,
					StatusCode:   resp.StatusCode,
					Size:         bodySize,
					Headers:      map[string]string{"Msg": fmt.Sprintf("Auto-filtered repetitive size: %d", bodySize)},
					IsAutoFilter: true,
				}:
				default:
				}
			}
			if threshold > 0 && count >= threshold {
				if e.cleanupJob(shouldExit) {
					return
				}
				continue
			}
		}

		// Capture interesting headers.
		capturedHeaders := make(map[string]string)
		for _, line := range strings.Split(strings.ReplaceAll(resp.Headers, "\r\n", "\n"), "\n") {
			if idx := strings.Index(line, ":"); idx != -1 {
				key := strings.TrimSpace(line[:idx])
				val := strings.TrimSpace(line[idx+1:])
				switch strings.ToLower(key) {
				case "server":
					capturedHeaders["Server"] = val
				case "x-powered-by":
					capturedHeaders["X-Powered-By"] = val
				case "cf-ray":
					capturedHeaders["Cf-Ray"] = val
				}
			}
		}

		result := Result{
			Path:        payload,
			Method:      successfulMethod,
			StatusCode:  resp.StatusCode,
			Size:        bodySize,
			Words:       wordCount,
			Lines:       lineCount,
			ContentType: contentType,
			Duration:    resp.Duration,
			Headers:     capturedHeaders,
			URL:         fullURL,
		}

		// Only include raw request/response when SaveRaw is enabled.
		if saveRaw {
			result.Request = string(rawRequest)
			result.Response = string(resp.Raw)
		}

		if resp.StatusCode >= 300 && resp.StatusCode < 400 && !followRedirects {
			result.Redirect = resp.GetHeader("Location")
		}
		if finalRedirectURL != "" && resp.StatusCode >= 300 && resp.StatusCode < 400 {
			result.Redirect = finalRedirectURL
		}
		if resp.StatusCode == 403 {
			result.Forbidden403Type = forbidden403Type
		}

		// Eagle Mode.
		if e.PreviousState != nil {
			if oldStatus, exists := e.PreviousState[payload]; exists && oldStatus != resp.StatusCode {
				result.IsEagleAlert = true
				result.OldStatusCode = oldStatus
			}
		}

		// Lua plugin match. Allocate the response body string only when a
		// match plugin is configured to avoid unnecessary large allocations.
		var bodyStr string
		if e.matchPlugin != nil {
			bodyStr = string(resp.Body)
		}
		if e.matchPlugin != nil && !e.matchPlugin.Match(resp.StatusCode, bodySize, wordCount, lineCount, bodyStr, contentType) {
			if e.cleanupJob(shouldExit) {
				return
			}
			continue
		}

		select {
		case e.Results <- result:
		case <-e.scannerCtx.Done():
			e.activeJobs.Done()
			return
		}

		// Outbound proxy replay via bounded queue.
		if proxyOut != "" {
			select {
			case e.replayCh <- replayTask{
				proxyAddr:   proxyOut,
				fullURL:     fullURL,
				method:      successfulMethod,
				ua:          ua,
				headers:     headers,
				requestBody: requestBody,
				payload:     payload,
			}:
			default:
				// Drop if queue is full — don't block workers.
			}
		}

		// Smart Mutation — applies to ALL paths (not just dotted ones).
		e.Config.RLock()
		doMutate := e.Config.Mutate
		e.Config.RUnlock()
		if doMutate && (resp.StatusCode == 200 || resp.StatusCode == 403 || resp.StatusCode == 301) {
			go func(runID int64, basePath, method string) {
				mutations := []string{".bak", ".old", ".save", "~", ".swp", ".orig", ".tmp"}
				for _, m := range mutations {
					e.Submit(Job{Path: basePath + m, Depth: depth, Method: method, RunID: runID})
				}
			}(job.RunID, payload, job.Method)
		}

		// Recursive scanning with bounded concurrency.
		e.Config.RLock()
		doRecurse := e.Config.Recursive
		maxDepth := e.Config.MaxDepth
		wordlistPath := e.Config.WordlistPath
		e.Config.RUnlock()

		if doRecurse && depth < maxDepth {
			inScope := true
			if result.Redirect != "" {
				if parsedRedir, err := url.Parse(result.Redirect); err == nil && parsedRedir.Host != "" {
					e.targetLock.RLock()
					scopeDom := e.scopeDomain
					e.targetLock.RUnlock()
					redirHost := parsedRedir.Hostname()
					if redirHost != scopeDom && !strings.HasSuffix(redirHost, "."+scopeDom) {
						inScope = false
					}
				}
			}
			if inScope {
				// Perform the wildcard check asynchronously so the worker isn't
				// blocked performing network IO. If the path is not a
				// wildcard and a semaphore slot is available, spawn the
				// recursive scanner.
				go func(runID int64, basePath string, nextDepth int, wlPath string) {
					if e.checkRecursiveWildcard(basePath) {
						return
					}

					// Acquire semaphore slot (non-blocking to avoid stalling).
					select {
					case e.recursiveSem <- struct{}{}:
						e.AddScanner()
						go func(runID int64, basePath string, nextDepth int, wlPath string) {
							defer e.scannerWg.Done()
							defer func() { <-e.recursiveSem }()

							f, err := os.Open(wlPath)
							if err != nil {
								return
							}
							defer f.Close()

							e.Config.RLock()
							methods := e.Config.Methods
							smartAPI := e.Config.SmartAPI
							e.Config.RUnlock()

							scanner := bufio.NewScanner(f)
							for scanner.Scan() {
								word := scanner.Text()
								if word == "" {
									continue
								}
								newPath := strings.TrimSuffix(basePath, "/") + "/" + strings.TrimPrefix(word, "/")
								for _, method := range resolveMethodsForPath(newPath, methods, smartAPI) {
									atomic.AddInt64(&e.TotalLines, 1)
									e.Submit(Job{Path: newPath, Depth: nextDepth, Method: method, RunID: runID})
								}
							}
						}(runID, basePath, nextDepth, wlPath)
					default:
						// Semaphore full; skip recursive scan for this hit.
					}
				}(job.RunID, payload, depth+1, wordlistPath)
			}
		}

		e.activeJobs.Done()
		if shouldExit {
			return
		}
	}
}

// ─── Proxy replay (bounded) ───────────────────────────────────────────────────

// execReplay forwards a hit through an HTTP proxy (e.g. Burp Suite).
func (e *Engine) execReplay(task replayTask) {
	client := e.getReplayClient(task.proxyAddr)
	if client == nil {
		return
	}

	method := task.method
	if method == "" || method == "HEAD" {
		method = "GET"
	}

	var body io.Reader
	if task.requestBody != "" && (method == "POST" || method == "PUT" || method == "PATCH") {
		body = strings.NewReader(strings.ReplaceAll(task.requestBody, "{PAYLOAD}", task.payload))
	}

	req, err := http.NewRequest(method, task.fullURL, body)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", strings.ReplaceAll(task.ua, "{PAYLOAD}", task.payload))
	for k, v := range task.headers {
		req.Header.Set(k, strings.ReplaceAll(v, "{PAYLOAD}", task.payload))
	}

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}

// getReplayClient returns a reusable *http.Client for the given proxy address.
// If the proxy address is invalid or empty this returns nil. Clients are
// cached in a sync.Map to avoid repeatedly allocating transports and to
// enable connection/TLS session reuse with the proxy.
func (e *Engine) getReplayClient(proxyAddr string) *http.Client {
	if proxyAddr == "" {
		return nil
	}
	if v, ok := e.replayClients.Load(proxyAddr); ok {
		return v.(*http.Client)
	}

	proxyURL, err := url.Parse(proxyAddr)
	if err != nil {
		return nil
	}

	transport := &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}

	actual, loaded := e.replayClients.LoadOrStore(proxyAddr, client)
	if loaded {
		// Another goroutine stored a client first; close our idle conns.
		if tr, ok := client.Transport.(*http.Transport); ok {
			tr.CloseIdleConnections()
		}
		return actual.(*http.Client)
	}
	return client
}

// ─── Job submission ───────────────────────────────────────────────────────────

// Submit adds a payload to the queue if it passes the Bloom filter check.
func (e *Engine) Submit(job Job) {
	if job.RunID != atomic.LoadInt64(&e.RunID) {
		return
	}

	e.filterLock.Lock()
	filterKey := job.Path
	if job.Method != "" {
		filterKey = job.Method + ":" + job.Path
	}
	isDuplicate := e.filter.TestAndAddString(filterKey)
	e.filterLock.Unlock()

	if isDuplicate {
		atomic.AddInt64(&e.ProcessedLines, 1)
		return
	}

	e.activeJobs.Add(1)
	select {
	case e.jobs <- job:
	case <-e.scannerCtx.Done():
		e.activeJobs.Done()
	}
}

// ─── Lifecycle ────────────────────────────────────────────────────────────────

func (e *Engine) Wait() {
	e.scannerWg.Wait()
	e.activeJobs.Wait()
}

// Shutdown requests a graceful stop and closes the Results channel.
func (e *Engine) Shutdown() {
	e.shutdownOnce.Do(func() {
		if e.scannerCancel != nil {
			e.scannerCancel()
		}
		e.drainJobs()
		e.Wait()

		// Close replay channel, stopping replay workers.
		close(e.replayCh)

		// Close idle connections on cached replay transports so they don't
		// leak goroutines or hold resources after shutdown.
		e.replayClients.Range(func(k, v interface{}) bool {
			if client, ok := v.(*http.Client); ok {
				if tr, ok := client.Transport.(*http.Transport); ok {
					tr.CloseIdleConnections()
				}
			}
			return true
		})

		close(e.Results)
	})
}

// ─── Meta ─────────────────────────────────────────────────────────────────────

type EngineConfigDump struct {
	Target     string
	Wordlist   string
	OutputFile string
	SmartAPI   bool
}

func (e *Engine) DumpMeta() EngineConfigDump {
	e.Config.RLock()
	defer e.Config.RUnlock()
	return EngineConfigDump{
		Target:     e.BaseURL(),
		Wordlist:   e.Config.WordlistPath,
		OutputFile: e.Config.OutputFile,
		SmartAPI:   e.Config.SmartAPI,
	}
}
