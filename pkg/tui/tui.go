package tui

import (
	"dirfuzz/pkg/engine"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// TUI Colors (Dracula Theme)
var (
	DraculaBg      = lipgloss.Color("#282a36")
	DraculaFg      = lipgloss.Color("#f8f8f2")
	DraculaPurple  = lipgloss.Color("#bd93f9")
	DraculaGreen   = lipgloss.Color("#50fa7b")
	DraculaCyan    = lipgloss.Color("#8be9fd")
	DraculaOrange  = lipgloss.Color("#ffb86c")
	DraculaRed     = lipgloss.Color("#ff5555")
	DraculaPink    = lipgloss.Color("#ff79c6")
	DraculaYellow  = lipgloss.Color("#f1fa8c")
	DraculaComment = lipgloss.Color("#6272a4")
)

// Styles
var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(DraculaPurple).
			Background(DraculaBg).
			PaddingLeft(1).
			PaddingRight(1)

	statusStyle = lipgloss.NewStyle().
			Foreground(DraculaGreen)

	errorStyle = lipgloss.NewStyle().
			Foreground(DraculaRed)

	mutedStyle = lipgloss.NewStyle().
			Foreground(DraculaComment)

	highlightStyle = lipgloss.NewStyle().
			Foreground(DraculaCyan)

	orangeStyle = lipgloss.NewStyle().
			Foreground(DraculaOrange)

	pinkStyle = lipgloss.NewStyle().
			Foreground(DraculaPink)

	yellowStyle = lipgloss.NewStyle().
			Foreground(DraculaYellow)

	logStyle = lipgloss.NewStyle().
			Foreground(DraculaFg)

	cmdPromptStyle = lipgloss.NewStyle().
			Foreground(DraculaPurple).
			Bold(true)

	separatorStyle = lipgloss.NewStyle().
			Foreground(DraculaComment)

	autocompleteBoxStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(DraculaCyan).
				Padding(0, 1)

	autocompleteItemStyle = lipgloss.NewStyle().
				Foreground(DraculaFg)

	autocompleteSelectedStyle = lipgloss.NewStyle().
					Foreground(DraculaBg).
					Background(DraculaPurple).
					Bold(true)

	paneStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(DraculaPurple).
			Padding(0, 1)

	detailPaneHeaderBaseStyle = lipgloss.NewStyle().
					Bold(true).
					Padding(0, 1)

	requestPaneHeaderStyle = detailPaneHeaderBaseStyle.Copy().
				Foreground(DraculaBg).
				Background(DraculaCyan)

	responsePaneHeaderStyle = detailPaneHeaderBaseStyle.Copy().
				Foreground(DraculaBg).
				Background(DraculaOrange)

	selectedRowStyle = lipgloss.NewStyle().
				Background(DraculaPurple).
				Foreground(DraculaBg)

	selectedCursorStyle = lipgloss.NewStyle().
				Foreground(DraculaPurple).
				Bold(true)

	severity2xxStyle     = lipgloss.NewStyle().Foreground(DraculaGreen)
	severity3xxStyle     = lipgloss.NewStyle().Foreground(DraculaCyan)
	severity403Style     = lipgloss.NewStyle().Foreground(DraculaOrange)
	severity4xxStyle     = lipgloss.NewStyle().Foreground(DraculaYellow)
	severity5xxStyle     = lipgloss.NewStyle().Foreground(DraculaRed)
	severityNeutralStyle = lipgloss.NewStyle().Foreground(DraculaComment)

	badgeBaseStyle = lipgloss.NewStyle().
			Bold(true).
			Padding(0, 1)

	badge2xxStyle = badgeBaseStyle.Copy().
			Foreground(DraculaBg).
			Background(DraculaGreen)

	badge403Style = badgeBaseStyle.Copy().
			Foreground(DraculaBg).
			Background(DraculaOrange)

	badge404Style = badgeBaseStyle.Copy().
			Foreground(DraculaFg).
			Background(DraculaComment)

	badge429Style = badgeBaseStyle.Copy().
			Foreground(DraculaBg).
			Background(DraculaYellow)

	badge5xxStyle = badgeBaseStyle.Copy().
			Foreground(DraculaFg).
			Background(DraculaRed)

	badgeErrStyle = badgeBaseStyle.Copy().
			Foreground(DraculaBg).
			Background(DraculaPink)
)

var ansiEscapePattern = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func renderStatusBadge(style lipgloss.Style, icon, label string, count int64) string {
	return style.Render(fmt.Sprintf("%s %s: %d", icon, label, count))
}

func renderSeverityMarker(hit *engine.Result) string {
	if hit == nil {
		return severityNeutralStyle.Render("·")
	}

	symbol := "●"
	switch {
	case hit.StatusCode >= 200 && hit.StatusCode < 300:
		return severity2xxStyle.Render(symbol)
	case hit.StatusCode >= 300 && hit.StatusCode < 400:
		return severity3xxStyle.Render(symbol)
	case hit.StatusCode == 403:
		return severity403Style.Render(symbol)
	case hit.StatusCode >= 400 && hit.StatusCode < 500:
		return severity4xxStyle.Render(symbol)
	case hit.StatusCode >= 500:
		return severity5xxStyle.Render(symbol)
	default:
		return severityNeutralStyle.Render(symbol)
	}
}

func severitySymbol(hit *engine.Result) string {
	if hit == nil {
		return "·"
	}
	return "●"
}

func stripANSI(text string) string {
	return ansiEscapePattern.ReplaceAllString(text, "")
}

func renderPaneHeader(style lipgloss.Style, width int, title string) string {
	if width < 1 {
		width = 1
	}
	return style.Copy().Width(width).Align(lipgloss.Left).Render(title)
}

func renderSparkline(values []int64, width int) string {
	if width <= 0 {
		return ""
	}
	if len(values) == 0 {
		return strings.Repeat("▁", width)
	}

	if len(values) > width {
		values = values[len(values)-width:]
	}

	blocks := []rune("▁▂▃▄▅▆▇█")
	minV, maxV := values[0], values[0]
	for _, v := range values {
		if v < minV {
			minV = v
		}
		if v > maxV {
			maxV = v
		}
	}

	var out strings.Builder
	for _, v := range values {
		idx := 0
		if maxV > minV {
			idx = int((v - minV) * int64(len(blocks)-1) / (maxV - minV))
		}
		out.WriteRune(blocks[idx])
	}

	if out.Len() < width {
		return strings.Repeat("▁", width-out.Len()) + out.String()
	}

	return out.String()
}

func clampFloat(v, minV, maxV float64) float64 {
	if v < minV {
		return minV
	}
	if v > maxV {
		return maxV
	}
	return v
}

func hexToRGB(hex string) (int64, int64, int64) {
	hex = strings.TrimPrefix(hex, "#")
	if len(hex) != 6 {
		return 255, 255, 255
	}
	r, errR := strconv.ParseInt(hex[0:2], 16, 64)
	g, errG := strconv.ParseInt(hex[2:4], 16, 64)
	b, errB := strconv.ParseInt(hex[4:6], 16, 64)
	if errR != nil || errG != nil || errB != nil {
		return 255, 255, 255
	}
	return r, g, b
}

func lerpHexColor(startHex, endHex string, t float64) string {
	t = clampFloat(t, 0, 1)
	sr, sg, sb := hexToRGB(startHex)
	er, eg, eb := hexToRGB(endHex)

	r := int64(float64(sr) + (float64(er-sr) * t))
	g := int64(float64(sg) + (float64(eg-sg) * t))
	b := int64(float64(sb) + (float64(eb-sb) * t))

	return fmt.Sprintf("#%02x%02x%02x", r, g, b)
}

func progressFillColor(progressPct float64) lipgloss.Color {
	progressPct = clampFloat(progressPct, 0, 100)
	if progressPct <= 70 {
		t := progressPct / 70.0
		return lipgloss.Color(lerpHexColor(string(DraculaGreen), string(DraculaYellow), t))
	}
	t := (progressPct - 70.0) / 30.0
	return lipgloss.Color(lerpHexColor(string(DraculaYellow), string(DraculaOrange), t))
}

func renderProgressBar(width int, progressPct float64) string {
	if width < 1 {
		return ""
	}

	progressPct = clampFloat(progressPct, 0, 100)
	fillUnits := (progressPct / 100.0) * float64(width)
	full := int(fillUnits)
	remainder := fillUnits - float64(full)

	if full > width {
		full = width
	}

	var fill strings.Builder
	if full > 0 {
		fill.WriteString(strings.Repeat("█", full))
	}

	partialAdded := false
	if full < width {
		partialIdx := int(remainder * 8)
		if partialIdx > 0 {
			partialRunes := []rune("▏▎▍▌▋▊▉")
			if partialIdx > len(partialRunes) {
				partialIdx = len(partialRunes)
			}
			fill.WriteRune(partialRunes[partialIdx-1])
			partialAdded = true
		}
	}

	used := full
	if partialAdded {
		used++
	}
	if used > width {
		used = width
	}

	empty := strings.Repeat("░", width-used)
	fillStyle := lipgloss.NewStyle().Foreground(progressFillColor(progressPct))

	return fillStyle.Render(fill.String()) + mutedStyle.Render(empty)
}

func suggestionDropdownWidth(suggestions []string, maxWidth int) int {
	if maxWidth < 16 {
		return 16
	}

	width := 20
	for _, s := range suggestions {
		candidate := len([]rune(s)) + 4
		if candidate > width {
			width = candidate
		}
	}

	if width > maxWidth {
		width = maxWidth
	}
	if width < 16 {
		width = 16
	}

	return width
}

func renderSuggestionDropdown(suggestions []string, selectedIdx, width int) string {
	if len(suggestions) == 0 {
		return ""
	}

	if width < 16 {
		width = 16
	}

	maxVisible := 6
	start := 0
	if selectedIdx >= maxVisible {
		start = selectedIdx - maxVisible + 1
	}
	end := start + maxVisible
	if end > len(suggestions) {
		end = len(suggestions)
	}

	innerWidth := width - 4
	if innerWidth < 1 {
		innerWidth = 1
	}

	var lines []string
	for i := start; i < end; i++ {
		prefix := "  "
		style := autocompleteItemStyle
		if i == selectedIdx {
			prefix = "▸ "
			style = autocompleteSelectedStyle
		}
		line := style.Width(innerWidth).Render(prefix + suggestions[i])
		lines = append(lines, line)
	}

	return autocompleteBoxStyle.Width(width).Render(strings.Join(lines, "\n"))
}

// CommandDef defines a TUI command.
type CommandDef struct {
	Name        string
	Description string
	Args        string
	Handler     func(m *Model, args string) string
}

// TickMsg is sent on each tick.
type TickMsg time.Time

// ViewState defines which screen the user is looking at
type ViewState int

const (
	StateList ViewState = iota
	StateDetail
	StateCommand
)

// Model is the BubbleTea model for the TUI.
type Model struct {
	Engine        *engine.Engine
	resultsCh     <-chan engine.Result
	viewport      viewport.Model
	textInput     textinput.Model
	logs          []string
	logLineHits   []*engine.Result
	hits          []engine.Result // Keep track of hits to view them later
	rpsHistory    []int64
	commandMode   bool
	width, height int
	ready         bool

	// View State
	state ViewState

	// List View Selection
	selectedIndex int
	listScrollIdx int // How far down the list we have scrolled

	// Detail Viewports
	reqViewport viewport.Model
	resViewport viewport.Model
	cmdOutput   []string
	cmdViewport viewport.Model

	// Telemetry display
	startTime time.Time

	// Command history
	cmdHistory    []string
	cmdHistoryIdx int

	// Available commands
	commands []CommandDef

	// Autocomplete state
	suggestions    []string
	selectedSugIdx int

	// State
	quitting       bool
	pendingTarget  string
	commandPulseOn bool
}

// NewModel initializes the TUI model.
func NewModel(eng *engine.Engine, resultsCh <-chan engine.Result) Model {
	ti := textinput.New()
	ti.Prompt = ""
	ti.Placeholder = "Type ':' to enter command mode, 'q' to quit, 'Enter' on a hit to view details"
	ti.CharLimit = 256
	ti.Width = 80

	vp := viewport.New(80, 20)
	vp.SetContent("")

	reqVp := viewport.New(40, 20)
	resVp := viewport.New(40, 20)
	cmdVp := viewport.New(80, 10)

	m := Model{
		Engine:         eng,
		resultsCh:      resultsCh,
		viewport:       vp,
		reqViewport:    reqVp,
		resViewport:    resVp,
		cmdViewport:    cmdVp,
		textInput:      ti,
		logs:           []string{},
		logLineHits:    []*engine.Result{},
		hits:           []engine.Result{},
		rpsHistory:     []int64{},
		cmdOutput:      []string{},
		startTime:      time.Now(),
		state:          StateList,
		commandPulseOn: true,
	}
	m.initCommands()
	return m
}

// initCommands registers all available TUI commands.
func (m *Model) initCommands() {
	m.commands = []CommandDef{
		{Name: "help", Description: "Show all commands", Args: "", Handler: func(m *Model, args string) string {
			var sb strings.Builder
			sb.WriteString(pinkStyle.Render("=== DirFuzz Commands ===") + "\n")
			for _, cmd := range m.commands {
				line := fmt.Sprintf("  :%s", cmd.Name)
				if cmd.Args != "" {
					line += " " + cmd.Args
				}
				sb.WriteString(highlightStyle.Render(line) + " - " + mutedStyle.Render(cmd.Description) + "\n")
			}
			return sb.String()
		}},
		{Name: "pause", Description: "Pause/resume scanning", Args: "", Handler: func(m *Model, args string) string {
			m.Engine.Config.RLock()
			p := m.Engine.Config.IsPaused
			m.Engine.Config.RUnlock()
			m.Engine.SetPaused(!p)
			if p {
				return statusStyle.Render("[*] Scan resumed")
			}
			return orangeStyle.Render("[*] Scan paused")
		}},
		{Name: "threads", Description: "Set worker count", Args: "<n>", Handler: func(m *Model, args string) string {
			n, err := strconv.Atoi(strings.TrimSpace(args))
			if err != nil || n < 1 {
				return errorStyle.Render("Usage: :threads <number>")
			}
			m.Engine.SetWorkerCount(n)
			return statusStyle.Render(fmt.Sprintf("[*] Workers set to %d", n))
		}},
		{Name: "delay", Description: "Set delay (ms)", Args: "<ms>", Handler: func(m *Model, args string) string {
			ms, err := strconv.Atoi(strings.TrimSpace(args))
			if err != nil || ms < 0 {
				return errorStyle.Render("Usage: :delay <milliseconds>")
			}
			m.Engine.SetDelay(time.Duration(ms) * time.Millisecond)
			return statusStyle.Render(fmt.Sprintf("[*] Delay set to %dms", ms))
		}},
		{Name: "rps", Description: "Set requests per second (0=unlimited)", Args: "<n>", Handler: func(m *Model, args string) string {
			n, err := strconv.Atoi(strings.TrimSpace(args))
			if err != nil || n < 0 {
				return errorStyle.Render("Usage: :rps <number>")
			}
			m.Engine.SetRPS(n)
			if n == 0 {
				return statusStyle.Render("[*] RPS: unlimited")
			}
			return statusStyle.Render(fmt.Sprintf("[*] RPS limit set to %d", n))
		}},
		{Name: "ua", Description: "Change User-Agent", Args: "<string>", Handler: func(m *Model, args string) string {
			if strings.TrimSpace(args) == "" {
				return errorStyle.Render("Usage: :ua <user-agent>")
			}
			m.Engine.UpdateUserAgent(strings.TrimSpace(args))
			return statusStyle.Render("[*] User-Agent updated")
		}},
		{Name: "header", Description: "Add header (key:value)", Args: "<key:value>", Handler: func(m *Model, args string) string {
			parts := strings.SplitN(strings.TrimSpace(args), ":", 2)
			if len(parts) != 2 {
				return errorStyle.Render("Usage: :header Key:Value")
			}
			m.Engine.AddHeader(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
			return statusStyle.Render(fmt.Sprintf("[*] Header set: %s: %s", parts[0], parts[1]))
		}},
		{Name: "rmheader", Description: "Remove header", Args: "<key>", Handler: func(m *Model, args string) string {
			if args == "" {
				return errorStyle.Render("Usage: :rmheader <key>")
			}
			m.Engine.RemoveHeader(strings.TrimSpace(args))
			return statusStyle.Render(fmt.Sprintf("[*] Header removed: %s", args))
		}},
		{Name: "addcode", Description: "Add match status code", Args: "<code>", Handler: func(m *Model, args string) string {
			code, err := strconv.Atoi(strings.TrimSpace(args))
			if err != nil {
				return errorStyle.Render("Usage: :addcode <code>")
			}
			m.Engine.AddMatchCode(code)
			return statusStyle.Render(fmt.Sprintf("[*] Added match code: %d", code))
		}},
		{Name: "rmcode", Description: "Remove match status code", Args: "<code>", Handler: func(m *Model, args string) string {
			code, err := strconv.Atoi(strings.TrimSpace(args))
			if err != nil {
				return errorStyle.Render("Usage: :rmcode <code>")
			}
			m.Engine.RemoveMatchCode(code)
			return statusStyle.Render(fmt.Sprintf("[*] Removed match code: %d", code))
		}},
		{Name: "filter", Description: "Add filtered size", Args: "<size>", Handler: func(m *Model, args string) string {
			size, err := strconv.Atoi(strings.TrimSpace(args))
			if err != nil {
				return errorStyle.Render("Usage: :filter <size>")
			}
			m.Engine.AddFilterSize(size)
			return statusStyle.Render(fmt.Sprintf("[*] Filtering size: %d", size))
		}},
		{Name: "rmfilter", Description: "Remove filtered size", Args: "<size>", Handler: func(m *Model, args string) string {
			size, err := strconv.Atoi(strings.TrimSpace(args))
			if err != nil {
				return errorStyle.Render("Usage: :rmfilter <size>")
			}
			m.Engine.RemoveFilterSize(size)
			return statusStyle.Render(fmt.Sprintf("[*] Removed filter size: %d", size))
		}},
		{Name: "addext", Description: "Add extension", Args: "<ext>", Handler: func(m *Model, args string) string {
			ext := strings.TrimSpace(args)
			if ext == "" {
				return errorStyle.Render("Usage: :addext <extension>")
			}
			m.Engine.AddExtension(ext)
			return statusStyle.Render(fmt.Sprintf("[*] Added extension: %s", ext))
		}},
		{Name: "rmext", Description: "Remove extension", Args: "<ext>", Handler: func(m *Model, args string) string {
			ext := strings.TrimSpace(args)
			if ext == "" {
				return errorStyle.Render("Usage: :rmext <extension>")
			}
			m.Engine.RemoveExtension(ext)
			return statusStyle.Render(fmt.Sprintf("[*] Removed extension: %s", ext))
		}},
		{Name: "mutate", Description: "Toggle mutation", Args: "", Handler: func(m *Model, args string) string {
			m.Engine.Config.RLock()
			current := m.Engine.Config.Mutate
			m.Engine.Config.RUnlock()
			m.Engine.SetMutation(!current)
			if !current {
				return statusStyle.Render("[*] Mutation enabled")
			}
			return orangeStyle.Render("[*] Mutation disabled")
		}},
		{Name: "wordlist", Description: "Change wordlist", Args: "<path>", Handler: func(m *Model, args string) string {
			path := strings.TrimSpace(args)
			if path == "" {
				return errorStyle.Render("Usage: :wordlist <path>")
			}
			if _, err := os.Stat(path); err != nil {
				return errorStyle.Render(fmt.Sprintf("Error: %v", err))
			}
			m.Engine.Config.Lock()
			m.Engine.Config.WordlistPath = path
			m.Engine.Config.Unlock()
			m.Engine.RefreshConfigSnapshot()
			return statusStyle.Render(fmt.Sprintf("[*] Wordlist queued: %s (run :restart to apply)", path))
		}},
		{Name: "changeurl", Description: "Change target URL", Args: "<url>", Handler: func(m *Model, args string) string {
			targetURL := strings.TrimSpace(args)
			if targetURL == "" {
				return errorStyle.Render("Usage: :changeurl <url>")
			}
			parsed, err := url.Parse(targetURL)
			if err != nil {
				return errorStyle.Render(fmt.Sprintf("Error: invalid target URL: %v", err))
			}
			if parsed.Scheme == "" || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
				return errorStyle.Render("Error: invalid target URL: must be http(s)://host")
			}
			m.pendingTarget = targetURL
			return statusStyle.Render(fmt.Sprintf("[*] Target URL queued: %s (run :restart to apply)", targetURL))
		}},
		{Name: "methods", Description: "Set HTTP methods (comma-separated, empty to clear)", Args: "<methods>", Handler: func(m *Model, args string) string {
			arg := strings.TrimSpace(args)
			if arg == "" {
				m.Engine.Config.Lock()
				m.Engine.Config.Methods = []string{}
				m.Engine.Config.Unlock()
				m.Engine.RefreshConfigSnapshot()
				return statusStyle.Render("[*] Methods cleared (run :restart to apply)")
			}
			parts := strings.Split(arg, ",")
			methods := make([]string, 0, len(parts))
			for _, p := range parts {
				p = strings.ToUpper(strings.TrimSpace(p))
				if p == "" {
					continue
				}
				switch p {
				case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE":
					methods = append(methods, p)
				default:
					return errorStyle.Render(fmt.Sprintf("Unsupported HTTP method: %s", p))
				}
			}
			m.Engine.Config.Lock()
			m.Engine.Config.Methods = methods
			m.Engine.Config.Unlock()
			m.Engine.RefreshConfigSnapshot()
			return statusStyle.Render(fmt.Sprintf("[*] Methods queued: %s (run :restart to apply)", strings.Join(methods, ",")))
		}},
		{Name: "restart", Description: "Restart scan", Args: "", Handler: func(m *Model, args string) string {
			if m.pendingTarget != "" {
				if err := m.Engine.SetTarget(m.pendingTarget); err != nil {
					return errorStyle.Render(fmt.Sprintf("Error applying pending target URL: %v", err))
				}
				m.pendingTarget = ""
			}
			if err := m.Engine.Restart(); err != nil {
				return errorStyle.Render(fmt.Sprintf("Error: %v", err))
			}
			m.clearScanLogs()
			return statusStyle.Render("[*] Scan restarted")
		}},
		{Name: "config", Description: "Show current config", Args: "", Handler: func(m *Model, args string) string {
			m.Engine.Config.RLock()
			ua := m.Engine.Config.UserAgent
			delay := m.Engine.Config.Delay
			headers := make(map[string]string, len(m.Engine.Config.Headers))
			for k, v := range m.Engine.Config.Headers {
				headers[k] = v
			}

			filters := make([]int, 0, len(m.Engine.Config.FilterSizes))
			for size := range m.Engine.Config.FilterSizes {
				filters = append(filters, size)
			}

			matchCodes := make([]int, 0, len(m.Engine.Config.MatchCodes))
			for code := range m.Engine.Config.MatchCodes {
				matchCodes = append(matchCodes, code)
			}

			exts := make([]string, len(m.Engine.Config.Extensions))
			copy(exts, m.Engine.Config.Extensions)
			methods := make([]string, len(m.Engine.Config.Methods))
			copy(methods, m.Engine.Config.Methods)

			workers := m.Engine.Config.MaxWorkers
			recursive := m.Engine.Config.Recursive
			maxDepth := m.Engine.Config.MaxDepth
			mutate := m.Engine.Config.Mutate
			smartAPI := m.Engine.Config.SmartAPI
			followRedir := m.Engine.Config.FollowRedirects
			maxRedirects := m.Engine.Config.MaxRedirects
			matchRegex := m.Engine.Config.MatchRegex
			filterRegex := m.Engine.Config.FilterRegex
			filterWords := m.Engine.Config.FilterWords
			filterLines := m.Engine.Config.FilterLines
			matchWords := m.Engine.Config.MatchWords
			matchLines := m.Engine.Config.MatchLines
			body := m.Engine.Config.RequestBody
			wordlist := m.Engine.Config.WordlistPath
			outputFmt := m.Engine.Config.OutputFormat
			outputFile := m.Engine.Config.OutputFile
			filterDurMin := m.Engine.Config.FilterRTMin
			filterDurMax := m.Engine.Config.FilterRTMax
			proxyOut := m.Engine.Config.ProxyOut
			timeout := m.Engine.Config.Timeout
			insecure := m.Engine.Config.Insecure
			autoFilterThreshold := m.Engine.Config.AutoFilterThreshold
			maxRetries := m.Engine.Config.MaxRetries
			saveRaw := m.Engine.Config.SaveRaw
			m.Engine.Config.RUnlock()

			sort.Ints(filters)
			sort.Ints(matchCodes)

			headerKeys := make([]string, 0, len(headers))
			for k := range headers {
				headerKeys = append(headerKeys, k)
			}
			sort.Strings(headerKeys)

			intsToCSV := func(nums []int) string {
				parts := make([]string, len(nums))
				for i, n := range nums {
					parts[i] = strconv.Itoa(n)
				}
				return strings.Join(parts, ",")
			}

			targetSwitch := m.Engine.BaseURL()
			target := targetSwitch
			if m.pendingTarget != "" {
				targetSwitch = m.pendingTarget
				target = m.pendingTarget + " (pending restart)"
			}
			wrapWidth := m.cmdViewport.Width - 6
			if wrapWidth < 40 {
				wrapWidth = 80
			}

			var sb strings.Builder
			writeLine := func(line string) {
				sb.WriteString(wrapText(line, wrapWidth))
				sb.WriteString("\n")
			}

			writeLine("=== Current Config ===")
			writeLine(fmt.Sprintf("Target: %s", target))
			if wordlist != "" {
				writeLine(fmt.Sprintf("Wordlist: %s", wordlist))
			}
			writeLine(fmt.Sprintf("Workers: %d", workers))
			writeLine(fmt.Sprintf("Delay: %s", delay))
			writeLine(fmt.Sprintf("UA: %s", ua))
			if len(exts) > 0 {
				writeLine(fmt.Sprintf("Extensions: %s", strings.Join(exts, ",")))
			}
			if len(methods) > 0 {
				writeLine(fmt.Sprintf("Methods: %s", strings.Join(methods, ",")))
			}
			if len(matchCodes) > 0 {
				writeLine(fmt.Sprintf("MatchCodes: %s", intsToCSV(matchCodes)))
			}
			if len(filters) > 0 {
				writeLine(fmt.Sprintf("FilterSizes: %s", intsToCSV(filters)))
			}
			if len(headerKeys) > 0 {
				writeLine("Headers:")
				for _, k := range headerKeys {
					writeLine(fmt.Sprintf("  - %s: %s", k, headers[k]))
				}
			}
			writeLine(fmt.Sprintf("Recursive: %v (depth: %d)", recursive, maxDepth))
			writeLine(fmt.Sprintf("Mutate: %v", mutate))
			writeLine(fmt.Sprintf("Follow: %v (max-redirects: %d)", followRedir, maxRedirects))
			writeLine(fmt.Sprintf("OutputFmt: %s", outputFmt))
			if outputFile != "" {
				writeLine(fmt.Sprintf("OutputFile: %s", outputFile))
			}
			writeLine(fmt.Sprintf("Timeout: %s", timeout))
			writeLine(fmt.Sprintf("InsecureTLS: %v", insecure))
			writeLine(fmt.Sprintf("SmartAPI: %v", smartAPI))
			writeLine(fmt.Sprintf("AutoFilterThreshold: %d", autoFilterThreshold))
			writeLine(fmt.Sprintf("Retries: %d", maxRetries))
			if matchRegex != "" {
				writeLine(fmt.Sprintf("MatchRegex: %s", matchRegex))
			}
			if filterRegex != "" {
				writeLine(fmt.Sprintf("FilterRegex: %s", filterRegex))
			}
			if filterWords >= 0 {
				writeLine(fmt.Sprintf("FilterWords: %d", filterWords))
			}
			if filterLines >= 0 {
				writeLine(fmt.Sprintf("FilterLines: %d", filterLines))
			}
			if matchWords >= 0 {
				writeLine(fmt.Sprintf("MatchWords: %d", matchWords))
			}
			if matchLines >= 0 {
				writeLine(fmt.Sprintf("MatchLines: %d", matchLines))
			}
			if filterDurMin > 0 {
				writeLine(fmt.Sprintf("RTmin: %s", filterDurMin))
			}
			if filterDurMax > 0 {
				writeLine(fmt.Sprintf("RTmax: %s", filterDurMax))
			}
			if proxyOut != "" {
				writeLine(fmt.Sprintf("ProxyOut: %s", proxyOut))
			}
			if body != "" {
				writeLine(fmt.Sprintf("Body: %s", body))
			}

			writeLine("")
			writeLine("CLI switches (effective now):")
			writeLine(fmt.Sprintf("  -u %s", targetSwitch))
			if wordlist != "" {
				writeLine(fmt.Sprintf("  -w %s", wordlist))
			}
			if workers != 50 {
				writeLine(fmt.Sprintf("  -t %d", workers))
			}
			if delay > 0 {
				writeLine(fmt.Sprintf("  -delay %s", delay))
			}
			if ua != "" {
				writeLine(fmt.Sprintf("  -ua %q", ua))
			}
			for _, k := range headerKeys {
				if strings.EqualFold(k, "Cookie") {
					writeLine(fmt.Sprintf("  -b %q", headers[k]))
				} else {
					writeLine(fmt.Sprintf("  -h %q", fmt.Sprintf("%s: %s", k, headers[k])))
				}
			}
			if len(exts) > 0 {
				writeLine(fmt.Sprintf("  -e %s", strings.Join(exts, ",")))
			}
			if len(matchCodes) > 0 {
				writeLine(fmt.Sprintf("  -mc %s", intsToCSV(matchCodes)))
			}
			if len(filters) > 0 {
				writeLine(fmt.Sprintf("  -fs %s", intsToCSV(filters)))
			}
			if mutate {
				writeLine("  -mutate")
			}
			if recursive {
				writeLine("  -r")
			}
			if maxDepth != 3 {
				writeLine(fmt.Sprintf("  -depth %d", maxDepth))
			}
			if len(methods) > 0 {
				writeLine(fmt.Sprintf("  -m %s", strings.Join(methods, ",")))
			}
			if smartAPI {
				writeLine("  -smart-api")
			}
			if body != "" {
				writeLine(fmt.Sprintf("  -d %q", body))
			}
			if followRedir {
				writeLine("  -follow")
			}
			if maxRedirects != 5 {
				writeLine(fmt.Sprintf("  -max-redirects %d", maxRedirects))
			}
			if matchRegex != "" {
				writeLine(fmt.Sprintf("  -mr %q", matchRegex))
			}
			if filterRegex != "" {
				writeLine(fmt.Sprintf("  -fr %q", filterRegex))
			}
			if filterWords >= 0 {
				writeLine(fmt.Sprintf("  -fw %d", filterWords))
			}
			if filterLines >= 0 {
				writeLine(fmt.Sprintf("  -fl %d", filterLines))
			}
			if matchWords >= 0 {
				writeLine(fmt.Sprintf("  -mw %d", matchWords))
			}
			if matchLines >= 0 {
				writeLine(fmt.Sprintf("  -ml %d", matchLines))
			}
			if filterDurMin > 0 {
				writeLine(fmt.Sprintf("  -rt-min %s", filterDurMin))
			}
			if filterDurMax > 0 {
				writeLine(fmt.Sprintf("  -rt-max %s", filterDurMax))
			}
			if outputFmt != "" {
				writeLine(fmt.Sprintf("  -of %s", outputFmt))
			}
			if outputFile != "" {
				writeLine(fmt.Sprintf("  -o %s", outputFile))
			}
			if timeout > 0 {
				writeLine(fmt.Sprintf("  -timeout %s", timeout))
			}
			if insecure {
				writeLine("  -k")
			}
			if saveRaw {
				writeLine("  --save-raw")
			}
			if proxyOut != "" {
				writeLine(fmt.Sprintf("  -proxy-out %s", proxyOut))
			}
			if autoFilterThreshold != engine.DefaultAutoFilterThreshold {
				writeLine(fmt.Sprintf("  -af %d", autoFilterThreshold))
			}
			if maxRetries > 0 {
				writeLine(fmt.Sprintf("  -retry %d", maxRetries))
			}

			return strings.TrimRight(sb.String(), "\n")
		}},
		{Name: "mr", Description: "Set match regex", Args: "<pattern>", Handler: func(m *Model, args string) string {
			pattern := strings.TrimSpace(args)
			if err := m.Engine.SetMatchRegex(pattern); err != nil {
				return errorStyle.Render(fmt.Sprintf("Invalid regex: %v", err))
			}
			if pattern == "" {
				return statusStyle.Render("[*] Match regex cleared")
			}
			return statusStyle.Render(fmt.Sprintf("[*] Match regex set: %s", pattern))
		}},
		{Name: "fr", Description: "Set filter regex", Args: "<pattern>", Handler: func(m *Model, args string) string {
			pattern := strings.TrimSpace(args)
			if err := m.Engine.SetFilterRegex(pattern); err != nil {
				return errorStyle.Render(fmt.Sprintf("Invalid regex: %v", err))
			}
			if pattern == "" {
				return statusStyle.Render("[*] Filter regex cleared")
			}
			return statusStyle.Render(fmt.Sprintf("[*] Filter regex set: %s", pattern))
		}},
		{Name: "fw", Description: "Filter by word count (-1 = off)", Args: "<count>", Handler: func(m *Model, args string) string {
			n, err := strconv.Atoi(strings.TrimSpace(args))
			if err != nil {
				return errorStyle.Render("Usage: :fw <number>")
			}
			m.Engine.Config.Lock()
			m.Engine.Config.FilterWords = n
			m.Engine.Config.Unlock()
			m.Engine.RefreshConfigSnapshot()
			if n < 0 {
				return statusStyle.Render("[*] Word filter disabled")
			}
			return statusStyle.Render(fmt.Sprintf("[*] Filter words: %d", n))
		}},
		{Name: "fl", Description: "Filter by line count (-1 = off)", Args: "<count>", Handler: func(m *Model, args string) string {
			n, err := strconv.Atoi(strings.TrimSpace(args))
			if err != nil {
				return errorStyle.Render("Usage: :fl <number>")
			}
			m.Engine.Config.Lock()
			m.Engine.Config.FilterLines = n
			m.Engine.Config.Unlock()
			m.Engine.RefreshConfigSnapshot()
			if n < 0 {
				return statusStyle.Render("[*] Line filter disabled")
			}
			return statusStyle.Render(fmt.Sprintf("[*] Filter lines: %d", n))
		}},
		{Name: "follow", Description: "Toggle redirect following", Args: "", Handler: func(m *Model, args string) string {
			m.Engine.Config.RLock()
			current := m.Engine.Config.FollowRedirects
			m.Engine.Config.RUnlock()
			m.Engine.SetFollowRedirects(!current)
			if !current {
				return statusStyle.Render("[*] Follow redirects enabled")
			}
			return orangeStyle.Render("[*] Follow redirects disabled")
		}},
		{Name: "saveraw", Description: "Enable/disable saving raw request/response (on|off)", Args: "<on|off>", Handler: func(m *Model, args string) string {
			arg := strings.ToLower(strings.TrimSpace(args))
			if arg == "on" || arg == "true" || arg == "1" {
				m.Engine.Config.Lock()
				m.Engine.Config.SaveRaw = true
				m.Engine.Config.Unlock()
				m.Engine.RefreshConfigSnapshot()
				return statusStyle.Render("[*] --save-raw enabled (applies to subsequent requests; run :restart to immediately reapply scanner)")
			}
			if arg == "off" || arg == "false" || arg == "0" {
				m.Engine.Config.Lock()
				m.Engine.Config.SaveRaw = false
				m.Engine.Config.Unlock()
				m.Engine.RefreshConfigSnapshot()
				return orangeStyle.Render("[*] --save-raw disabled")
			}
			return errorStyle.Render("Usage: :saveraw <on|off>")
		}},
		{Name: "body", Description: "Set request body for POST/PUT", Args: "<body>", Handler: func(m *Model, args string) string {
			m.Engine.Config.Lock()
			m.Engine.Config.RequestBody = strings.TrimSpace(args)
			m.Engine.Config.Unlock()
			m.Engine.RefreshConfigSnapshot()
			if args == "" {
				return statusStyle.Render("[*] Request body cleared")
			}
			return statusStyle.Render("[*] Request body set")
		}},
		{Name: "rtmin", Description: "Set min response time filter (e.g. 500ms, 0 = off)", Args: "<duration>", Handler: func(m *Model, args string) string {
			arg := strings.TrimSpace(args)
			if arg == "" || arg == "0" || arg == "off" {
				m.Engine.Config.Lock()
				m.Engine.Config.FilterRTMin = 0
				m.Engine.Config.Unlock()
				m.Engine.RefreshConfigSnapshot()
				return statusStyle.Render("[*] Min response time filter disabled")
			}
			d, err := time.ParseDuration(arg)
			if err != nil {
				return errorStyle.Render("Usage: :rtmin <duration> (e.g. 500ms, 1s)")
			}
			m.Engine.Config.Lock()
			m.Engine.Config.FilterRTMin = d
			m.Engine.Config.Unlock()
			m.Engine.RefreshConfigSnapshot()
			return statusStyle.Render(fmt.Sprintf("[*] Min response time filter: %s", d))
		}},
		{Name: "rtmax", Description: "Set max response time filter (e.g. 5s, 0 = off)", Args: "<duration>", Handler: func(m *Model, args string) string {
			arg := strings.TrimSpace(args)
			if arg == "" || arg == "0" || arg == "off" {
				m.Engine.Config.Lock()
				m.Engine.Config.FilterRTMax = 0
				m.Engine.Config.Unlock()
				m.Engine.RefreshConfigSnapshot()
				return statusStyle.Render("[*] Max response time filter disabled")
			}
			d, err := time.ParseDuration(arg)
			if err != nil {
				return errorStyle.Render("Usage: :rtmax <duration> (e.g. 5s, 10s)")
			}
			m.Engine.Config.Lock()
			m.Engine.Config.FilterRTMax = d
			m.Engine.Config.Unlock()
			m.Engine.RefreshConfigSnapshot()
			return statusStyle.Render(fmt.Sprintf("[*] Max response time filter: %s", d))
		}},
		{Name: "proxyout", Description: "Set proxy-out for Burp replay (empty = off)", Args: "<url>", Handler: func(m *Model, args string) string {
			addr := strings.TrimSpace(args)
			m.Engine.Config.Lock()
			m.Engine.Config.ProxyOut = addr
			if addr == "" || addr == "off" {
				m.Engine.Config.ProxyOut = ""
				m.Engine.Config.Unlock()
				m.Engine.RefreshConfigSnapshot()
				return statusStyle.Render("[*] Proxy-out disabled")
			}
			m.Engine.Config.Unlock()
			m.Engine.RefreshConfigSnapshot()
			return statusStyle.Render(fmt.Sprintf("[*] Proxy-out: %s", addr))
		}},
		{Name: "clear", Description: "Clear log output", Args: "", Handler: func(m *Model, args string) string {
			m.clearScanLogs()
			return ""
		}},
		{Name: "clearcmd", Description: "Clear command panel output", Args: "", Handler: func(m *Model, args string) string {
			m.cmdOutput = []string{}
			m.cmdViewport.SetContent("")
			return ""
		}},
	}
}

func tickCmd() tea.Cmd {
	return tea.Tick(500*time.Millisecond, func(t time.Time) tea.Msg {
		return TickMsg(t)
	})
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(tickCmd(), m.listenForResults())
}

// ResultMsg wraps a result coming from the engine.
type ResultMsg engine.Result

// listenForResults returns a command that reads from the Results channel.
func (m Model) listenForResults() tea.Cmd {
	return func() tea.Msg {
		result, ok := <-m.resultsCh
		if !ok {
			return nil
		}
		return ResultMsg(result)
	}
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		headerHeight := 6 // 5 lines of content + 1 separator
		footerHeight := 2 // 1 line of text + 1 separator
		vpHeight := m.height - headerHeight - footerHeight
		if vpHeight < 5 {
			vpHeight = 5
		}
		vpWidth := m.width - 2
		if vpWidth < 20 {
			vpWidth = 20
		}

		paneWidth := (vpWidth / 2) - 4

		if !m.ready {
			m.viewport = viewport.New(vpWidth, vpHeight)
			m.viewport.SetContent(strings.Join(m.logs, "\n"))
			m.cmdViewport = viewport.New(vpWidth, 12)
			m.cmdViewport.SetContent(strings.Join(m.cmdOutput, "\n"))

			// Detail viewports
			m.reqViewport = viewport.New(paneWidth, vpHeight-2)
			m.resViewport = viewport.New(paneWidth, vpHeight-2)

			m.ready = true
		} else {
			m.viewport.Width = vpWidth
			m.viewport.Height = vpHeight
			m.cmdViewport.Width = vpWidth
			m.cmdViewport.Height = 12

			m.reqViewport.Width = paneWidth
			m.reqViewport.Height = vpHeight - 2
			m.resViewport.Width = paneWidth
			m.resViewport.Height = vpHeight - 2
		}
		m.cmdViewport.Width = vpWidth
		m.cmdViewport.Height = 12
		m.textInput.Width = vpWidth - 7
		if m.textInput.Width < 10 {
			m.textInput.Width = 10
		}

	case TickMsg:
		m.Engine.UpdateRPS()
		currentRPS := atomic.LoadInt64(&m.Engine.CurrentRPS)
		m.rpsHistory = append(m.rpsHistory, currentRPS)
		if len(m.rpsHistory) > 30 {
			m.rpsHistory = m.rpsHistory[len(m.rpsHistory)-30:]
		}
		m.commandPulseOn = !m.commandPulseOn
		cmds = append(cmds, tickCmd())

	case ResultMsg:
		result := engine.Result(msg)
		if result.IsAutoFilter {
			msgStr := ""
			if result.Headers != nil {
				msgStr = result.Headers["Msg"]
			}
			if msgStr != "" {
				m.appendLog(orangeStyle.Render(fmt.Sprintf("[!] %s: %s", result.Path, msgStr)), nil)
			}
		} else if result.IsEagleAlert {
			m.appendLog(yellowStyle.Render(fmt.Sprintf("[EAGLE] %s changed: %d -> %d", result.Path, result.OldStatusCode, result.StatusCode)), nil)
		} else {
			m.appendLog(formatResult(result), &result)
		}
		cmds = append(cmds, m.listenForResults())

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			m.quitting = true
			return m, tea.Quit

		case "q":
			if m.state == StateDetail {
				m.state = StateList
				return m, nil
			}
			if !m.commandMode {
				m.quitting = true
				return m, tea.Quit
			}

		case ":":
			if !m.commandMode && m.state == StateList {
				m.commandMode = true
				m.state = StateCommand
				m.commandPulseOn = true
				m.textInput.SetValue("")
				m.textInput.Focus()
				m.suggestions = nil
				m.selectedSugIdx = 0
				return m, nil
			}

		case "esc":
			if m.commandMode {
				m.commandMode = false
				m.state = StateList
				m.commandPulseOn = false
				m.textInput.Blur()
				m.suggestions = nil
				return m, nil
			}
			if m.state == StateDetail {
				m.state = StateList
				return m, nil
			}

		case "enter":
			if m.commandMode {
				val := strings.TrimSpace(m.textInput.Value())
				if val != "" {
					output := m.executeCommand(val)
					if output != "" {
						m.appendCmd(output)
					}
					m.cmdHistory = append(m.cmdHistory, val)
					m.cmdHistoryIdx = len(m.cmdHistory)
				}
				m.textInput.SetValue("")
				m.suggestions = nil
				m.selectedSugIdx = 0
				m.commandMode = true
				m.state = StateCommand
				m.commandPulseOn = true
				m.textInput.Focus()
				return m, nil
			}

			if m.state == StateList && len(m.hits) > 0 {
				// We don't track selection across all logs, only hits, but we want to show the detail of the 'last' selected one.
				// However, if we implement true list selection, we would transition to state detail here
				// For now, if they press enter in list mode and have hits, let's just show the last one, or maybe we build a selection.
				if m.selectedIndex >= 0 && m.selectedIndex < len(m.logs) {
					// We need a way to map log lines back to results. Let's just enter detail mode for the last hit for simplicity if not selected properly,
					// or we implement a full selection mechanism.
					// We'll implement basic selection.
					if len(m.hits) > 0 {
						// Calculate which hit corresponds to the selected log line
						// This is tricky because logs contain non-hit messages.
						// Instead, let's make selection navigate through 'hits' directly, and just highlight the line in the text.
						m.state = StateDetail
						m.updateDetailView()
					}
				}
				return m, nil
			}

		case "up", "k":
			if m.commandMode && m.state != StateCommand && len(m.suggestions) > 0 {
				m.selectedSugIdx--
				if m.selectedSugIdx < 0 {
					m.selectedSugIdx = len(m.suggestions) - 1
				}
				return m, nil
			}
			if m.commandMode && m.state != StateCommand && len(m.cmdHistory) > 0 {
				if m.cmdHistoryIdx > 0 {
					m.cmdHistoryIdx--
					m.textInput.SetValue(m.cmdHistory[m.cmdHistoryIdx])
					m.textInput.SetCursor(len(m.textInput.Value()))
				}
				return m, nil
			}

			if m.state == StateList {
				if m.selectedIndex > 0 {
					m.selectedIndex--
					// Adjust scroll if necessary
					if m.selectedIndex < m.listScrollIdx {
						m.listScrollIdx = m.selectedIndex
					}
					m.renderListView()
				}
				return m, nil
			}
			if m.state == StateDetail {
				m.reqViewport.LineUp(1)
				m.resViewport.LineUp(1)
				return m, nil
			}
			if m.state == StateCommand {
				m.cmdViewport.LineUp(1)
				return m, nil
			}

		case "down", "j":
			if m.commandMode && m.state != StateCommand && len(m.suggestions) > 0 {
				m.selectedSugIdx++
				if m.selectedSugIdx >= len(m.suggestions) {
					m.selectedSugIdx = 0
				}
				return m, nil
			}
			if m.commandMode && m.state != StateCommand && len(m.cmdHistory) > 0 {
				if m.cmdHistoryIdx < len(m.cmdHistory)-1 {
					m.cmdHistoryIdx++
					m.textInput.SetValue(m.cmdHistory[m.cmdHistoryIdx])
					m.textInput.SetCursor(len(m.textInput.Value()))
				}
				return m, nil
			}

			if m.state == StateList {
				if m.selectedIndex < len(m.logs)-1 {
					m.selectedIndex++
					// Adjust scroll
					if m.selectedIndex >= m.listScrollIdx+m.viewport.Height {
						m.listScrollIdx++
					}
					m.renderListView()
				}
				return m, nil
			}
			if m.state == StateDetail {
				m.reqViewport.LineDown(1)
				m.resViewport.LineDown(1)
				return m, nil
			}
			if m.state == StateCommand {
				m.cmdViewport.LineDown(1)
				return m, nil
			}

		case "pagedown":
			if m.state == StateList {
				m.selectedIndex += m.viewport.Height
				if m.selectedIndex >= len(m.logs) {
					m.selectedIndex = len(m.logs) - 1
				}
				m.listScrollIdx += m.viewport.Height
				if m.listScrollIdx > len(m.logs)-m.viewport.Height {
					m.listScrollIdx = len(m.logs) - m.viewport.Height
					if m.listScrollIdx < 0 {
						m.listScrollIdx = 0
					}
				}
				m.renderListView()
			} else if m.state == StateDetail {
				m.reqViewport.ViewDown()
				m.resViewport.ViewDown()
			}
			return m, nil

		case "pageup":
			if m.state == StateList {
				m.selectedIndex -= m.viewport.Height
				if m.selectedIndex < 0 {
					m.selectedIndex = 0
				}
				m.listScrollIdx -= m.viewport.Height
				if m.listScrollIdx < 0 {
					m.listScrollIdx = 0
				}
				m.renderListView()
			} else if m.state == StateDetail {
				m.reqViewport.ViewUp()
				m.resViewport.ViewUp()
			}
			return m, nil

		case "tab":
			if m.commandMode && len(m.suggestions) > 0 {
				val := m.textInput.Value()
				if strings.HasPrefix(val, "wordlist ") {
					// Append the completion instead of replacing the whole string
					base := val
					lastSlash := strings.LastIndex(val, "/")
					if lastSlash != -1 {
						base = val[:lastSlash+1]
					} else {
						base = "wordlist "
					}

					suggestion := m.suggestions[m.selectedSugIdx]
					if strings.HasSuffix(suggestion, "/") {
						newVal := base + suggestion
						m.textInput.SetValue(newVal)
						m.textInput.SetCursor(len(newVal))
						// Trigger new completion
						m.updateSuggestions(newVal)
					} else {
						newVal := base + suggestion + " "
						m.textInput.SetValue(newVal)
						m.textInput.SetCursor(len(newVal))
						m.suggestions = nil
					}
				} else {
					newVal := m.suggestions[m.selectedSugIdx] + " "
					m.textInput.SetValue(newVal)
					m.textInput.SetCursor(len(newVal))
					m.suggestions = nil
				}
				return m, nil
			}
		}

		if m.commandMode {
			var cmd tea.Cmd
			m.textInput, cmd = m.textInput.Update(msg)
			cmds = append(cmds, cmd)

			// Autocomplete
			val := m.textInput.Value()
			m.updateSuggestions(val)

			return m, tea.Batch(cmds...)
		}

		// Non-command mode key shortcuts
		switch msg.String() {
		case "p":
			m.Engine.Config.RLock()
			p := m.Engine.Config.IsPaused
			m.Engine.Config.RUnlock()
			m.Engine.SetPaused(!p)
			if p {
				m.appendCmd(statusStyle.Render("[*] Scan resumed"))
			} else {
				m.appendCmd(orangeStyle.Render("[*] Scan paused"))
			}
		case "?":
			output := m.commands[0].Handler(&m, "")
			m.appendCmd(output)
		}
	}

	return m, tea.Batch(cmds...)
}

func wrapText(text string, width int) string {
	if width <= 0 {
		return text
	}
	var wrapped strings.Builder
	lines := strings.Split(text, "\n")
	for _, line := range lines {
		// Handle carriage returns
		line = strings.ReplaceAll(line, "\r", "")
		for len(line) > width {
			wrapped.WriteString(line[:width] + "\n")
			line = line[width:]
		}
		wrapped.WriteString(line + "\n")
	}
	return strings.TrimSuffix(wrapped.String(), "\n")
}

func (m *Model) updateDetailView() {
	if len(m.hits) == 0 {
		return
	}

	// Figure out which hit corresponds to the selected log line.
	var selectedHit *engine.Result
	if m.selectedIndex >= 0 && m.selectedIndex < len(m.logLineHits) && m.logLineHits[m.selectedIndex] != nil {
		selectedHit = m.logLineHits[m.selectedIndex]
	}

	if selectedHit == nil && m.selectedIndex >= 0 && m.selectedIndex < len(m.logs) {
		selectedText := m.logs[m.selectedIndex]
		for i := len(m.hits) - 1; i >= 0; i-- {
			// Basic heuristic: if the log line contains the path of the hit
			if strings.Contains(selectedText, m.hits[i].Path) {
				selectedHit = &m.hits[i]
				break
			}
		}
	}

	if selectedHit == nil {
		// Fallback to the last hit
		selectedHit = &m.hits[len(m.hits)-1]
	}

	reqContent := "No raw request available. Use --save-raw to include raw request/response; set follow redirects or disable body filters if using HEAD."
	if selectedHit.Request != "" {
		reqContent = selectedHit.Request
	}

	resContent := "No raw response available. Use --save-raw to include raw request/response."
	if selectedHit.Response != "" {
		resContent = selectedHit.Response
	}

	// Wrap text to viewport width to prevent horizontal overflow
	m.reqViewport.SetContent(wrapText(reqContent, m.reqViewport.Width))
	m.resViewport.SetContent(wrapText(resContent, m.resViewport.Width))

	m.reqViewport.GotoTop()
	m.resViewport.GotoTop()
}

func (m *Model) renderListView() {
	if len(m.logs) == 0 {
		m.viewport.SetContent("")
		return
	}

	var visibleLines []string
	start := m.listScrollIdx
	end := start + m.viewport.Height
	if end > len(m.logs) {
		end = len(m.logs)
	}

	for i := start; i < end; i++ {
		line := m.logs[i]

		var lineHit *engine.Result
		if i < len(m.logLineHits) {
			lineHit = m.logLineHits[i]
		}

		if i == m.selectedIndex {
			selectedRow := fmt.Sprintf("▶ %s %s", severitySymbol(lineHit), stripANSI(line))
			visibleLines = append(visibleLines, selectedRowStyle.Width(m.viewport.Width).Render(selectedRow))
			continue
		}

		cursor := severityNeutralStyle.Render(" ")
		severity := renderSeverityMarker(lineHit)
		visibleLines = append(visibleLines, fmt.Sprintf("%s %s %s", cursor, severity, line))
	}

	m.viewport.SetContent(strings.Join(visibleLines, "\n"))
}

func (m *Model) updateSuggestions(val string) {
	m.suggestions = nil
	if val == "" {
		return
	}

	if strings.HasPrefix(val, "wordlist ") {
		path := strings.TrimPrefix(val, "wordlist ")
		dir := "."
		base := path

		lastSlash := strings.LastIndex(path, "/")
		if lastSlash != -1 {
			dir = path[:lastSlash]
			base = path[lastSlash+1:]
			if dir == "" {
				dir = "/"
			}
		}

		entries, err := os.ReadDir(dir)
		if err == nil {
			for _, entry := range entries {
				name := entry.Name()
				if strings.HasPrefix(name, base) {
					if entry.IsDir() {
						m.suggestions = append(m.suggestions, name+"/")
					} else {
						m.suggestions = append(m.suggestions, name)
					}
				}
			}
		}
		m.selectedSugIdx = 0
		return
	}

	for _, c := range m.commands {
		if strings.HasPrefix(c.Name, val) {
			m.suggestions = append(m.suggestions, c.Name)
		}
	}
	m.selectedSugIdx = 0
}

func (m *Model) clearScanLogs() {
	m.logs = []string{}
	m.logLineHits = []*engine.Result{}
	m.hits = []engine.Result{}
	m.viewport.SetContent("")
	m.selectedIndex = 0
	m.listScrollIdx = 0
}

func (m *Model) appendLog(text string, hit *engine.Result) {
	if text == "" {
		return
	}
	m.logs = append(m.logs, text)
	if hit != nil {
		m.hits = append(m.hits, *hit)
		hitCopy := *hit
		m.logLineHits = append(m.logLineHits, &hitCopy)
	} else {
		m.logLineHits = append(m.logLineHits, nil)
	}

	// Auto-scroll to bottom if we are at the bottom
	if m.selectedIndex >= len(m.logs)-2 {
		m.selectedIndex = len(m.logs) - 1
		m.listScrollIdx = len(m.logs) - m.viewport.Height
		if m.listScrollIdx < 0 {
			m.listScrollIdx = 0
		}
	}

	m.renderListView()
	m.viewport.GotoBottom()
}

func (m *Model) appendCmd(text string) {
	if text == "" {
		return
	}
	for _, line := range strings.Split(text, "\n") {
		if line != "" {
			m.cmdOutput = append(m.cmdOutput, line)
		}
	}
	m.cmdViewport.SetContent(strings.Join(m.cmdOutput, "\n"))
	m.cmdViewport.GotoBottom()
}

// executeCommand parses and runs a TUI command.
func (m *Model) executeCommand(input string) string {
	parts := strings.SplitN(input, " ", 2)
	name := strings.ToLower(parts[0])
	args := ""
	if len(parts) > 1 {
		args = parts[1]
	}

	for _, cmd := range m.commands {
		if cmd.Name == name {
			return cmd.Handler(m, args)
		}
	}
	return errorStyle.Render(fmt.Sprintf("Unknown command: %s (type :help for list)", name))
}

// formatResult formats a result for display.
func formatResult(r engine.Result) string {
	methodStr := r.Method
	if methodStr == "" {
		methodStr = "GET"
	}

	statusColor := statusStyle
	switch {
	case r.StatusCode >= 200 && r.StatusCode < 300:
		statusColor = lipgloss.NewStyle().Foreground(DraculaGreen)
	case r.StatusCode >= 300 && r.StatusCode < 400:
		statusColor = lipgloss.NewStyle().Foreground(DraculaCyan)
	case r.StatusCode == 403:
		statusColor = lipgloss.NewStyle().Foreground(DraculaOrange)
	case r.StatusCode >= 400 && r.StatusCode < 500:
		statusColor = lipgloss.NewStyle().Foreground(DraculaYellow)
	case r.StatusCode >= 500:
		statusColor = lipgloss.NewStyle().Foreground(DraculaRed)
	}

	extras := ""
	if r.StatusCode == 403 && r.Forbidden403Type != "" {
		forbidden403Style := mutedStyle
		switch r.Forbidden403Type {
		case "CF_WAF_BLOCK":
			forbidden403Style = lipgloss.NewStyle().Foreground(DraculaRed)
		case "CF_ADMIN_403":
			forbidden403Style = lipgloss.NewStyle().Foreground(DraculaOrange)
		case "NGINX_403":
			forbidden403Style = lipgloss.NewStyle().Foreground(DraculaCyan)
		case "GENERIC_403":
			forbidden403Style = mutedStyle
		}
		extras += forbidden403Style.Render(fmt.Sprintf(" [%s]", r.Forbidden403Type))
	}
	if r.Redirect != "" {
		extras += mutedStyle.Render(fmt.Sprintf(" -> %s", r.Redirect))
	}
	if val, ok := r.Headers["Server"]; ok {
		extras += mutedStyle.Render(fmt.Sprintf(" [Server: %s]", val))
	}
	if val, ok := r.Headers["X-Powered-By"]; ok {
		extras += mutedStyle.Render(fmt.Sprintf(" [X-Powered-By: %s]", val))
	}
	if r.ContentType != "" {
		extras += mutedStyle.Render(fmt.Sprintf(" [%s]", r.ContentType))
	}
	if r.Duration > 0 {
		extras += mutedStyle.Render(fmt.Sprintf(" [%s]", r.Duration.Round(time.Millisecond)))
	}

	return fmt.Sprintf("%s %s %s %s %s %s%s",
		statusColor.Render(fmt.Sprintf("[%d]", r.StatusCode)),
		pinkStyle.Render(methodStr),
		highlightStyle.Render(r.Path),
		mutedStyle.Render(fmt.Sprintf("(Size:%d", r.Size)),
		mutedStyle.Render(fmt.Sprintf("W:%d L:%d)", r.Words, r.Lines)),
		extras,
		"",
	)
}

func (m Model) View() string {
	if m.quitting {
		return "\n  " + mutedStyle.Render("DirFuzz finished. Goodbye!") + "\n"
	}

	if !m.ready {
		return "Initializing..."
	}

	// Header
	elapsed := time.Since(m.startTime).Round(time.Second)
	total := atomic.LoadInt64(&m.Engine.TotalLines)
	processed := atomic.LoadInt64(&m.Engine.ProcessedLines)
	rps := atomic.LoadInt64(&m.Engine.CurrentRPS)
	queueSize := m.Engine.QueueSize()
	count200 := atomic.LoadInt64(&m.Engine.Count200)
	count403 := atomic.LoadInt64(&m.Engine.Count403)
	count404 := atomic.LoadInt64(&m.Engine.Count404)
	count429 := atomic.LoadInt64(&m.Engine.Count429)
	count500 := atomic.LoadInt64(&m.Engine.Count500)
	connErr := atomic.LoadInt64(&m.Engine.CountConnErr)

	m.Engine.Config.RLock()
	paused := m.Engine.Config.IsPaused
	workers := m.Engine.Config.MaxWorkers
	delay := m.Engine.Config.Delay
	m.Engine.Config.RUnlock()

	progressPct := float64(0)
	if total > 0 {
		progressPct = float64(processed) / float64(total) * 100
	}

	// Build progress bar
	barWidth := 30
	if m.width > 60 {
		barWidth = m.width / 4
	}
	bar := renderProgressBar(barWidth, progressPct)

	pauseBanner := ""
	if paused {
		borderColor := DraculaOrange
		textColor := DraculaYellow
		if m.commandPulseOn {
			borderColor = DraculaYellow
			textColor = DraculaOrange
		}

		bannerWidth := m.width - 2
		if bannerWidth < 20 {
			bannerWidth = 20
		}

		bannerStyle := lipgloss.NewStyle().
			Bold(true).
			Foreground(textColor).
			Border(lipgloss.RoundedBorder()).
			BorderForeground(borderColor).
			Align(lipgloss.Center)

		pauseBanner = bannerStyle.Width(bannerWidth).Render("PAUSED - Press 'p' or :pause to resume")
	}

	tuiDropped := atomic.LoadInt64(&m.Engine.TUIDropped)
	droppedStr := ""
	if tuiDropped > 0 {
		droppedStr = " " + errorStyle.Render(fmt.Sprintf("⚠ TUI-dropped:%d", tuiDropped))
	}

	statsLine := strings.Join([]string{
		renderStatusBadge(badge2xxStyle, "✓", "2xx", count200),
		renderStatusBadge(badge403Style, "⛔", "403", count403),
		renderStatusBadge(badge404Style, "❓", "404", count404),
		renderStatusBadge(badge429Style, "🐢", "429", count429),
		renderStatusBadge(badge5xxStyle, "💥", "5xx", count500),
		renderStatusBadge(badgeErrStyle, "⚠", "Err", connErr),
	}, " ") + droppedStr
	rpsSparkline := highlightStyle.Render(renderSparkline(m.rpsHistory, 10))

	headerLines := []string{
		fmt.Sprintf("%s %s", titleStyle.Render(" 🦇 DirFuzz "), highlightStyle.Render(m.Engine.BaseURL())),
	}
	progressPrefix := separatorStyle.Render("· ")
	headerLines = append(headerLines,
		fmt.Sprintf("  %s", statsLine),
		fmt.Sprintf("  %sProgress: %s %s  |  RPS: %s %s  |  Queue: %s",
			progressPrefix,
			bar,
			highlightStyle.Render(fmt.Sprintf("%.1f%%", progressPct)),
			pinkStyle.Render(fmt.Sprintf("%d", rps)),
			rpsSparkline,
			mutedStyle.Render(fmt.Sprintf("%d", queueSize)),
		),
		fmt.Sprintf("  Workers: %s  Delay: %s  Elapsed: %s",
			highlightStyle.Render(fmt.Sprintf("%d", workers)),
			mutedStyle.Render(delay.String()),
			mutedStyle.Render(elapsed.String()),
		),
		fmt.Sprintf("  %s", mutedStyle.Render(fmt.Sprintf("(%d/%d)", processed, total))),
	)
	if pauseBanner != "" {
		headerLines = append(headerLines, pauseBanner)
	}
	header := strings.Join(headerLines, "\n") + "\n"
	sep := separatorStyle.Render(strings.Repeat("─", m.width))
	header = header + sep

	var mainContent string

	if m.state == StateList {
		mainContent = m.viewport.View()
	} else if m.state == StateDetail {
		reqHeader := renderPaneHeader(requestPaneHeaderStyle, m.reqViewport.Width, "Request")
		resHeader := renderPaneHeader(responsePaneHeaderStyle, m.resViewport.Width, "Response")

		reqPane := paneStyle.Width(m.reqViewport.Width + 2).Height(m.reqViewport.Height + 2).Render(
			lipgloss.JoinVertical(lipgloss.Top,
				reqHeader,
				m.reqViewport.View(),
			),
		)
		resPane := paneStyle.Width(m.resViewport.Width + 2).Height(m.resViewport.Height + 2).Render(
			lipgloss.JoinVertical(lipgloss.Top,
				resHeader,
				m.resViewport.View(),
			),
		)
		mainContent = lipgloss.JoinHorizontal(lipgloss.Top, reqPane, resPane)
	} else if m.state == StateCommand {
		resultsHeight := m.height - lipgloss.Height(header) - 16 // 16 = cmd panel
		if resultsHeight < 3 {
			resultsHeight = 3
		}
		frozenVp := lipgloss.NewStyle().Height(resultsHeight).Render(m.viewport.View())
		cmdInnerWidth := m.width - 6
		if cmdInnerWidth < 8 {
			cmdInnerWidth = 8
		}

		panelBorderColor := DraculaCyan
		if !m.commandPulseOn {
			panelBorderColor = DraculaPurple
		}

		cmdPanelStyle := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(panelBorderColor).
			Width(m.width-2).
			Height(12).
			Padding(0, 1)

		cmdTitle := pinkStyle.Render(" ⚡ Command Panel ") +
			mutedStyle.Render(" (Esc to close, ':help' for commands) ")
		promptLine := cmdPromptStyle.Render(":") + m.textInput.View()

		suggestionsBlock := ""
		if len(m.suggestions) > 0 {
			dropdownWidth := suggestionDropdownWidth(m.suggestions, cmdInnerWidth)
			suggestionsBlock = renderSuggestionDropdown(m.suggestions, m.selectedSugIdx, dropdownWidth)
		}

		cmdSections := []string{
			cmdTitle,
			m.cmdViewport.View(),
			separatorStyle.Render(strings.Repeat("─", cmdInnerWidth)),
		}
		if suggestionsBlock != "" {
			cmdSections = append(cmdSections, suggestionsBlock)
		}
		cmdSections = append(cmdSections, promptLine)

		cmdContent := lipgloss.JoinVertical(lipgloss.Top, cmdSections...)
		cmdPanel := cmdPanelStyle.Render(cmdContent)

		mainContent = lipgloss.JoinVertical(lipgloss.Top, frozenVp, cmdPanel)
	}

	// Footer
	var footer string
	if m.commandMode && m.state != StateCommand {
		cmdLine := cmdPromptStyle.Render(":") + m.textInput.View()

		// Show suggestions
		if len(m.suggestions) > 0 {
			dropdownWidth := suggestionDropdownWidth(m.suggestions, m.width-2)
			cmdLine += "\n" + renderSuggestionDropdown(m.suggestions, m.selectedSugIdx, dropdownWidth)
		}

		footer = cmdLine
	} else {
		footerBarStyle := lipgloss.NewStyle().
			Foreground(DraculaCyan).
			Bold(true).
			Width(m.width).
			PaddingLeft(2)
		if m.state == StateCommand {
			footer = footerBarStyle.Render("Esc: close panel | Enter: run command | Up/Down: scroll output")
		} else if m.state == StateDetail {
			footer = footerBarStyle.Render("Press 'Esc' or 'q' to return to list | Up/Down to scroll")
		} else {
			footer = footerBarStyle.Render("Press ':' for commands | 'p' to pause | '?' for help | 'q' to quit | 'Enter' on hit to view")
		}
	}
	footerSep := separatorStyle.Render(strings.Repeat("─", m.width))
	footer = footerSep + "\n" + footer

	remainingHeight := m.height - lipgloss.Height(header) - lipgloss.Height(footer)
	if remainingHeight < 1 {
		remainingHeight = 1
	}
	paddedContent := lipgloss.NewStyle().Height(remainingHeight).Render(mainContent)

	// Compose
	return lipgloss.JoinVertical(lipgloss.Top, header, paddedContent, footer)
}
