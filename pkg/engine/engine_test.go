package engine

import (
	"testing"
	"time"
)

// TestNewEngine verifies engine initialization
func TestNewEngine(t *testing.T) {
	eng := NewEngine(50, DefaultBloomFilterSize, DefaultBloomFilterFP)

	if eng == nil {
		t.Fatal("Expected non-nil engine")
	}

	if eng.numWorkers != 50 {
		t.Errorf("Expected 50 workers, got %d", eng.numWorkers)
	}

	if eng.Config.Timeout != DefaultHTTPTimeout {
		t.Errorf("Expected timeout %v, got %v", DefaultHTTPTimeout, eng.Config.Timeout)
	}

	if eng.Config.MaxRedirects != DefaultMaxRedirects {
		t.Errorf("Expected max redirects %d, got %d", DefaultMaxRedirects, eng.Config.MaxRedirects)
	}
}

// TestConfigureFilters verifies filter configuration
func TestConfigureFilters(t *testing.T) {
	eng := NewEngine(10, 1000, 0.01)

	matchCodes := []int{200, 204, 301}
	filterSizes := []int{1234, 5678}

	eng.ConfigureFilters(matchCodes, filterSizes)

	eng.Config.RLock()
	defer eng.Config.RUnlock()

	// Check match codes
	for _, code := range matchCodes {
		if !eng.Config.MatchCodes[code] {
			t.Errorf("Expected match code %d to be configured", code)
		}
	}

	// Check filter sizes
	for _, size := range filterSizes {
		if !eng.Config.FilterSizes[size] {
			t.Errorf("Expected filter size %d to be configured", size)
		}
	}
}

// TestSetMatchRegex verifies regex matching configuration
func TestSetMatchRegex(t *testing.T) {
	eng := NewEngine(10, 1000, 0.01)

	// Valid regex
	err := eng.SetMatchRegex(`"success"\s*:\s*true`)
	if err != nil {
		t.Errorf("Expected valid regex to succeed, got: %v", err)
	}

	if eng.matchRe == nil {
		t.Error("Expected matchRe to be set")
	}

	// Invalid regex
	err = eng.SetMatchRegex(`[invalid(`)
	if err == nil {
		t.Error("Expected invalid regex to fail")
	}
}

// TestSetFilterRegex verifies filter regex configuration
func TestSetFilterRegex(t *testing.T) {
	eng := NewEngine(10, 1000, 0.01)

	// Valid regex
	err := eng.SetFilterRegex(`404 Not Found`)
	if err != nil {
		t.Errorf("Expected valid regex to succeed, got: %v", err)
	}

	if eng.filterRe == nil {
		t.Error("Expected filterRe to be set")
	}

	// Clear regex
	err = eng.SetFilterRegex("")
	if err != nil {
		t.Errorf("Expected empty regex to succeed, got: %v", err)
	}

	if eng.filterRe != nil {
		t.Error("Expected filterRe to be nil after clearing")
	}
}

// TestAddRemoveFilters verifies dynamic filter modification
func TestAddRemoveFilters(t *testing.T) {
	eng := NewEngine(10, 1000, 0.01)

	// Add match code
	eng.AddMatchCode(200)
	eng.Config.RLock()
	if !eng.Config.MatchCodes[200] {
		t.Error("Expected match code 200 to be added")
	}
	eng.Config.RUnlock()

	// Remove match code
	eng.RemoveMatchCode(200)
	eng.Config.RLock()
	if eng.Config.MatchCodes[200] {
		t.Error("Expected match code 200 to be removed")
	}
	eng.Config.RUnlock()

	// Add filter size
	eng.AddFilterSize(1234)
	eng.Config.RLock()
	if !eng.Config.FilterSizes[1234] {
		t.Error("Expected filter size 1234 to be added")
	}
	eng.Config.RUnlock()

	// Remove filter size
	eng.RemoveFilterSize(1234)
	eng.Config.RLock()
	if eng.Config.FilterSizes[1234] {
		t.Error("Expected filter size 1234 to be removed")
	}
	eng.Config.RUnlock()
}

// TestSetDelay verifies delay configuration
func TestSetDelay(t *testing.T) {
	eng := NewEngine(10, 1000, 0.01)

	delay := 200 * time.Millisecond
	eng.SetDelay(delay)

	eng.Config.RLock()
	if eng.Config.Delay != delay {
		t.Errorf("Expected delay %v, got %v", delay, eng.Config.Delay)
	}
	eng.Config.RUnlock()
}

// TestSetTarget verifies target URL validation
func TestSetTarget(t *testing.T) {
	eng := NewEngine(10, 1000, 0.01)

	tests := []struct {
		url   string
		valid bool
	}{
		{"https://example.com", true},
		{"http://example.com/api", true},
		{"https://example.com/{PAYLOAD}", true},
		{"not-a-url", false},
		{"", false},
	}

	for _, tt := range tests {
		err := eng.SetTarget(tt.url)
		if tt.valid && err != nil {
			t.Errorf("Expected URL %q to be valid, got error: %v", tt.url, err)
		}
		if !tt.valid && err == nil {
			t.Errorf("Expected URL %q to be invalid", tt.url)
		}
	}
}

// TestRandomString verifies random string generation
func TestRandomString(t *testing.T) {
	lengths := []int{8, 16, 32}

	for _, length := range lengths {
		str := randomString(length)
		if len(str) != length {
			t.Errorf("Expected string length %d, got %d", length, len(str))
		}

		// Verify it contains only expected characters
		for _, ch := range str {
			if (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') {
				t.Errorf("Unexpected character in random string: %c", ch)
			}
		}
	}
}

// TestIsAPIPath verifies API path detection
func TestIsAPIPath(t *testing.T) {
	tests := []struct {
		path  string
		isAPI bool
	}{
		{"/api/users", true},
		{"/v1/data", true},
		{"/v2/endpoint", true},
		{"/rest/resource", true},
		{"/graphql", true},
		{"/admin/panel", false},
		{"/static/css", false},
		{"", false},
	}

	for _, tt := range tests {
		result := isAPIPath(tt.path)
		if result != tt.isAPI {
			t.Errorf("isAPIPath(%q) = %v, want %v", tt.path, result, tt.isAPI)
		}
	}
}
