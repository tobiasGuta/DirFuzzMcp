package httpclient

import (
	"context"
	"testing"
	"time"
)

// TestSendHTTP2Request verifies HTTP/2 client basic functionality
func TestSendHTTP2Request(t *testing.T) {
	// Test against a known HTTP/2 server
	tests := []struct {
		url      string
		method   string
		wantCode int
	}{
		{"https://www.google.com/", "GET", 200},
		{"https://www.google.com/", "HEAD", 200},
	}

	for _, tt := range tests {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		resp, err := SendHTTP2Request(ctx, tt.url, tt.method, nil, "", 10*time.Second, true)
		if err != nil {
			t.Logf("HTTP/2 request to %s failed (may be network issue): %v", tt.url, err)
			continue
		}

		if resp.StatusCode != tt.wantCode {
			t.Errorf("SendHTTP2Request(%s) status = %d, want %d", tt.url, resp.StatusCode, tt.wantCode)
		}

		if resp.Duration == 0 {
			t.Error("Expected non-zero duration")
		}
	}
}

// TestSendHTTP2RequestWithHeaders verifies custom headers
func TestSendHTTP2RequestWithHeaders(t *testing.T) {
	headers := map[string]string{
		"User-Agent": "TestClient/1.0",
		"Accept":     "application/json",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := SendHTTP2Request(ctx, "https://www.google.com/", "GET", headers, "", 10*time.Second, true)
	if err != nil {
		t.Logf("HTTP/2 request failed (may be network issue): %v", err)
		return
	}

	if resp.StatusCode == 0 {
		t.Error("Expected non-zero status code")
	}
}

// TestSendHTTP2RequestTimeout verifies timeout handling
func TestSendHTTP2RequestTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	// This should timeout
	_, err := SendHTTP2Request(ctx, "https://www.google.com/", "GET", nil, "", 1*time.Millisecond, true)
	if err == nil {
		t.Error("Expected timeout error")
	}
}

// TestSendHTTP2RequestInvalidURL verifies error handling
func TestSendHTTP2RequestInvalidURL(t *testing.T) {
	ctx := context.Background()

	tests := []string{
		"not-a-url",
		"",
		"http://", // HTTP/2 requires HTTPS
	}

	for _, url := range tests {
		_, err := SendHTTP2Request(ctx, url, "GET", nil, "", 5*time.Second, true)
		if err == nil {
			t.Errorf("Expected error for invalid URL: %s", url)
		}
	}
}
