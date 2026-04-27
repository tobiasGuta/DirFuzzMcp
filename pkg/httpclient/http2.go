package httpclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/http2"
)

// SendHTTP2Request sends an HTTP/2 request using the standard library
func SendHTTP2Request(ctx context.Context, targetURL, method string, headers map[string]string, body string, timeout time.Duration, insecure bool) (*RawResponse, error) {
	start := time.Now()

	// Create HTTP/2 transport
	transport := &http2.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: insecure,
		},
		// Allow connection reuse
		AllowHTTP: false,
		DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
			// Check context before dial
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			dialer := &net.Dialer{Timeout: timeout}
			return tls.DialWithDialer(dialer, network, addr, cfg)
		},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	// Create request
	var bodyReader io.Reader
	if body != "" {
		bodyReader = bytes.NewBufferString(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, targetURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	// Execute request
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, MaxBodySize))
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Build headers string for compatibility
	var headersStr bytes.Buffer
	headersStr.WriteString(fmt.Sprintf("%s %s\r\n", resp.Proto, resp.Status))
	for k, vals := range resp.Header {
		for _, v := range vals {
			headersStr.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
		}
	}

	// Build raw response for compatibility
	var raw bytes.Buffer
	raw.WriteString(headersStr.String())
	raw.WriteString("\r\n")
	raw.Write(respBody)

	return &RawResponse{
		StatusCode: resp.StatusCode,
		Headers:    headersStr.String(),
		Body:       respBody,
		Raw:        raw.Bytes(),
		Duration:   time.Since(start),
	}, nil
}
