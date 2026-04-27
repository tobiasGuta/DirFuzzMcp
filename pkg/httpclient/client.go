package httpclient

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/proxy"
)

// MaxBodySize limits response body reading to prevent memory exhaustion.
const MaxBodySize = 5 * 1024 * 1024 // 5 MB

// RawResponse holds the unparsed, raw response data.
type RawResponse struct {
	StatusCode int
	Headers    string
	HeaderMap  map[string]string
	Body       []byte
	Raw        []byte
	Duration   time.Duration
	// BodyComplete is true when the response body was fully read from the
	// network (either by satisfying Content-Length or by seeing the final
	// chunk terminator for chunked responses). When false the connection
	// should not be returned to a keep-alive pool.
	BodyComplete bool
	// BodyEncoded indicates that the response body contains an encoding that
	// this client cannot decode (e.g. Brotli / "br") or an attempted
	// decompression failed. When true callers should avoid content-based
	// metrics (word/line counts) because the body is still encoded.
	BodyEncoded bool
}

// GetHeader extracts a header value from the raw headers string (case-insensitive).
func (r *RawResponse) GetHeader(key string) string {
	if r == nil {
		return ""
	}
	lowerKey := strings.ToLower(key)
	if r.HeaderMap != nil {
		if v, ok := r.HeaderMap[lowerKey]; ok {
			return v
		}
		return ""
	}
	// Fallback: parse the raw header string (for compatibility).
	normalized := strings.ReplaceAll(r.Headers, "\r\n", "\n")
	normalized = strings.ReplaceAll(normalized, "\r", "\n")
	lines := strings.Split(normalized, "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			k := strings.ToLower(strings.TrimSpace(parts[0]))
			if k == lowerKey {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

// ─── DNS cache ────────────────────────────────────────────────────────────────

// SendRawRequest sends a raw HTTP request (no context, no pool).
func SendRawRequest(targetURL string, rawRequest []byte, timeout time.Duration, proxyAddr string) (*RawResponse, error) {
	return SendRawRequestWithContext(context.Background(), targetURL, rawRequest, timeout, proxyAddr, false)
}

// SendRawRequestWithContext sends a raw HTTP/1.1 request with full context
// support, connection pooling, TLS cipher randomisation, and both SOCKS5 and
// HTTP proxy support.
//
// Proxy URL formats accepted:
//
//	socks5://[user:pass@]host:port  — SOCKS5 (bare host:port also treated as SOCKS5)
//	http://[user:pass@]host:port    — HTTP CONNECT proxy
func SendRawRequestWithContext(
	ctx context.Context,
	targetURL string,
	rawRequest []byte,
	timeout time.Duration,
	proxyAddr string,
	insecure bool,
) (*RawResponse, error) {
	start := time.Now()

	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	address := net.JoinHostPort(host, port)
	poolKey := u.Scheme + "://" + address

	// Detect HTTP vs SOCKS5 proxy.
	proxyIsHTTP := false
	if proxyAddr != "" {
		low := strings.ToLower(proxyAddr)
		if strings.HasPrefix(low, "http://") || strings.HasPrefix(low, "https://") {
			proxyIsHTTP = true
		}
	}

	// Try to get a pooled connection (only when no proxy, proxy conns aren't trivially reusable).
	var conn net.Conn
	if proxyAddr == "" {
		conn = DefaultPool.Get(poolKey)
	}

	// Dial a new connection if pool miss.
	if conn == nil {
		conn, err = dialNew(ctx, u.Scheme, address, host, proxyAddr, proxyIsHTTP, timeout, insecure)
		if err != nil {
			return nil, err
		}
	}

	// Send the request.
	conn.SetDeadline(time.Now().Add(timeout))

	if ctx.Err() != nil {
		conn.Close()
		return nil, ctx.Err()
	}

	_, writeErr := conn.Write(rawRequest)
	if writeErr != nil {
		// Stale pooled connection — discard and retry with a fresh connection.
		conn.Close()
		conn, err = dialNew(ctx, u.Scheme, address, host, proxyAddr, proxyIsHTTP, timeout, insecure)
		if err != nil {
			return nil, err
		}
		conn.SetDeadline(time.Now().Add(timeout))
		if _, err = conn.Write(rawRequest); err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to write request: %w", err)
		}
	}

	// Read the response.
	resp, parseErr := parseRawResponse(conn)
	if parseErr != nil {
		conn.Close()
		return nil, parseErr
	}
	resp.Duration = time.Since(start)

	// Return connection to pool when keep-alive is possible and the body
	// was fully consumed. If the body was truncated we must not reuse the
	// connection because unread bytes will remain on the socket and will
	// corrupt the next response parsing.
	if proxyAddr == "" && responseAllowsKeepalive(resp.Headers) && resp.BodyComplete {
		DefaultPool.Put(poolKey, u.Scheme, conn)
	} else {
		conn.Close()
	}

	return resp, nil
}

// ─── Dial helpers ─────────────────────────────────────────────────────────────

func dialNew(ctx context.Context, scheme, address, host, proxyAddr string, proxyIsHTTP bool, timeout time.Duration, insecure bool) (net.Conn, error) {
	if scheme == "https" {
		return dialHTTPS(ctx, address, host, proxyAddr, proxyIsHTTP, timeout, insecure)
	}
	return dialHTTP(ctx, address, proxyAddr, proxyIsHTTP, timeout)
}

func dialHTTPS(ctx context.Context, address, host, proxyAddr string, proxyIsHTTP bool, timeout time.Duration, insecure bool) (net.Conn, error) {
	ciphers := []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	}
	rand.Shuffle(len(ciphers), func(i, j int) { ciphers[i], ciphers[j] = ciphers[j], ciphers[i] })

	tlsCfg := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: insecure,
		CipherSuites:       ciphers,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS13,
	}

	if proxyAddr == "" {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		dialer := &net.Dialer{Timeout: timeout}
		return tls.DialWithDialer(dialer, "tcp", address, tlsCfg)
	}

	if proxyIsHTTP {
		rawConn, err := dialHTTPProxy(ctx, proxyAddr, address, timeout)
		if err != nil {
			return nil, err
		}
		tlsConn := tls.Client(rawConn, tlsCfg)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			rawConn.Close()
			return nil, fmt.Errorf("TLS handshake through HTTP proxy failed: %w", err)
		}
		return tlsConn, nil
	}

	// SOCKS5 proxy.
	auth, proxyURL := parseSocks5Proxy(proxyAddr)
	d, err := proxy.SOCKS5("tcp", proxyURL, auth, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("proxy init failed: %w", err)
	}
	rawConn, err := d.Dial("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("proxy dial failed: %w", err)
	}
	tlsConn := tls.Client(rawConn, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("TLS handshake through SOCKS5 proxy failed: %w", err)
	}
	return tlsConn, nil
}

func dialHTTP(ctx context.Context, address, proxyAddr string, proxyIsHTTP bool, timeout time.Duration) (net.Conn, error) {
	if proxyAddr == "" {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		dialer := &net.Dialer{
			Timeout: timeout,
			Control: func(network, address string, c syscall.RawConn) error {
				return setSocketLinger(c)
			},
		}
		return dialer.Dial("tcp", address)
	}

	if proxyIsHTTP {
		// For plain HTTP through an HTTP proxy the TCP tunnel just needs to
		// reach the proxy. The caller must put the absolute URL in the
		// request-line (not implemented here — engine.go sends raw requests).
		return dialHTTPProxy(ctx, proxyAddr, address, timeout)
	}

	auth, proxyURL := parseSocks5Proxy(proxyAddr)
	d, err := proxy.SOCKS5("tcp", proxyURL, auth, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("proxy init failed: %w", err)
	}
	return d.Dial("tcp", address)
}

// dialHTTPProxy dials an HTTP proxy and sends a CONNECT request to tunnel to
// the given target address (host:port).
func dialHTTPProxy(ctx context.Context, proxyAddr, targetAddr string, timeout time.Duration) (net.Conn, error) {
	proxyURL, err := url.Parse(proxyAddr)
	if err != nil {
		proxyURL, err = url.Parse("http://" + proxyAddr)
		if err != nil {
			return nil, fmt.Errorf("invalid HTTP proxy address %q: %w", proxyAddr, err)
		}
	}

	proxyHost := proxyURL.Host
	if !strings.Contains(proxyHost, ":") {
		proxyHost += ":3128"
	}

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", proxyHost)
	if err != nil {
		return nil, fmt.Errorf("HTTP proxy dial failed: %w", err)
	}

	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", targetAddr, targetAddr)
	if proxyURL.User != nil {
		u := proxyURL.User.Username()
		p, _ := proxyURL.User.Password()
		encoded := base64.StdEncoding.EncodeToString([]byte(u + ":" + p))
		connectReq += "Proxy-Authorization: Basic " + encoded + "\r\n"
	}
	connectReq += "\r\n"

	conn.SetDeadline(time.Now().Add(timeout))
	if _, err = conn.Write([]byte(connectReq)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("HTTP proxy CONNECT write failed: %w", err)
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		conn.Close()
		return nil, fmt.Errorf("HTTP proxy CONNECT response read failed: %w", err)
	}
	respStr := string(buf[:n])
	if !strings.Contains(respStr, "200") {
		conn.Close()
		return nil, fmt.Errorf("HTTP proxy CONNECT refused: %s", strings.TrimSpace(respStr))
	}

	return conn, nil
}

// parseSocks5Proxy extracts optional auth and the clean host:port from a proxy
// string that may or may not have a socks5:// scheme or user:pass@ prefix.
func parseSocks5Proxy(proxyAddr string) (auth *proxy.Auth, cleanAddr string) {
	proxyAddr = strings.TrimPrefix(proxyAddr, "socks5://")
	if strings.Contains(proxyAddr, "@") {
		parts := strings.SplitN(proxyAddr, "@", 2)
		if len(parts) == 2 && strings.Contains(parts[0], ":") {
			authParts := strings.SplitN(parts[0], ":", 2)
			auth = &proxy.Auth{User: authParts[0], Password: authParts[1]}
			proxyAddr = parts[1]
		}
	}
	return auth, proxyAddr
}

// ─── Response parsing ─────────────────────────────────────────────────────────

// dechunkBody decodes an HTTP/1.1 chunked body and returns the dechunked
// payload plus any trailer headers found after the terminating 0 chunk.
// If the input does not appear to be chunked (parsing fails before any
// data is dechunked) the original body is returned and the trailer map is
// nil.
func dechunkBody(body []byte) ([]byte, map[string]string) {
	var dechunked bytes.Buffer
	// Use a reader wrapper to avoid copying the entire body into a new
	// buffer. bytes.NewReader is lightweight; bufio.Reader provides
	// ReadString used below.
	buf := bufio.NewReader(bytes.NewReader(body))
	for {
		line, err := buf.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if idx := strings.IndexByte(line, ';'); idx != -1 {
			line = line[:idx]
		}
		line = strings.TrimSpace(line)
		chunkSize, err := strconv.ParseInt(line, 16, 64)
		if err != nil || chunkSize < 0 {
			if dechunked.Len() == 0 {
				return body, nil
			}
			break
		}
		if chunkSize == 0 {
			// Final chunk — read optional trailer headers until an empty line.
			trailers := make(map[string]string)
			lastKey := ""
			for {
				tline, terr := buf.ReadString('\n')
				if terr != nil && terr != io.EOF {
					break
				}
				trimmed := strings.TrimRight(tline, "\r\n")
				if trimmed == "" {
					// End of trailers
					break
				}
				// Continuation line (obsolete folding)
				if len(trimmed) > 0 && (trimmed[0] == ' ' || trimmed[0] == '\t') {
					if lastKey != "" {
						trailers[lastKey] = trailers[lastKey] + " " + strings.TrimSpace(trimmed)
					}
					continue
				}
				parts := strings.SplitN(trimmed, ":", 2)
				if len(parts) != 2 {
					continue
				}
				k := strings.ToLower(strings.TrimSpace(parts[0]))
				v := strings.TrimSpace(parts[1])
				trailers[k] = v
				lastKey = k
			}
			return dechunked.Bytes(), trailers
		}
		chunk := make([]byte, chunkSize)
		_, err = io.ReadFull(buf, chunk)
		if err != nil {
			dechunked.Write(chunk)
			break
		}
		dechunked.Write(chunk)
		// Consume the trailing CRLF after the chunk data.
		buf.ReadString('\n')
	}
	if dechunked.Len() > 0 {
		return dechunked.Bytes(), nil
	}
	return body, nil
}

func decompressGzip(body []byte) ([]byte, error) {
	if len(body) == 0 {
		return body, nil
	}
	reader, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	decompressed, err := io.ReadAll(reader)
	if err != nil && err != io.ErrUnexpectedEOF {
		if len(decompressed) == 0 {
			return nil, err
		}
	}
	return decompressed, nil
}

// decompressDeflate attempts to decode a "deflate" compressed body. Some
// servers emit raw DEFLATE (RFC 1951) while others use zlib-wrapped
// deflate (RFC 1950) but both are commonly labelled "deflate". Try zlib
// first and fall back to raw inflate if that fails.
func decompressDeflate(body []byte) ([]byte, error) {
	if len(body) == 0 {
		return body, nil
	}
	// Try zlib-wrapped (RFC 1950).
	if zr, err := zlib.NewReader(bytes.NewReader(body)); err == nil {
		defer zr.Close()
		out, err := io.ReadAll(zr)
		if err == nil || (err == io.ErrUnexpectedEOF && len(out) > 0) {
			return out, nil
		}
	}
	// Try raw DEFLATE (RFC 1951).
	fr := flate.NewReader(bytes.NewReader(body))
	if fr != nil {
		defer fr.Close()
		out, err := io.ReadAll(fr)
		if err == nil || (err == io.ErrUnexpectedEOF && len(out) > 0) {
			return out, nil
		}
	}
	return nil, fmt.Errorf("deflate decompression failed")
}

func parseRawResponse(conn net.Conn) (*RawResponse, error) {
	var buf bytes.Buffer
	chunk := make([]byte, 4096)
	headerParsed := false
	headerEndIdx := -1
	sepLen := 4
	contentLength := -1
	isChunked := false
	// protoIsHTTP10 is set when the status line indicates HTTP/1.0. We use
	// this later to recognise HTTP/1.0 responses that terminate the body by
	// closing the connection (io.EOF) when there's no Content-Length.
	protoIsHTTP10 := false
	var headerMap map[string]string
	var lastErr error

	for {
		n, err := conn.Read(chunk)
		lastErr = err
		if n > 0 {
			buf.Write(chunk[:n])
		}
		rawBytes := buf.Bytes()

		if !headerParsed {
			// Avoid rescanning the entire buffer on each read: compute the
			// previous buffer length (before this read) and only search from a
			// small overlap before the appended data. This makes the search
			// linear in the amount of data received rather than quadratic.
			prevLen := len(rawBytes) - n
			if prevLen < 0 {
				prevLen = 0
			}
			start := prevLen - 4
			if start < 0 {
				start = 0
			}

			if idx := bytes.Index(rawBytes[start:], []byte("\r\n\r\n")); idx != -1 {
				headerEndIdx = start + idx
				sepLen = 4
				headerParsed = true
			} else if idx := bytes.Index(rawBytes[start:], []byte("\n\n")); idx != -1 {
				headerEndIdx = start + idx
				sepLen = 2
				headerParsed = true
			}

			if headerParsed {
				headersStr := string(rawBytes[:headerEndIdx])
				// Normalize line endings and build a header map (lowercased keys).
				normalized := strings.ReplaceAll(headersStr, "\r\n", "\n")
				normalized = strings.ReplaceAll(normalized, "\r", "\n")
				lines := strings.Split(normalized, "\n")
				headerMap = make(map[string]string)
				// Detect HTTP version from the status line (first line).
				if len(lines) > 0 {
					firstLine := strings.TrimSpace(lines[0])
					if strings.HasPrefix(strings.ToUpper(firstLine), "HTTP/1.0") {
						protoIsHTTP10 = true
					}
				}
				// Support obsolete header folding: continuation lines start
				// with a space or tab and should be appended to the previous
				// header's value. For Transfer-Encoding duplicates, concatenate
				// their values with commas so we preserve the full sequence.
				lastKey := ""
				for i, line := range lines {
					if i == 0 || strings.TrimSpace(line) == "" {
						// Skip status line and empty lines.
						continue
					}
					// Continuation line for previous header (obsolete folding).
					if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
						if lastKey != "" {
							prev := headerMap[lastKey]
							headerMap[lastKey] = prev + " " + strings.TrimSpace(line)
						}
						continue
					}
					parts := strings.SplitN(line, ":", 2)
					if len(parts) != 2 {
						continue
					}
					k := strings.ToLower(strings.TrimSpace(parts[0]))
					v := strings.TrimSpace(parts[1])
					if prev, exists := headerMap[k]; exists {
						if k == "transfer-encoding" {
							// Concatenate multiple Transfer-Encoding values.
							if prev == "" {
								headerMap[k] = v
							} else if v != "" {
								headerMap[k] = prev + ", " + v
							}
						}
						// otherwise: ignore duplicate header lines (preserve first)
					} else {
						headerMap[k] = v
					}
					lastKey = k
				}
				if te, ok := headerMap["transfer-encoding"]; ok && strings.Contains(strings.ToLower(te), "chunked") {
					isChunked = true
				} else if cl, ok := headerMap["content-length"]; ok {
					if clv, err2 := strconv.Atoi(cl); err2 == nil {
						contentLength = clv
					}
				}
			}
		}

		if headerParsed {
			bodyLen := buf.Len() - (headerEndIdx + sepLen)
			if isChunked {
				if bytes.HasSuffix(rawBytes, []byte("0\r\n\r\n")) || bytes.HasSuffix(rawBytes, []byte("0\n\n")) {
					break
				}
			} else if contentLength != -1 {
				if bodyLen >= contentLength {
					break
				}
			}
		}

		if err != nil {
			break
		}
		if buf.Len() > MaxBodySize {
			break
		}
	}

	rawBytes := buf.Bytes()
	if len(rawBytes) == 0 {
		return nil, fmt.Errorf("empty response")
	}

	// Determine whether we actually consumed the entire body from the
	// connection. This is required so callers know whether it's safe to
	// return the underlying connection to a keep-alive pool.
	bodyComplete := false
	if headerEndIdx != -1 {
		if isChunked {
			if bytes.HasSuffix(rawBytes, []byte("0\r\n\r\n")) || bytes.HasSuffix(rawBytes, []byte("0\n\n")) {
				bodyComplete = true
			}
		} else if contentLength != -1 {
			bodyLen := len(rawBytes) - (headerEndIdx + sepLen)
			if bodyLen >= contentLength {
				bodyComplete = true
			}
		}
	}

	// Special-case: HTTP/1.0 responses which signal the end of the body by
	// closing the connection (io.EOF) and which do NOT provide a
	// Content-Length or Transfer-Encoding. Treat an EOF in that case as a
	// complete body so callers can compute metrics. We compute the final
	// decision below after observing lastErr.
	http10EOFBody := false
	if headerEndIdx != -1 && protoIsHTTP10 && !isChunked && contentLength == -1 && lastErr == io.EOF {
		http10EOFBody = true
		bodyComplete = true
	}

	// If we broke out due to a read error (lastErr != nil) we should treat
	// the body as incomplete for pooling purposes — except when the error
	// is io.EOF for an HTTP/1.0 connection-close body (handled above).
	if lastErr != nil {
		if lastErr == io.EOF && http10EOFBody {
			// keep bodyComplete = true
		} else {
			bodyComplete = false
		}
	}

	resp := &RawResponse{Raw: rawBytes, BodyComplete: bodyComplete, HeaderMap: headerMap}
	if headerEndIdx != -1 {
		resp.Headers = string(rawBytes[:headerEndIdx])
		resp.Body = rawBytes[headerEndIdx+sepLen:]
	} else {
		resp.Body = rawBytes
	}

	if len(resp.Body) > MaxBodySize {
		resp.Body = resp.Body[:MaxBodySize]
	}

	firstLineEnd := strings.Index(resp.Headers, "\n")
	if firstLineEnd != -1 {
		firstLine := strings.TrimSpace(resp.Headers[:firstLineEnd])
		parts := strings.SplitN(firstLine, " ", 3)
		if len(parts) >= 2 {
			if code, err := strconv.Atoi(parts[1]); err == nil {
				resp.StatusCode = code
			}
		}
	}

	needsUpdate := false
	if isChunked {
		newBody, trailers := dechunkBody(resp.Body)
		resp.Body = newBody
		if len(trailers) > 0 {
			if resp.HeaderMap == nil {
				resp.HeaderMap = make(map[string]string)
			}
			// Trailer headers take precedence over original headers.
			for k, v := range trailers {
				resp.HeaderMap[k] = v
			}
		}
		needsUpdate = true
	}

	// Handle stacked Content-Encoding values. RFC lists the last encoding
	// applied first, so we must process encodings in reverse order.
	encHeader := strings.ToLower(strings.TrimSpace(resp.GetHeader("Content-Encoding")))
	if encHeader != "" {
		parts := strings.Split(encHeader, ",")
		stop := false
		for i := len(parts) - 1; i >= 0; i-- {
			if stop {
				break
			}
			enc := strings.ToLower(strings.TrimSpace(parts[i]))
			switch enc {
			case "gzip", "x-gzip":
				if newBody, err := decompressGzip(resp.Body); err == nil {
					resp.Body = newBody
					needsUpdate = true
				} else {
					resp.BodyEncoded = true
					stop = true
				}
			case "deflate", "x-deflate":
				if newBody, err := decompressDeflate(resp.Body); err == nil {
					resp.Body = newBody
					needsUpdate = true
				} else {
					resp.BodyEncoded = true
					stop = true
				}
			case "br", "brotli":
				// Brotli is not supported by the stdlib; mark as encoded so
				// callers can handle it appropriately.
				resp.BodyEncoded = true
				stop = true
			case "", "identity":
				// No-op: identity means no encoding.
			default:
				// Unknown encoding — mark as encoded and stop.
				resp.BodyEncoded = true
				stop = true
			}
		}
	}
	if needsUpdate {
		var newRaw bytes.Buffer
		newRaw.WriteString(resp.Headers)
		newRaw.WriteString("\r\n\r\n")
		newRaw.Write(resp.Body)
		resp.Raw = newRaw.Bytes()
	}

	return resp, nil
}
