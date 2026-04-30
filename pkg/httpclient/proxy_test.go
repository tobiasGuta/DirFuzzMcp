package httpclient

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHTTPProxyUsesAbsoluteFormForPlainHTTP(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("target"))
	}))
	defer target.Close()

	requestLineCh := make(chan string, 1)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestLineCh <- r.RequestURI
		if !strings.HasPrefix(r.RequestURI, "http://") {
			http.Error(w, "expected absolute-form request", http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("proxied"))
	}))
	defer proxy.Close()

	raw := []byte("GET /admin HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
	resp, err := SendRawRequestWithContext(context.Background(), target.URL, raw, 2*time.Second, proxy.URL, true)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	got := <-requestLineCh
	if !strings.HasPrefix(got, target.URL+"/admin") {
		t.Fatalf("proxy request URI = %q, want absolute target URL", got)
	}
}

func TestHTTPProxyUsesConnectForHTTPS(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("secure"))
	}))
	defer target.Close()

	connectCh := make(chan string, 1)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "expected CONNECT", http.StatusBadGateway)
			return
		}
		connectCh <- r.Host
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijacker", http.StatusInternalServerError)
			return
		}
		clientConn, _, err := hj.Hijack()
		if err != nil {
			return
		}
		targetConn, err := net.Dial("tcp", r.Host)
		if err != nil {
			_, _ = fmt.Fprint(clientConn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
			_ = clientConn.Close()
			return
		}
		_, _ = fmt.Fprint(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		go func() {
			defer clientConn.Close()
			defer targetConn.Close()
			_, _ = io.Copy(targetConn, clientConn)
		}()
		go func() {
			defer clientConn.Close()
			defer targetConn.Close()
			_, _ = io.Copy(clientConn, targetConn)
		}()
	}))
	defer proxy.Close()

	raw := []byte("GET /secure HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
	resp, err := SendRawRequestWithContext(context.Background(), target.URL, raw, 5*time.Second, proxy.URL, true)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	select {
	case host := <-connectCh:
		if host == "" {
			t.Fatal("empty CONNECT host")
		}
	case <-time.After(time.Second):
		t.Fatal("proxy did not receive CONNECT")
	}
}
