package mailru

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestMailruWebSocketUsesHTTPSProxy(t *testing.T) {
	// net/http caches proxy environment on first use. Isolate this network
	// test so other tests cannot determine its environment in advance.
	if os.Getenv("OPENFLUX_PROXY_TEST_CHILD") != "1" {
		command := exec.Command(os.Args[0], "-test.run=^TestMailruWebSocketUsesHTTPSProxy$", "-test.timeout=15s")
		for _, entry := range os.Environ() {
			name := strings.ToUpper(strings.SplitN(entry, "=", 2)[0])
			if name == "HTTP_PROXY" || name == "HTTPS_PROXY" || name == "ALL_PROXY" || name == "NO_PROXY" {
				continue
			}
			command.Env = append(command.Env, entry)
		}
		command.Env = append(command.Env, "OPENFLUX_PROXY_TEST_CHILD=1")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("proxy integration test: %v\n%s", err, output)
		}
		return
	}
	upgrader := websocket.Upgrader{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connection, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer connection.Close()
		_ = connection.SetReadDeadline(time.Now().Add(5 * time.Second))
		kind, payload, err := connection.ReadMessage()
		if err == nil {
			_ = connection.WriteMessage(kind, payload)
		}
	}))
	defer server.Close()
	connectTargets := make(chan string, 1)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT required", http.StatusBadRequest)
			return
		}
		connectTargets <- r.Host
		upstream, err := net.DialTimeout("tcp", server.Listener.Addr().String(), 5*time.Second)
		if err != nil {
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
			return
		}
		defer upstream.Close()
		downstream, buffer, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer downstream.Close()
		_, _ = buffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		_ = buffer.Flush()
		go func() { _, _ = io.Copy(upstream, buffer); _ = upstream.Close() }()
		_, _ = io.Copy(downstream, upstream)
	}))
	defer proxy.Close()
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("NO_PROXY", "bypass.openflux.test")
	certificate, err := x509.ParseCertificate(server.TLS.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	dialer := newMailruWebSocketDialer()
	dialer.TLSClientConfig = &tls.Config{RootCAs: roots, ServerName: certificate.DNSNames[0]}
	// This host has no direct route. Only the CONNECT proxy maps it to the
	// test server. TLS certificate verification remains enabled.
	connection, _, err := dialer.Dial("wss://editor.openflux.test/", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetReadDeadline(time.Now().Add(5 * time.Second))
	payload := []byte("encrypted-carrier-packet")
	if err := connection.WriteMessage(websocket.BinaryMessage, payload); err != nil {
		t.Fatal(err)
	}
	_, received, err := connection.ReadMessage()
	if err != nil || !bytes.Equal(received, payload) {
		t.Fatalf("proxied websocket echo: %q, %v", received, err)
	}
	if target := <-connectTargets; target != "editor.openflux.test:443" {
		t.Fatalf("CONNECT target: %q", target)
	}
	bypassRequest, err := http.NewRequest(http.MethodGet, "https://bypass.openflux.test/", nil)
	if err != nil { t.Fatal(err) }
	if route, err := dialer.Proxy(bypassRequest); err != nil || route != nil {
		t.Fatalf("NO_PROXY ignored: route=%v, error=%v", route, err)
	}
}
