package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/p1neappleXpress/OpenFlux/transport"
)

type managedOptions struct {
	config, http, socks, probe, ca string
	timeout                        time.Duration
	pfs, json                      bool
	command                        []string
}
type doctorCheck struct {
	Stage string `json:"stage"`
	State string `json:"state"`
	Code  string `json:"code,omitempty"`
}
type doctorReport struct {
	Version         string                       `json:"version"`
	ProxyConfigured bool                         `json:"proxy_configured"`
	Checks          []doctorCheck                `json:"checks"`
	Session         *transport.SessionDiagnostic `json:"session,omitempty"`
}

func parseManaged(args []string, doctor bool, errOut io.Writer) (managedOptions, error) {
	o := managedOptions{}
	fs := flag.NewFlagSet("openflux run/doctor", flag.ContinueOnError)
	fs.SetOutput(errOut)
	fs.StringVar(&o.config, "config", "client.conf", "Client configuration file")
	fs.StringVar(&o.http, "http-proxy", "127.0.0.1:0", "Private HTTP proxy listener; 0 chooses a free port")
	fs.StringVar(&o.socks, "socks5", "", "Private SOCKS listener; defaults to configuration or a free port")
	fs.DurationVar(&o.timeout, "timeout", 120*time.Second, "Startup/diagnostic deadline")
	fs.BoolVar(&o.pfs, "forward-secrecy", false, "Require forward secrecy on both peers")
	if doctor {
		fs.BoolVar(&o.json, "json", false, "Emit a redacted JSON report")
		fs.StringVar(&o.probe, "probe-url", "https://example.com/", "HTTPS endpoint to test through the tunnel")
	}
	if doctor {
		fs.StringVar(&o.ca, "probe-ca-file", "", "Additional trusted PEM CA for the HTTPS probe")
	}
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	o.command = fs.Args()
	if o.timeout <= 0 || o.timeout > 10*time.Minute {
		return o, errors.New("timeout must be greater than zero and at most 10m")
	}
	if !doctor && len(o.command) == 0 {
		return o, errors.New("usage: openflux run --config client.conf -- command [args]")
	}
	if doctor && len(o.command) > 0 {
		return o, errors.New("doctor does not take an application command")
	}
	return o, nil
}

type boundedLog struct {
	mu   sync.Mutex
	data []byte
}

func (b *boundedLog) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.data = append(b.data, p...)
	if len(b.data) > 128<<10 {
		b.data = append([]byte(nil), b.data[len(b.data)-(128<<10):]...)
	}
	return len(p), nil
}
func (b *boundedLog) failureCode() string {
	b.mu.Lock()
	text := strings.ToLower(string(b.data))
	b.mu.Unlock()
	for _, entry := range [][2]string{{"address already in use", "port_in_use"}, {"bind: only one usage", "port_in_use"}, {"encryption secret", "invalid_key"}, {"no carrier is connected", "carrier_unreachable"}, {"packets arrived but none decrypted", "peer_key_mismatch"}, {"handshake timed out", "peer_handshake_timeout"}, {"websocket dial failed", "websocket_unreachable"}, {"cannot open the document", "document_unreachable"}} {
		if strings.Contains(text, entry[0]) {
			return entry[1]
		}
	}
	return "core_exited_before_ready"
}

type managedCore struct {
	child             *ownedChild
	http, socks, temp string
	lock              *os.File
	log               boundedLog
}

func loopbackAddress(value string) (string, error) {
	host, _, err := net.SplitHostPort(value)
	if err != nil {
		return "", errors.New("invalid local proxy address")
	}
	ip := net.ParseIP(host)
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return "", errors.New("managed proxy listeners must use loopback addresses")
	}
	ln, err := net.Listen("tcp", value)
	if err != nil {
		return "", errors.New("port_in_use_or_unavailable")
	}
	address := ln.Addr().String()
	_ = ln.Close()
	return address, nil
}

func startManagedCore(o managedOptions) (*managedCore, error) {
	path, err := filepath.Abs(o.config)
	if err != nil {
		return nil, errors.New("config_unreadable")
	}
	conf, err := parseConf(path)
	if err != nil {
		return nil, errors.New("config_invalid")
	}
	if role := conf.Interface["Role"]; role != "" && role != "client" {
		return nil, errors.New("managed commands require a client configuration")
	}
	key := conf.Interface["EncryptionKeyFile"]
	if key == "" {
		return nil, errors.New("encryption_key_required")
	}
	if !filepath.IsAbs(key) {
		key = filepath.Join(filepath.Dir(path), key)
	}
	f, err := os.Open(key)
	if err != nil {
		return nil, errors.New("key_unreadable")
	}
	_ = f.Close()
	c := &managedCore{}
	c.lock, err = os.OpenFile(path+".run.lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, errors.New("launcher_lock_unavailable")
	}
	if err := lockManaged(c.lock); err != nil {
		_ = c.lock.Close()
		return nil, errors.New("another_managed_session_is_running")
	}
	cleanup := true
	defer func() {
		if cleanup {
			c.close()
		}
	}()
	socks := o.socks
	if socks == "" {
		socks = conf.Interface["Socks5"]
	}
	if socks == "" {
		socks = "127.0.0.1:0"
	}
	c.socks, err = loopbackAddress(socks)
	if err != nil {
		return nil, err
	}
	c.http, err = loopbackAddress(o.http)
	if err != nil {
		return nil, err
	}
	if c.http == c.socks {
		return nil, errors.New("proxy listeners must use different ports")
	}
	c.temp, err = os.MkdirTemp("", "openflux-managed-")
	if err != nil {
		return nil, errors.New("status_directory_unavailable")
	}
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	args := []string{"--config=" + path, "--role=client", "--inbound=socks5", "--negotiate", "--socks5=" + c.socks, "--http-proxy=" + c.http, "--status-file=" + filepath.Join(c.temp, "status.json"), "--debug=2", "--sensitive=false"}
	if o.pfs {
		args = append(args, "--forward-secrecy")
	}
	cmd := exec.Command(self, args...)
	cmd.Dir = filepath.Dir(path)
	cmd.Stdout, cmd.Stderr = &c.log, &c.log
	c.child, err = startOwned(cmd)
	if err != nil {
		return nil, errors.New("core_start_failed")
	}
	cleanup = false
	return c, nil
}

func (c *managedCore) close() {
	if c.child != nil {
		c.child.stop()
	}
	if c.lock != nil {
		_ = c.lock.Close()
	}
	if c.temp != "" {
		_ = os.RemoveAll(c.temp)
	}
}
func (c *managedCore) snapshot() *transport.SessionDiagnostic {
	b, err := os.ReadFile(filepath.Join(c.temp, "status.json"))
	if err != nil {
		return nil
	}
	var status transport.SessionDiagnostic
	if json.Unmarshal(b, &status) != nil {
		return nil
	}
	return &status
}

func (c *managedCore) wait(ctx context.Context) error {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	httpClient := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: time.Second}
	defer httpClient.CloseIdleConnections()
	for {
		select {
		case <-ctx.Done():
			return errors.New("startup_cancelled_or_timed_out")
		case <-c.child.done:
			return errors.New(c.log.failureCode())
		case <-ticker.C:
			status := c.snapshot()
			if status == nil || !status.Authenticated {
				continue
			}
			resp, err := httpClient.Get("http://" + c.http + "/")
			if err != nil {
				continue
			}
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusBadRequest {
				return nil
			}
		}
	}
}

func applicationEnvironment(parent []string, proxy string) []string {
	names := map[string]bool{}
	for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy", "PI_PROXY", "PI_PROXY_OPENAI", "PI_PROXY_OPENAI_CODEX"} {
		names[name] = true
	}
	env := make([]string, 0, len(parent)+len(names))
	for _, value := range parent {
		name, _, _ := strings.Cut(value, "=")
		if !names[name] {
			env = append(env, value)
		}
	}
	for name := range names {
		env = append(env, name+"="+proxy)
	}
	return env
}

func runManaged(args []string, in io.Reader, out, errOut io.Writer) int {
	o, err := parseManaged(args, false, errOut)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()
	signals := make(chan os.Signal, 2)
	notifySignals(signals)
	defer signal.Stop(signals)
	go func() {
		select {
		case <-signals:
			cancel()
		case <-ctx.Done():
		}
	}()
	core, err := startManagedCore(o)
	if err != nil {
		fmt.Fprintln(errOut, "OpenFlux:", err)
		return 1
	}
	defer core.close()
	if err := core.wait(ctx); err != nil {
		fmt.Fprintln(errOut, "OpenFlux:", err, "(run openflux doctor for a redacted report)")
		return 1
	}
	if ctx.Err() != nil {
		return 130
	}
	// A startup deadline must not become the application's lifetime limit.
	cancel()
	cmd := exec.Command(o.command[0], o.command[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = in, out, errOut
	cmd.Env = applicationEnvironment(os.Environ(), "http://"+core.http)
	app, err := startOwned(cmd)
	if err != nil {
		fmt.Fprintln(errOut, "Application failed to start")
		return 1
	}
	defer app.stop()
	restore := foregroundManaged(app.cmd)
	defer restore()
	select {
	case <-app.done:
		return app.exitCode()
	case <-core.child.done:
		fmt.Fprintln(errOut, "OpenFlux stopped; terminating the managed application")
		return 1
	case <-signals:
		return 130
	}
}

func runDoctor(args []string, out, errOut io.Writer) int {
	o, err := parseManaged(args, true, errOut)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 2
	}
	report := doctorReport{Version: buildVersion}
	printReport := func() {
		if o.json {
			_ = json.NewEncoder(out).Encode(report)
			return
		}
		for _, check := range report.Checks {
			fmt.Fprintf(out, "%s: %s", check.Stage, check.State)
			if check.Code != "" {
				fmt.Fprintf(out, " (%s)", check.Code)
			}
			fmt.Fprintln(out)
		}
		if report.Session != nil {
			for _, link := range report.Session.Links {
				fmt.Fprintf(out, "carrier %s: %s, queued=%d bytes, retries=%d, expired=%d\n", link.Name, link.Carrier.Phase, link.QueueBytes, link.Retries, link.Expired)
			}
		}
	}
	for _, name := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		if value := os.Getenv(name); value != "" {
			report.ProxyConfigured = true
			u, e := url.Parse(value)
			if e != nil || u.Host == "" {
				report.Checks = append(report.Checks, doctorCheck{"environment_proxy", "failed", "invalid_proxy_url"})
				printReport()
				return 1
			}
		}
	}
	report.Checks = append(report.Checks, doctorCheck{"environment_proxy", "ok", ""})
	u, err := url.Parse(o.probe)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		report.Checks = append(report.Checks, doctorCheck{"https_probe", "failed", "probe_must_be_https_without_credentials"})
		printReport()
		return 2
	}
	core, err := startManagedCore(o)
	if err != nil {
		report.Checks = append(report.Checks, doctorCheck{"configuration_and_ports", "failed", err.Error()})
		printReport()
		return 1
	}
	defer core.close()
	report.Checks = append(report.Checks, doctorCheck{"configuration_and_ports", "ok", ""})
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()
	signals := make(chan os.Signal, 1)
	notifySignals(signals)
	defer signal.Stop(signals)
	go func() {
		select {
		case <-signals:
			cancel()
		case <-ctx.Done():
		}
	}()
	err = core.wait(ctx)
	report.Session = core.snapshot()
	if report.Session != nil {
		for _, link := range report.Session.Links {
			phase := link.Carrier.Phase
			if link.Name == "mailru" {
				rank := 0
				switch phase {
				case "websocket":
					rank = 1
				case "editor":
					rank = 2
				case "authenticated":
					rank = 3
				}
				for index, stage := range []string{"document", "websocket", "editor_authentication"} {
					state, code := "pending", ""
					if index < rank {
						state = "ok"
					} else if index == rank && link.Carrier.Code != "" {
						state, code = "failed", link.Carrier.Code
					}
					report.Checks = append(report.Checks, doctorCheck{link.Name + "/" + stage, state, code})
				}
			} else {
				state := "pending"
				if link.Connected {
					state = "ok"
				}
				report.Checks = append(report.Checks, doctorCheck{link.Name + "/carrier", state, link.Carrier.Code})
			}
		}
	}
	if err != nil {
		code := err.Error()
		if report.Session != nil && report.Session.ForwardSecrecy {
			for _, link := range report.Session.Links {
				if !link.PFSReady && link.Carrier.Phase == "authenticated" {
					code = "forward_secrecy_peer_unavailable_or_key_mismatch"
				}
			}
		}
		report.Checks = append(report.Checks, doctorCheck{"peer_authentication", "failed", code})
		printReport()
		return 1
	}
	report.Checks = append(report.Checks, doctorCheck{"peer_authentication", "ok", ""})
	proxy, _ := url.Parse("http://" + core.http)
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if o.ca != "" {
		roots, e := x509.SystemCertPool()
		if e != nil {
			roots = x509.NewCertPool()
		}
		pem, e := os.ReadFile(o.ca)
		if e != nil || !roots.AppendCertsFromPEM(pem) {
			report.Checks = append(report.Checks, doctorCheck{"https_probe", "failed", "invalid_probe_ca"})
			printReport()
			return 2
		}
		tlsConfig.RootCAs = roots
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxy), TLSClientConfig: tlsConfig}, Timeout: 20 * time.Second}
	defer client.CloseIdleConnections()
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, o.probe, nil)
	response, err := client.Do(request)
	if err != nil {
		report.Checks = append(report.Checks, doctorCheck{"https_through_tunnel", "failed", "connect_or_tls_failed"})
		printReport()
		return 1
	}
	_, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
	_ = response.Body.Close()
	if readErr != nil {
		report.Checks = append(report.Checks, doctorCheck{"https_through_tunnel", "failed", "response_interrupted"})
		printReport()
		return 1
	}
	report.Checks = append(report.Checks, doctorCheck{"https_through_tunnel", "ok", fmt.Sprintf("http_%d", response.StatusCode)})
	printReport()
	return 0
}

func writeStatusLoop(path string, session *transport.Session) {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for range ticker.C {
		snapshot := session.DiagnosticSnapshot()
		data, err := json.Marshal(snapshot)
		if err != nil {
			continue
		}
		temporary := path + ".tmp"
		if os.WriteFile(temporary, data, 0600) == nil {
			_ = os.Rename(temporary, path)
		}
	}
}
