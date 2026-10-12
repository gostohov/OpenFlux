package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestManagedEnvironmentIsScopedAndKeepsCarrierRoute(t *testing.T) {
	parent := []string{"HTTPS_PROXY=http://carrier-proxy:3128", "PI_PROXY=old", "CUSTOM=retained", "NO_PROXY=localhost"}
	before := append([]string(nil), parent...)
	env := applicationEnvironment(parent, "http://127.0.0.1:1234")
	joined := strings.Join(env, "\n")
	if !strings.Contains(joined, "HTTPS_PROXY=http://127.0.0.1:1234") || !strings.Contains(joined, "PI_PROXY_OPENAI_CODEX=http://127.0.0.1:1234") || !strings.Contains(joined, "CUSTOM=retained") {
		t.Fatal("incorrect application environment")
	}
	if strings.Join(before, "\n") != strings.Join(parent, "\n") {
		t.Fatal("modified parent/carrier environment")
	}
}

func TestDoctorDoesNotDiscloseProxyCredentialsOrPrivateConfiguration(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://private-user:private-password@proxy.invalid:3128")
	var out, errOut bytes.Buffer
	code := runDoctor([]string{"--json", "--config", filepath.Join(t.TempDir(), "missing")}, &out, &errOut)
	if code == 0 {
		t.Fatal("missing configuration accepted")
	}
	var report doctorReport
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"private-user", "private-password", "proxy.invalid"} {
		if strings.Contains(out.String()+errOut.String(), secret) {
			t.Fatal("diagnostic leaked private data")
		}
	}
}

func TestOwnedProcessHelper(t *testing.T) {
	if os.Getenv("OPENFLUX_PROCESS_HELPER") != "1" {
		return
	}
	if os.Getenv("OPENFLUX_HELPER_MODE") == "exit" {
		os.Exit(37)
	}
	if os.Getenv("OPENFLUX_HELPER_MODE") == "tree" {
		child := exec.Command(os.Args[0], "-test.run=^TestOwnedProcessHelper$")
		child.Env = append(os.Environ(), "OPENFLUX_HELPER_MODE=listen")
		if err := child.Start(); err != nil {
			os.Exit(2)
		}
	}
	if os.Getenv("OPENFLUX_HELPER_MODE") == "listen" {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			os.Exit(2)
		}
		if err := os.WriteFile(os.Getenv("OPENFLUX_CHILD_ADDRESS_FILE"), []byte(listener.Addr().String()), 0600); err != nil {
			os.Exit(3)
		}
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			_ = connection.Close()
		}
	}
	for {
		time.Sleep(time.Hour)
	}
}

func TestOwnedProcessExitAndStop(t *testing.T) {
	for _, mode := range []string{"exit", "wait"} {
		t.Run(mode, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestOwnedProcessHelper$")
			cmd.Env = append(os.Environ(), "OPENFLUX_PROCESS_HELPER=1", "OPENFLUX_HELPER_MODE="+mode)
			child, err := startOwned(cmd)
			if err != nil {
				t.Fatal(err)
			}
			defer child.stop()
			if mode == "exit" {
				select {
				case <-child.done:
					if child.exitCode() != 37 {
						t.Fatal("exit status lost")
					}
				case <-time.After(5 * time.Second):
					t.Fatal("owned process failed to exit")
				}
			} else {
				child.stop()
				select {
				case <-child.done:
				case <-time.After(time.Second):
					t.Fatal("owned process not reaped")
				}
			}
		})
	}
}

func TestOwnedProcessStopIncludesDescendants(t *testing.T) {
	file := filepath.Join(t.TempDir(), "child-address")
	cmd := exec.Command(os.Args[0], "-test.run=^TestOwnedProcessHelper$")
	cmd.Env = append(os.Environ(), "OPENFLUX_PROCESS_HELPER=1", "OPENFLUX_HELPER_MODE=tree", "OPENFLUX_CHILD_ADDRESS_FILE="+file)
	parent, err := startOwned(cmd)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.stop()
	deadline := time.Now().Add(5 * time.Second)
	var address []byte
	for time.Now().Before(deadline) {
		address, _ = os.ReadFile(file)
		if len(address) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(address) == 0 {
		t.Fatal("grandchild failed to start")
	}
	connection, err := net.DialTimeout("tcp", string(address), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
	parent.stop()
	connection, err = net.DialTimeout("tcp", string(address), time.Second)
	if err == nil {
		_ = connection.Close()
		t.Fatal("owned grandchild survived cleanup")
	}
}

func TestManagedCLIEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("full CLI integration builds a binary")
	}
	dir := t.TempDir()
	binary := os.Getenv("OPENFLUX_TEST_BINARY")
	if binary == "" {
		goBin := filepath.Join(runtime.GOROOT(), "bin", "go")
		if runtime.GOOS == "windows" {
			goBin += ".exe"
		}
		if _, err := os.Stat(goBin); err != nil {
			t.Skip("native Go toolchain unavailable")
		}
		binary = filepath.Join(dir, "openflux")
		if runtime.GOOS == "windows" {
			binary += ".exe"
		}
		build := exec.Command(goBin, "build", "-o", binary, ".")
		if output, err := build.CombinedOutput(); err != nil {
			t.Fatalf("build: %v\n%s", err, output)
		}
	}
	// gVisor intentionally does not route 127/8 out through the virtual NIC.
	// Bind the fixture to a local non-loopback IPv4 address instead.
	var localIP net.IP
	addresses, _ := net.InterfaceAddrs()
	for _, address := range addresses {
		network, ok := address.(*net.IPNet)
		if ok && network.IP.To4() != nil && !network.IP.IsLoopback() {
			localIP = network.IP.To4()
			break
		}
	}
	if localIP == nil {
		t.Skip("non-loopback IPv4 address required for tunnel integration")
	}
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{localIP}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &private.PublicKey, private)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(bytes.Repeat([]byte("bulk-https"), 8192)) }))
	_ = server.Listener.Close()
	server.Listener, err = net.Listen("tcp", net.JoinHostPort(localIP.String(), "0"))
	if err != nil {
		t.Fatal(err)
	}
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: private}}}
	server.StartTLS()
	defer server.Close()
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(key, []byte("integration key 12345678901234567890"), 0600); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := ln.Addr().String()
	_ = ln.Close()
	conf := filepath.Join(dir, "client.conf")
	text := fmt.Sprintf("[Interface]\nRole = client\nEncryptionKeyFile = secret.txt\nForwardSecrecy = true\n[Transport \"direct\"]\nDial = %s\n", address)
	if err := os.WriteFile(conf, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	exitCmd := exec.Command(binary, "--role=exit", "--mode=l4", "--negotiate", "--forward-secrecy", "--transport=direct", "--direct-listen="+address, "--encryption-key-file="+key, "--debug=2")
	var exitLog boundedLog
	exitCmd.Stdout, exitCmd.Stderr = &exitLog, &exitLog
	exit, err := startOwned(exitCmd)
	if err != nil {
		t.Fatal(err)
	}
	defer exit.stop()
	// Doctor must authenticate both cryptographic layers and read a large TLS
	// response through a real direct carrier and HTTP CONNECT proxy.
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	doctor := exec.CommandContext(ctx, binary, "doctor", "--config="+conf, "--json", "--timeout=20s", "--probe-url="+server.URL, "--probe-ca-file="+ca)
	output, err := doctor.CombinedOutput()
	if err != nil {
		exitLog.mu.Lock()
		logs := string(exitLog.data)
		exitLog.mu.Unlock()
		t.Fatalf("doctor: %v\n%s\nExit diagnostics:\n%s", err, output, logs)
	}
	var report doctorReport
	if err := json.Unmarshal(output, &report); err != nil {
		t.Fatalf("report: %v\n%s", err, output)
	}
	if report.Session == nil || !report.Session.Authenticated || !report.Session.ForwardSecrecy {
		t.Fatal("doctor did not verify secure session")
	}
	// A managed application's exit code must survive cleanup; the parent
	// configuration lock must be reusable immediately afterwards.
	for i := 0; i < 2; i++ {
		command := exec.CommandContext(ctx, binary, "run", "--config="+conf, "--timeout=10s", "--", os.Args[0], "-test.run=^TestOwnedProcessHelper$")
		command.Env = append(os.Environ(), "OPENFLUX_PROCESS_HELPER=1", "OPENFLUX_HELPER_MODE=exit")
		output, err := command.CombinedOutput()
		exitError, ok := err.(*exec.ExitError)
		if !ok || exitError.ExitCode() != 37 {
			t.Fatalf("managed application: %v\n%s", err, output)
		}
	}
}
