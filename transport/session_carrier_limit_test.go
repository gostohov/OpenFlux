package transport

import (
	"bytes"
	"sync/atomic"
	"testing"
	"time"

	"github.com/p1neappleXpress/OpenFlux/transport/control"
)

type recoverableNegotiationWire struct {
	*negotiationWire
	connected atomic.Bool
}

func (w *recoverableNegotiationWire) IsConnected() bool { return w.connected.Load() }

func TestSessionBuffersShortCarrierOutageWithoutNewHandshake(t *testing.T) {
	a, b := &negotiationWire{}, &negotiationWire{}
	a.peer, b.peer = b, a
	carrier := &recoverableNegotiationWire{negotiationWire: a}
	carrier.connected.Store(true)
	params := PeerParameters{Capabilities: control.CapabilityIPv4 | control.CapabilityTCP, MaxPacketSize: 1500}
	client, _ := NewSession(params, false)
	exit, _ := NewSession(params, true)
	t.Cleanup(func() { _ = client.Stop(); _ = exit.Stop() })
	if err := client.AddTransport("primary", carrier, testSessionSecret, testSessionCtx, 100); err != nil {
		t.Fatal(err)
	}
	if err := exit.AddTransport("primary", b, testSessionSecret, testSessionCtx, 100); err != nil {
		t.Fatal(err)
	}
	if err := exit.Start(); err != nil {
		t.Fatal(err)
	}
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	got := make(chan []byte, 1)
	exit.Receive(func(p []byte) { got <- append([]byte(nil), p...) })
	client.mu.Lock()
	peer := client.peer
	client.mu.Unlock()
	carrier.connected.Store(false)
	packet := testIPv4(1000, 6)
	if err := client.Send(packet); err != nil {
		t.Fatal("established session refused short-outage buffering:", err)
	}
	deadline := time.Now().Add(time.Second)
	buffered := false
	for time.Now().Before(deadline) {
		snapshot := client.DiagnosticSnapshot()
		if snapshot.Links[0].QueuePackets > 0 {
			buffered = true
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !buffered {
		t.Fatal("outage frame was not buffered")
	}
	carrier.connected.Store(true)
	select {
	case data := <-got:
		if !bytes.Equal(data, packet) {
			t.Fatal("buffer changed packet")
		}
	case <-time.After(time.Second):
		t.Fatal("buffered frame not delivered after reconnect")
	}
	client.mu.Lock()
	same := client.peer == peer && client.ready
	client.mu.Unlock()
	if !same {
		t.Fatal("short carrier outage replaced the session")
	}
}

type limitedNegotiationWire struct{ *negotiationWire }

func (*limitedNegotiationWire) BatchPacketLimit() int { return 1 }

func TestSessionCarrierLimitKeepsEncryptedBurstWithinMTU(t *testing.T) {
	t.Setenv("OPENFLUX_BATCH_COUNT", "64")
	a, b := &negotiationWire{}, &negotiationWire{}
	a.peer, b.peer = b, a
	params := PeerParameters{Capabilities: control.CapabilityIPv4 | control.CapabilityTCP, MaxPacketSize: 1500}
	client, err := NewSession(params, false)
	if err != nil {
		t.Fatal(err)
	}
	exit, err := NewSession(params, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Stop(); _ = exit.Stop() })
	if err := client.AddTransport("limited", &limitedNegotiationWire{a}, testSessionSecret, testSessionCtx, 100); err != nil {
		t.Fatal(err)
	}
	if err := exit.AddTransport("limited", &limitedNegotiationWire{b}, testSessionSecret, testSessionCtx, 100); err != nil {
		t.Fatal(err)
	}
	received := make(chan []byte, 8)
	exit.Receive(func(p []byte) { received <- append([]byte(nil), p...) })
	if err := exit.Start(); err != nil {
		t.Fatal(err)
	}
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	start := len(a.packets)
	a.mu.Unlock()
	for i := 0; i < 5; i++ {
		p := testIPv4(1500, 6)
		p[20] = byte(i)
		if err := client.Send(p); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 5; i++ {
		want := testIPv4(1500, 6)
		want[20] = byte(i)
		select {
		case got := <-received:
			if !bytes.Equal(got, want) {
				t.Fatalf("packet %d changed or reordered", i)
			}
		case <-time.After(time.Second):
			t.Fatal("missing packet from burst")
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, frame := range a.packets[start:] {
		if len(frame) > 1600 {
			t.Fatalf("carrier received coalesced encrypted frame: %d bytes", len(frame))
		}
	}
}
