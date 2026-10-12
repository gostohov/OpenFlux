package transport

import (
	"bytes"
	"testing"
	"time"

	"github.com/p1neappleXpress/OpenFlux/transport/control"
)

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
