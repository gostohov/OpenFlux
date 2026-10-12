package transport

import (
	"bytes"
	"testing"
	"time"
)

func noisePair(t *testing.T, secret string) (*NoiseTransport, *NoiseTransport, *negotiationWire, *negotiationWire) {
	t.Helper()
	a, b := &negotiationWire{}, &negotiationWire{}
	a.peer, b.peer = b, a
	client, err := NewNoiseTransport(a, testSessionSecret, testSessionCtx, false)
	if err != nil {
		t.Fatal(err)
	}
	exit, err := NewNoiseTransport(b, secret, testSessionCtx, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Stop(); _ = exit.Stop() })
	if err := exit.Start(); err != nil {
		t.Fatal(err)
	}
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	return client, exit, a, b
}
func waitNoise(t *testing.T, a, b *NoiseTransport) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if a.IsConnected() && b.IsConnected() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("Noise handshake did not complete")
}

func TestNoiseAuthenticatedDuplexReplayAndReordering(t *testing.T) {
	a, b, wire, _ := noisePair(t, testSessionSecret)
	waitNoise(t, a, b)
	got := make(chan []byte, 8)
	b.Receive(func(p []byte) { got <- p })
	reply := make(chan []byte, 1)
	a.Receive(func(p []byte) { reply <- p })
	if err := b.Send([]byte("response")); err != nil {
		t.Fatal(err)
	}
	if p := <-reply; string(p) != "response" {
		t.Fatal("reverse direction failed")
	}
	wire.mu.Lock()
	wire.drop = true
	start := len(wire.packets)
	wire.mu.Unlock()
	for _, p := range []string{"first", "second"} {
		if err := a.Send([]byte(p)); err != nil {
			t.Fatal(err)
		}
	}
	wire.mu.Lock()
	frames := append([][]byte(nil), wire.packets[start:]...)
	wire.mu.Unlock()
	tampered := append([]byte(nil), frames[0]...)
	tampered[22] ^= 0x40
	b.receive(tampered)
	b.receive(frames[1])
	b.receive(frames[0])
	b.receive(frames[0])
	for _, want := range []string{"second", "first"} {
		select {
		case p := <-got:
			if string(p) != want {
				t.Fatal("message changed")
			}
		case <-time.After(time.Second):
			t.Fatal("missing secure data")
		}
	}
	select {
	case <-got:
		t.Fatal("tampered/replayed data admitted")
	default:
	}
	// Unencrypted legacy data must not be delivered in secure mode.
	b.receive([]byte("OFX\x01plaintext"))
	select {
	case <-got:
		t.Fatal("legacy downgrade admitted")
	default:
	}
}

func TestNoiseRejectsWrongPSK(t *testing.T) {
	a, b, _, _ := noisePair(t, "different secret 123456789")
	time.Sleep(400 * time.Millisecond)
	if a.IsConnected() || b.IsConnected() {
		t.Fatal("wrong PSK authenticated")
	}
	_, rejected := b.SecurityStatus()
	if rejected == 0 {
		t.Fatal("wrong-key handshake not checked")
	}
}

func TestNoiseFreshRekeyAndReplayedHandshakeCannotDisplacePeer(t *testing.T) {
	a, b, wire, _ := noisePair(t, testSessionSecret)
	waitNoise(t, a, b)
	a.mu.Lock()
	oldID := a.active.id
	oldKey := a.active.send.UnsafeKey()
	a.mu.Unlock()
	wire.mu.Lock()
	var oldInit, oldConfirm []byte
	for _, p := range wire.packets {
		if len(p) > 4 && p[4] == noiseInit {
			oldInit = append([]byte(nil), p...)
		}
		if len(p) > 4 && p[4] == noiseConfirm {
			oldConfirm = append([]byte(nil), p...)
		}
	}
	wire.mu.Unlock()
	a.mu.Lock()
	if err := a.beginLocked(time.Now()); err != nil {
		t.Fatal(err)
	}
	a.mu.Unlock()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		a.mu.Lock()
		changed := a.active.id != oldID
		a.mu.Unlock()
		if changed {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	a.mu.Lock()
	newID := a.active.id
	newKey := a.active.send.UnsafeKey()
	a.mu.Unlock()
	if newID == oldID || bytes.Equal(oldKey[:], newKey[:]) {
		t.Fatal("rekey reused epoch/key")
	}
	b.receive(oldInit)
	b.receive(oldConfirm)
	b.mu.Lock()
	id := b.active.id
	b.mu.Unlock()
	if id != newID {
		t.Fatal("recorded handshake displaced authenticated epoch")
	}
	got := make(chan []byte, 1)
	b.Receive(func(p []byte) { got <- p })
	if err := a.Send([]byte("still connected")); err != nil {
		t.Fatal(err)
	}
	select {
	case p := <-got:
		if string(p) != "still connected" {
			t.Fatal("changed payload")
		}
	case <-time.After(time.Second):
		t.Fatal("replayed handshake broke active data")
	}
}
