package transport

import (
	"bytes"
	"sync/atomic"
	"testing"
	"time"
)

type outageCarrier struct {
	fakeTransport
	connected atomic.Bool
}

func (c *outageCarrier) IsConnected() bool          { return c.connected.Load() }
func (*outageCarrier) CarrierLimits() CarrierLimits { return CarrierLimits{MaxPayloadBytes: 96} }

func TestRecoveryBuffersOutageAndFragmentsWithinLimit(t *testing.T) {
	inner := &outageCarrier{}
	r, err := NewRecoveryTransport(inner, RecoveryOptions{QueueBytes: 1024, QueuePackets: 2, PacketTTL: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan []byte, 2)
	r.Receive(func(p []byte) { got <- append([]byte(nil), p...) })
	if err := r.Start(); err != nil {
		t.Fatal(err)
	}
	defer r.Stop()
	want := bytes.Repeat([]byte{0xa5}, 300)
	if err := r.Send(want); err != nil {
		t.Fatal(err)
	}
	if err := r.Send([]byte("after")); err != nil {
		t.Fatal(err)
	}
	if err := r.Send([]byte("overflow")); err != ErrCarrierQueueFull {
		t.Fatalf("queue bound: %v", err)
	}
	inner.connected.Store(true)
	deadline := time.Now().Add(time.Second)
	for inner.sendCount() < 6 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	inner.mu.Lock()
	frames := append([][]byte(nil), inner.sent...)
	inner.mu.Unlock()
	if len(frames) != 6 {
		t.Fatalf("sent %d fragments/frames", len(frames))
	}
	for _, f := range frames {
		if len(f) > 96 {
			t.Fatal("oversized carrier write")
		}
	}
	// Reassemble an out-of-order transfer and ignore duplicate fragments.
	for i := 4; i >= 0; i-- {
		r.receive(frames[i])
		if i == 4 {
			r.receive(frames[i])
		}
	}
	r.receive(frames[5])
	for _, expected := range [][]byte{want, []byte("after")} {
		select {
		case p := <-got:
			if !bytes.Equal(p, expected) {
				t.Fatal("payload/order changed")
			}
		case <-time.After(time.Second):
			t.Fatal("missing frame")
		}
	}
}

func TestRecoveryExpiryAndStopReleaseBufferedData(t *testing.T) {
	inner := &outageCarrier{}
	r, _ := NewRecoveryTransport(inner, RecoveryOptions{QueueBytes: 1024, QueuePackets: 2, PacketTTL: 20 * time.Millisecond})
	if err := r.Start(); err != nil {
		t.Fatal(err)
	}
	if err := r.Send([]byte("expires")); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		_, _, _, expired := r.QueueStatus()
		if expired > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	_, _, _, expired := r.QueueStatus()
	if expired != 1 {
		t.Fatal("frame did not expire")
	}
	if err := r.Send([]byte("pending")); err != nil {
		t.Fatal(err)
	}
	if err := r.Stop(); err != nil {
		t.Fatal(err)
	}
	count, size, _, _ := r.QueueStatus()
	if count != 0 || size != 0 {
		t.Fatal("stop retained payloads")
	}
	if err := r.Send([]byte("late")); err != ErrCarrierStopped {
		t.Fatal("send after stop admitted")
	}
}

func FuzzCarrierFragments(f *testing.F) {
	f.Add([]byte("OFF\x01invalid"))
	f.Add(make([]byte, 30))
	f.Fuzz(func(t *testing.T, p []byte) {
		r, _ := NewRecoveryTransport(&fakeTransport{}, DefaultRecoveryOptions())
		r.receive(p)
		if r.assemblyBytes > 1<<20 || len(r.assemblies) > 16 {
			t.Fatal("unbounded reassembly")
		}
	})
}
