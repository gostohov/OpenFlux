package transport

import (
	"encoding/binary"
	"testing"
)

type captureTransport struct {
	Transport
	cb func([]byte)
}

func (c *captureTransport) Receive(cb func([]byte)) { c.cb = cb }

type parameterCapture struct {
	captureTransport
	parameters PeerParameters
	ready      bool
}

func (c *parameterCapture) PeerParameters() (PeerParameters, bool) {
	return c.parameters, c.ready
}

func TestPortDemuxPreservesNegotiatedParameters(t *testing.T) {
	inner := &parameterCapture{parameters: PeerParameters{Capabilities: CapabilityIPv4 | CapabilityTCP, MaxPacketSize: 1280}, ready: true}
	demux := NewPortDemux(inner, 12000, 12999)
	for _, endpoint := range []Transport{demux, demux.Side()} {
		provider, ok := endpoint.(PeerParameterProvider)
		if !ok {
			t.Fatal("demux endpoint hides negotiated parameters")
		}
		if got, ready := provider.PeerParameters(); !ready || got != inner.parameters {
			t.Fatal("negotiated MTU or capabilities changed")
		}
		inner.ready = false
		if _, ready := provider.PeerParameters(); ready {
			t.Fatal("pending negotiation reported ready")
		}
		inner.ready = true
	}
	plain := NewPortDemux(&captureTransport{}, 12000, 12999)
	if _, ready := plain.PeerParameters(); ready {
		t.Fatal("legacy carrier reported negotiated parameters")
	}
}

func packetTo(proto byte, port uint16) []byte {
	p := make([]byte, 40)
	p[0] = 0x45
	p[9] = proto
	binary.BigEndian.PutUint16(p[22:24], port)
	return p
}

func TestPortDemuxSplitsByTCPDestinationPort(t *testing.T) {
	inner := &captureTransport{}
	d := NewPortDemux(inner, 12000, 12999)
	var main, side int
	d.Receive(func([]byte) { main++ })
	d.Side().Receive(func([]byte) { side++ })

	for _, p := range [][]byte{
		packetTo(6, 12000), packetTo(6, 12999), // side stack's TCP ports
		packetTo(6, 11999), packetTo(6, 13000), packetTo(6, 443), // main path
		packetTo(17, 12500), // UDP is never the side stack's
	} {
		inner.cb(p)
	}
	if side != 2 || main != 4 {
		t.Fatalf("side=%d main=%d, want 2 and 4", side, main)
	}

	frag := packetTo(6, 12000)
	binary.BigEndian.PutUint16(frag[6:8], 5) // non-first fragment: no TCP header
	inner.cb(frag)
	if main != 5 {
		t.Fatal("a non-first fragment was routed by bytes that are not a port")
	}
}
