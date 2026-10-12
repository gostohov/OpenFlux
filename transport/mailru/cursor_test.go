package mailru

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/p1neappleXpress/OpenFlux/transport"
)

func cursorEntry(payload string) string {
	return fmt.Sprintf(`{"cursor":"18;%s","time":1790800029352,"user":"anonX","useridoriginal":"anonX"}`, payload)
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// The server batches cursor entries into one message under load. Every data
// entry must come out, in order, and keep-alives anywhere in the batch must
// not cost the data around them.
func TestCursorPayloadsBatch(t *testing.T) {
	ka := cursorEntry("---KA---")
	cases := []struct {
		name string
		text string
		want []string
	}{
		{"one entry", `42["message",{"type":"cursor","messages":[` + cursorEntry(b64("one")) + `]}]`, []string{b64("one")}},
		{"batched data", `42["message",{"type":"cursor","messages":[` + cursorEntry(b64("a")) + "," + cursorEntry(b64("b")) + "," + cursorEntry(b64("c")) + `]}]`, []string{b64("a"), b64("b"), b64("c")}},
		{"keep-alive first, data behind it", `42["message",{"type":"cursor","messages":[` + ka + "," + cursorEntry(b64("data")) + `]}]`, []string{b64("data")}},
		{"data, keep-alive, data", `42["message",{"type":"cursor","messages":[` + cursorEntry(b64("x")) + "," + ka + "," + cursorEntry(b64("y")) + `]}]`, []string{b64("x"), b64("y")}},
		{"only a keep-alive", `42["message",{"type":"cursor","messages":[` + ka + `]}]`, nil},
		{"encoded keep-alive", `42["message",{"type":"cursor","messages":[` + cursorEntry(b64("---KA---")) + "," + cursorEntry(b64("data")) + `]}]`, []string{b64("data")}},
	}
	for _, c := range cases {
		if got := cursorPayloads(c.text); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

// Validate envelopes the same way as the editor, including packet sizes far
// larger than a real text cursor and the non-packet heartbeat marker.
func TestCursorEnvelopeUsesActualBinaryLength(t *testing.T) {
	for _, payload := range [][]byte{[]byte("---KA---"), []byte("test-transport"), bytes.Repeat([]byte{0, 255, 1}, 4096)} {
		var event []json.RawMessage
		frame := buildCursorMessage(payload)
		if err := json.Unmarshal(frame[2:], &event); err != nil {
			t.Fatal(err)
		}
		var body struct {
			Type   string `json:"type"`
			Cursor string `json:"cursor"`
		}
		if err := json.Unmarshal(event[1], &body); err != nil {
			t.Fatal(err)
		}
		parts := strings.SplitN(body.Cursor, ";", 2)
		if len(parts) != 2 || body.Type != "cursor" {
			t.Fatal("bad cursor envelope")
		}
		length, err := strconv.Atoi(parts[0])
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := base64.StdEncoding.DecodeString(parts[1])
		if err != nil {
			t.Fatal(err)
		}
		if length != len(decoded) || !bytes.Equal(decoded, payload) {
			t.Fatalf("length=%d decoded=%d wanted=%d", length, len(decoded), len(payload))
		}
	}
}

func TestHandleMessageDeliversEveryPacketOfABatch(t *testing.T) {
	tr := NewMailruDocsTransport("Vuri/test", transport.DefaultConfig())
	tr.SetConnected(true)
	var got []string
	tr.Receive(func(b []byte) { got = append(got, string(b)) })
	msg := `42["message",{"type":"cursor","messages":[` + cursorEntry("---KA---") + "," +
		cursorEntry(b64("first")) + "," + cursorEntry(b64("second")) + `]}]`
	tr.handleMessage(&DocSession{}, []byte(msg))
	if !reflect.DeepEqual(got, []string{"first", "second"}) {
		t.Fatalf("delivered %v, want [first second]", got)
	}
}

// A scheduled reconnect that is already waiting makes a second one a no-op.
func TestSecondReconnectWhileOneIsWaitingReturnsAtOnce(t *testing.T) {
	tr := NewMailruDocsTransport("AbCdEfGh1/IjKlMnOp2", transport.DefaultConfig())
	if err := tr.BaseTransport.Start(); err != nil {
		t.Fatal(err)
	}
	defer tr.BaseTransport.Stop()
	tr.reconnecting.Store(true)
	done := make(chan struct{})
	go func() { tr.scheduleReconnect(0); close(done) }()
	select {
	case <-done:
	case <-time.After(300 * time.Millisecond):
		t.Fatal("a second scheduled reconnect waited out its own backoff instead of yielding")
	}
}
