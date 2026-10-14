package mailru

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/p1neappleXpress/OpenFlux/transport"
)

func TestQueuedCursorWaitsForEditorAdmission(t *testing.T) {
	frames := make(chan []byte, 2)
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connection, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		defer connection.Close()
		for {
			_, frame, err := connection.ReadMessage()
			if err != nil {
				return
			}
			frames <- frame
		}
	}))
	defer server.Close()
	connection, _, err := websocket.DefaultDialer.Dial(strings.Replace(server.URL, "http", "ws", 1), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	tr := NewMailruDocsTransport("test/document", transport.DefaultConfig())
	if err := tr.BaseTransport.Start(); err != nil {
		t.Fatal(err)
	}
	defer tr.Stop()
	// Reconnects reuse a queue containing frames accepted on the old socket.
	session := &DocSession{Conn: connection, WriteQueue: make(chan []byte, 2), UserID: "test"}
	tr.session = session
	payload := []byte("queued-before-reconnect")
	session.WriteQueue <- payload
	done := make(chan struct{})
	go func() { defer close(done); tr.writerLoop() }()
	defer func() {
		_ = tr.Stop()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("writer did not stop")
		}
	}()
	select {
	case <-frames:
		t.Fatal("queued cursor reached the editor before authentication")
	case <-time.After(100 * time.Millisecond):
	}
	tr.handleMessage(session, []byte(`42["message",{"type":"auth","result":1}]`))
	select {
	case frame := <-frames:
		if !bytes.Equal(frame, buildCursorMessage(payload)) {
			t.Fatal("queued payload was not preserved")
		}
	case <-time.After(time.Second):
		t.Fatal("authenticated writer did not resume")
	}
}

func TestCursorEncodingFitsConservativeWireBudget(t *testing.T) {
	tr := NewMailruDocsTransport("test/document", transport.DefaultConfig())
	frame := buildCursorMessage(make([]byte, tr.CarrierLimits().MaxPayloadBytes))
	if len(frame) > 2048 {
		t.Fatalf("cursor envelope is %d bytes, exceeding the conservative 2048-byte wire budget", len(frame))
	}
}
