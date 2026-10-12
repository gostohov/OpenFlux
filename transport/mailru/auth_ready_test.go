package mailru

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/p1neappleXpress/OpenFlux/transport"
)

func TestSendWaitsForEditorAuthentication(t *testing.T) {
	tr := NewMailruDocsTransport("test/document", transport.DefaultConfig())
	session := &DocSession{WriteQueue: make(chan []byte, 1), UserID: "test"}
	tr.session = session
	payload := []byte("encrypted-session-hello")
	if err := tr.Send(payload); err == nil {
		t.Fatal("sent before editor authentication")
	}
	for _, frame := range []string{`40{"sid":"socket-ready"}`, `42["message",{"type":"auth","result":0}]`} {
		tr.handleMessage(session, []byte(frame))
		if tr.IsConnected() {
			t.Fatal("Socket.IO or rejected auth admitted the transport")
		}
	}
	tr.handleMessage(&DocSession{}, []byte(`42["message",{"type":"auth","result":1}]`))
	if tr.IsConnected() {
		t.Fatal("a stale editor session admitted the transport")
	}
	tr.handleMessage(session, []byte(`42["message",{"type":"auth","result":1}]`))
	if !tr.IsConnected() {
		t.Fatal("editor authentication did not admit the transport")
	}
	if err := tr.Send(payload); err != nil {
		t.Fatalf("send after editor authentication: %v", err)
	}
	if got := <-session.WriteQueue; !bytes.Equal(got, payload) {
		t.Fatalf("queued payload = %q", got)
	}
}

func TestIncomingCursorWaitsForEditorAuthentication(t *testing.T) {
	tr := NewMailruDocsTransport("test/document", transport.DefaultConfig())
	session := &DocSession{UserID: "test"}
	tr.session = session
	var received [][]byte
	tr.Receive(func(p []byte) { received = append(received, append([]byte(nil), p...)) })
	frame := []byte(`42["message",{"type":"cursor","messages":[{"cursor":"18;aGVsbG8="}]}]`)
	tr.handleMessage(session, frame)
	if len(received) != 0 {
		t.Fatal("accepted a peer hello before editor authentication")
	}
	tr.handleMessage(session, []byte(`42["message",{"type":"auth","result":1}]`))
	tr.handleMessage(session, frame)
	if len(received) != 1 || string(received[0]) != "hello" {
		t.Fatal("did not deliver the peer hello after editor authentication")
	}
}

func TestEditorChangesAcknowledgedBeforeAuthentication(t *testing.T) {
	acks := make(chan string, 1)
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		if err := conn.WriteMessage(websocket.TextMessage, []byte(`42["message",{"type":"authChanges","changes":[]}]`)); err != nil {
			t.Error(err)
			return
		}
		_, ack, err := conn.ReadMessage()
		if err != nil {
			t.Error(err)
			return
		}
		acks <- string(ack)
		if err := conn.WriteMessage(websocket.TextMessage, []byte(`42["message",{"type":"auth","result":1}]`)); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	tr := NewMailruDocsTransport("test/document", transport.DefaultConfig())
	session := &DocSession{Conn: conn, WriteQueue: make(chan []byte, 1), UserID: "test"}
	tr.session = session
	for i := 0; i < 2; i++ {
		_, frame, err := conn.ReadMessage()
		if err != nil {
			t.Fatal(err)
		}
		tr.handleMessage(session, frame)
	}
	if got := <-acks; got != `42["message",{"type":"authChangesAck"}]` {
		t.Fatalf("auth acknowledgment = %q", got)
	}
	if !tr.IsConnected() {
		t.Fatal("auth did not complete after acknowledgment")
	}
}

func TestWaitingEditorUnlockRequiresCurrentAuthenticatedSession(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		ready, current, waiting bool
		wantUnlock              bool
	}{
		{"admitted editor releases its auth lock", true, true, true, true},
		{"unauthenticated editor cannot release", false, true, true, false},
		{"stale session cannot release", true, false, true, false},
		{"normal participant update keeps locks", true, true, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			frames := make(chan string, 1)
			upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				conn, err := upgrader.Upgrade(w, r, nil)
				if err != nil {
					frames <- "upgrade failed"
					return
				}
				defer conn.Close()
				_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
				_, frame, err := conn.ReadMessage()
				if err != nil {
					frames <- ""
					return
				}
				frames <- string(frame)
			}))
			defer server.Close()
			conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			tr := NewMailruDocsTransport("test/document", transport.DefaultConfig())
			session := &DocSession{Conn: conn, UserID: "test"}
			if tc.current {
				tr.session = session
			} else {
				tr.session = &DocSession{}
			}
			tr.SetConnected(tc.ready)
			waiting := "false"
			if tc.waiting {
				waiting = "true"
			}
			tr.handleMessage(session, []byte(`42["message",{"type":"connectState","waitAuth":`+waiting+`}]`))
			want := ""
			if tc.wantUnlock {
				want = `42["message",{"type":"unLockDocument","isSave":false,"unlock":true,"deleteIndex":null,"releaseLocks":false}]`
			}
			if got := <-frames; got != want {
				t.Fatalf("lock response = %q, want %q", got, want)
			}
		})
	}
}

func TestRetiredDocumentVersionDisconnectsOnlyCurrentSession(t *testing.T) {
	for _, tc := range []struct {
		name               string
		code               int
		current, wantClose bool
	}{
		{"retired current document", 4008, true, true},
		{"retired stale session", 4008, false, false},
		{"unrelated server code", 4004, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			closed := make(chan bool, 1)
			upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				conn, err := upgrader.Upgrade(w, r, nil)
				if err != nil {
					closed <- false
					return
				}
				defer conn.Close()
				_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
				_, _, err = conn.ReadMessage()
				if networkError, ok := err.(net.Error); ok && networkError.Timeout() {
					closed <- false
					return
				}
				closed <- err != nil
			}))
			defer server.Close()
			conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			tr := NewMailruDocsTransport("test/document", transport.DefaultConfig())
			session := &DocSession{Conn: conn}
			if tc.current {
				tr.session = session
			} else {
				tr.session = &DocSession{}
			}
			tr.SetConnected(true)
			tr.handleMessage(session, []byte(fmt.Sprintf(`42["message",{"type":"error","code":%d}]`, tc.code)))
			if got := <-closed; got != tc.wantClose {
				t.Fatalf("connection closed = %v, want %v", got, tc.wantClose)
			}
			if tr.IsConnected() == tc.wantClose {
				t.Fatalf("connected = %v", tr.IsConnected())
			}
		})
	}
}
