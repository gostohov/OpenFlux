package mailru

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/p1neappleXpress/OpenFlux/transport"
)

// An admitted editor must send packets without synthetic document changes:
// the real backend now disconnects on saveChanges despite API edit=true.
func TestDefaultActivityDoesNotWriteButCursorPacketsStillSend(t *testing.T) {
	t.Setenv("OPENFLUX_MAILRU_EDITOR_ACTIVITY", "")
	frames := make(chan string, 4)
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		for {
			_, b, err := c.ReadMessage()
			if err != nil {
				return
			}
			frames <- string(b)
		}
	}))
	defer server.Close()
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	tr := NewMailruDocsTransport("test/document", transport.DefaultConfig())
	if err := tr.BaseTransport.Start(); err != nil {
		t.Fatal(err)
	}
	defer tr.BaseTransport.Stop()
	session := &DocSession{Conn: conn, WriteQueue: make(chan []byte, 1), Info: MailruDocsInfo{Permissions: map[string]interface{}{"edit": true}}}
	tr.session = session
	tr.SetConnected(true)
	stopped := make(chan struct{})
	go func() { tr.editorActivityLoop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("default editor activity continued to run")
	}
	writerStopped := make(chan struct{})
	go func() { tr.writerLoop(); close(writerStopped) }()
	if err := tr.Send([]byte("encrypted-session-hello")); err != nil {
		t.Fatal(err)
	}
	select {
	case frame := <-frames:
		if !strings.Contains(frame, `"type":"cursor"`) || !strings.Contains(frame, b64("encrypted-session-hello")) {
			t.Fatalf("expected cursor packet, got %q", frame)
		}
	case <-time.After(time.Second):
		t.Fatal("cursor packet was not sent")
	}
	close(session.WriteQueue)
	select {
	case <-writerStopped:
	case <-time.After(time.Second):
		t.Fatal("writer did not stop")
	}
}
