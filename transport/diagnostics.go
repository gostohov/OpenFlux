package transport

import (
	"sync/atomic"
)

// Diagnostic values are fixed codes, never URLs, tokens, cookies or payloads.
type CarrierDiagnostic struct {
	Phase         string `json:"phase"`
	Code          string `json:"code,omitempty"`
	HTTPStatus    int    `json:"http_status,omitempty"`
	LastErrorCode string `json:"last_error_code,omitempty"`
}

type DiagnosticState struct {
	current atomic.Pointer[CarrierDiagnostic]
}

func (d *DiagnosticState) Set(phase, code string, status int) {
	for {
		old := d.current.Load()
		next := &CarrierDiagnostic{Phase: phase, Code: code, HTTPStatus: status}
		if old != nil {
			next.LastErrorCode = old.LastErrorCode
		}
		if code != "" {
			next.LastErrorCode = code
		}
		if phase == "authenticated" {
			next.LastErrorCode = ""
		}
		if d.current.CompareAndSwap(old, next) {
			return
		}
	}
}
func (d *DiagnosticState) Snapshot() CarrierDiagnostic {
	if value := d.current.Load(); value != nil {
		return *value
	}
	return CarrierDiagnostic{Phase: "starting"}
}

type LinkDiagnostic struct {
	Name            string            `json:"name"`
	Connected       bool              `json:"connected"`
	Carrier         CarrierDiagnostic `json:"carrier"`
	QueuePackets    int               `json:"queue_packets"`
	QueueBytes      int               `json:"queue_bytes"`
	Retries         uint64            `json:"send_retries"`
	Expired         uint64            `json:"expired_frames"`
	BatchSendErrors uint64            `json:"batch_send_errors"`
	PFSReady        bool              `json:"pfs_ready"`
	Rejected        uint64            `json:"rejected_secure_frames"`
}
type SessionDiagnostic struct {
	Authenticated  bool             `json:"authenticated"`
	ForwardSecrecy bool             `json:"forward_secrecy"`
	State          string           `json:"state"`
	Links          []LinkDiagnostic `json:"links"`
}

func (s *Session) DiagnosticSnapshot() SessionDiagnostic {
	s.mu.Lock()
	out := SessionDiagnostic{Authenticated: s.ready && !s.stopped, ForwardSecrecy: s.forwardSecrecy, State: "connecting"}
	links := make([]*transportLink, 0, len(s.order))
	for _, name := range s.order {
		links = append(links, s.links[name])
	}
	s.mu.Unlock()
	if out.Authenticated {
		out.State = "ready"
	}
	for _, link := range links {
		item := LinkDiagnostic{Name: link.name, Connected: link.raw.IsConnected()}
		item.BatchSendErrors = link.batched.SendErrors()
		raw := link.raw
		if n, ok := raw.(*NoiseTransport); ok {
			item.PFSReady, item.Rejected = n.SecurityStatus()
			raw = n.Transport
		}
		if r, ok := raw.(*RecoveryTransport); ok {
			item.QueuePackets, item.QueueBytes, item.Retries, item.Expired = r.QueueStatus()
			raw = r.Transport
		}
		if d, ok := raw.(interface{ DiagnosticStatus() CarrierDiagnostic }); ok {
			item.Carrier = d.DiagnosticStatus()
		} else if raw.IsConnected() {
			item.Carrier.Phase = "connected"
		} else {
			item.Carrier.Phase = "connecting"
		}
		out.Links = append(out.Links, item)
	}
	return out
}
