package transport

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"runtime"
	"sync"
	"time"

	"github.com/flynn/noise"
	"golang.org/x/crypto/scrypt"
)

var noiseMagic = []byte{'O', 'F', 'N', 1}
var ErrNoisePending = errors.New("forward-secrecy handshake is pending")

const noiseHeader = 29
const (
	noiseInit    byte = 1
	noiseReply   byte = 2
	noiseData    byte = 3
	noiseConfirm byte = 4
)

type noiseEpoch struct {
	id                [16]byte
	send, recv        *noise.CipherState
	sequence, highest uint64
	window            replayWindow
	created, heard    time.Time
}
type noiseAttempt struct {
	id            [16]byte
	hs            *noise.HandshakeState
	epoch         *noiseEpoch
	message       []byte
	created, sent time.Time
}

// NoiseTransport adds opt-in Noise_NNpsk0_25519_AESGCM_SHA256 outside the
// existing encrypted Session protocol. There is no legacy/plaintext fallback.
// A candidate cannot replace an active epoch until it proves possession of
// the fresh DH keys. Handshake retries reuse wire bytes, never encrypt twice
// under the same nonce. Data counters permit bounded out-of-order delivery.
type NoiseTransport struct {
	Transport
	mu               sync.Mutex
	exit             bool
	psk              []byte
	prologue         []byte
	active           *noiseEpoch
	pending          *noiseAttempt
	lastConfirm      []byte
	cb               func([]byte)
	done             chan struct{}
	wg               sync.WaitGroup
	started, stopped bool
	rejected         uint64
}

func NewNoiseTransport(inner Transport, secret, binding string, exit bool) (*NoiseTransport, error) {
	salt := sha256.Sum256([]byte("OpenFlux Noise PSK v1\x00" + binding))
	psk, err := scrypt.Key([]byte(secret), salt[:], 32768, 8, 1, 32)
	if err != nil {
		return nil, err
	}
	return &NoiseTransport{Transport: inner, exit: exit, psk: psk, prologue: append([]byte("OpenFlux forward secrecy v1\x00"), salt[:]...), done: make(chan struct{})}, nil
}

func (n *NoiseTransport) handshake(initiator bool, id [16]byte) (*noise.HandshakeState, error) {
	prologue := append(append([]byte(nil), n.prologue...), id[:]...)
	return noise.NewHandshakeState(noise.Config{CipherSuite: noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256), Pattern: noise.HandshakeNN, Initiator: initiator, PresharedKey: n.psk, PresharedKeyPlacement: 0, Prologue: prologue})
}

func clearEphemeral(hs *noise.HandshakeState) {
	if hs != nil {
		key := hs.LocalEphemeral()
		clear(key.Private)
		runtime.KeepAlive(key)
	}
}

func noisePrefix(kind byte, id [16]byte, sequence uint64) []byte {
	header := make([]byte, noiseHeader)
	copy(header, noiseMagic)
	header[4] = kind
	copy(header[5:21], id[:])
	binary.BigEndian.PutUint64(header[21:29], sequence)
	return header
}

func (n *NoiseTransport) Start() error {
	n.mu.Lock()
	if n.stopped {
		n.mu.Unlock()
		return ErrCarrierStopped
	}
	if n.started {
		n.mu.Unlock()
		return nil
	}
	n.started = true
	n.mu.Unlock()
	n.Transport.Receive(n.receive)
	if err := n.Transport.Start(); err != nil {
		n.mu.Lock()
		n.started = false
		n.mu.Unlock()
		return err
	}
	n.wg.Add(1)
	go n.loop()
	return nil
}

func (n *NoiseTransport) Stop() error {
	n.mu.Lock()
	if !n.stopped {
		n.stopped = true
		close(n.done)
	}
	if n.pending != nil {
		clearEphemeral(n.pending.hs)
	}
	n.pending, n.active, n.lastConfirm = nil, nil, nil
	clear(n.psk)
	n.mu.Unlock()
	err := n.Transport.Stop()
	n.wg.Wait()
	return err
}

func (n *NoiseTransport) IsConnected() bool {
	n.mu.Lock()
	ready := n.active != nil && !n.stopped
	n.mu.Unlock()
	return ready && n.Transport.IsConnected()
}

func (n *NoiseTransport) Receive(cb func([]byte)) { n.mu.Lock(); n.cb = cb; n.mu.Unlock() }

func (n *NoiseTransport) Send(data []byte) error {
	n.mu.Lock()
	if n.active == nil || n.stopped {
		n.mu.Unlock()
		return ErrNoisePending
	}
	epoch := n.active
	if len(data)+16 > 65535 || epoch.sequence >= noise.MaxNonce {
		n.mu.Unlock()
		return errors.New("Noise frame/nonce limit exceeded; new handshake required")
	}
	epoch.sequence++
	header := noisePrefix(noiseData, epoch.id, epoch.sequence)
	epoch.send.SetNonce(epoch.sequence)
	frame, err := epoch.send.Encrypt(header, header, data)
	n.mu.Unlock()
	if err != nil {
		return err
	}
	return n.Transport.Send(frame)
}

func (n *NoiseTransport) beginLocked(now time.Time) error {
	if n.pending != nil {
		clearEphemeral(n.pending.hs)
	}
	attempt := &noiseAttempt{created: now}
	if _, err := rand.Read(attempt.id[:]); err != nil {
		return err
	}
	hs, err := n.handshake(true, attempt.id)
	if err != nil {
		return err
	}
	attempt.hs = hs
	message, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		clearEphemeral(hs)
		return err
	}
	attempt.message = append(noisePrefix(noiseInit, attempt.id, 0), message...)
	n.pending = attempt
	return nil
}

func (n *NoiseTransport) loop() {
	defer n.wg.Done()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-n.done:
			return
		case now := <-ticker.C:
			connected := n.Transport.IsConnected()
			n.mu.Lock()
			if n.stopped {
				n.mu.Unlock()
				return
			}
			if n.pending != nil && now.Sub(n.pending.created) > 10*time.Second {
				clearEphemeral(n.pending.hs)
				n.pending = nil
			}
			if !connected {
				n.mu.Unlock()
				continue
			}
			if !n.exit && n.pending == nil && (n.active == nil || now.Sub(n.active.heard) > 45*time.Second || now.Sub(n.active.created) > 30*time.Minute) {
				_ = n.beginLocked(now)
			}
			var frame []byte
			if n.pending != nil && now.Sub(n.pending.sent) >= time.Second {
				frame = append([]byte(nil), n.pending.message...)
				n.pending.sent = now
			}
			n.mu.Unlock()
			if frame != nil {
				_ = n.Transport.Send(frame)
			}
		}
	}
}

func (n *NoiseTransport) receive(frame []byte) {
	if len(frame) < noiseHeader+16 || len(frame) > noiseHeader+65535 || !bytes.HasPrefix(frame, noiseMagic) {
		return
	}
	var id [16]byte
	copy(id[:], frame[5:21])
	sequence := binary.BigEndian.Uint64(frame[21:29])
	var answer, plaintext []byte
	n.mu.Lock()
	if n.stopped {
		n.mu.Unlock()
		return
	}
	now := time.Now()
	switch frame[4] {
	case noiseInit:
		if !n.exit || sequence != 0 {
			break
		}
		if n.active != nil && n.active.id == id {
			break
		}
		if n.pending != nil && n.pending.id == id {
			answer = n.pending.message
			break
		}
		hs, err := n.handshake(false, id)
		if err != nil {
			break
		}
		payload, _, _, err := hs.ReadMessage(nil, frame[noiseHeader:])
		if err != nil || len(payload) != 0 {
			clearEphemeral(hs)
			n.rejected++
			break
		}
		reply, first, second, err := hs.WriteMessage(nil, nil)
		clearEphemeral(hs)
		if err != nil {
			break
		}
		epoch := &noiseEpoch{id: id, send: second, recv: first, created: now, heard: now}
		answer = append(noisePrefix(noiseReply, id, 0), reply...)
		n.pending = &noiseAttempt{id: id, epoch: epoch, message: answer, created: now}
	case noiseReply:
		if n.exit || sequence != 0 {
			break
		}
		if n.active != nil && n.active.id == id {
			answer = n.lastConfirm
			break
		}
		if n.pending == nil || n.pending.id != id || n.pending.hs == nil {
			break
		}
		payload, first, second, err := n.pending.hs.ReadMessage(nil, frame[noiseHeader:])
		if err != nil || len(payload) != 0 {
			n.rejected++
			break
		}
		clearEphemeral(n.pending.hs)
		epoch := &noiseEpoch{id: id, send: first, recv: second, created: now, heard: now}
		header := noisePrefix(noiseConfirm, id, 0)
		answer, err = first.Encrypt(header, header, []byte("OpenFlux key confirmation v1"))
		if err != nil {
			break
		}
		n.active, n.pending, n.lastConfirm = epoch, nil, answer
	case noiseConfirm:
		if !n.exit || sequence != 0 || n.pending == nil || n.pending.id != id || n.pending.epoch == nil {
			break
		}
		epoch := n.pending.epoch
		epoch.recv.SetNonce(0)
		proof, err := epoch.recv.Decrypt(nil, frame[:noiseHeader], frame[noiseHeader:])
		if err != nil || string(proof) != "OpenFlux key confirmation v1" {
			n.rejected++
			break
		}
		n.active, n.pending = epoch, nil
	case noiseData:
		if n.active == nil || n.active.id != id || sequence == 0 || sequence > noise.MaxNonce {
			break
		}
		epoch := n.active
		if sequence <= epoch.highest && (epoch.highest-sequence >= replayWindowSize || epoch.window.has(sequence)) {
			n.rejected++
			break
		}
		epoch.recv.SetNonce(sequence)
		var err error
		plaintext, err = epoch.recv.Decrypt(nil, frame[:noiseHeader], frame[noiseHeader:])
		if err != nil {
			plaintext = nil
			n.rejected++
			break
		}
		if sequence > epoch.highest {
			for i := epoch.highest + 1; i <= sequence && i-epoch.highest <= replayWindowSize; i++ {
				epoch.window.clear(i)
			}
			if sequence-epoch.highest >= replayWindowSize {
				epoch.window = replayWindow{}
			}
			epoch.highest = sequence
		}
		epoch.window.set(sequence)
		epoch.heard = now
	}
	cb := n.cb
	n.mu.Unlock()
	if answer != nil {
		_ = n.Transport.Send(answer)
	}
	if plaintext != nil && cb != nil {
		cb(plaintext)
	}
}

func (n *NoiseTransport) SecurityStatus() (ready bool, rejected uint64) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.active != nil && !n.stopped, n.rejected
}
