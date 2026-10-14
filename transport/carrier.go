package transport

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/p1neappleXpress/OpenFlux/utils"
)

// CarrierLimits are binary payload limits, after encryption and before the
// carrier's own Base64/JSON encoding. Zero means no additional restriction.
type CarrierLimits struct {
	MaxPayloadBytes   int
	MaxBatchPackets   int
	MessagesPerSecond int
	// Applied to the Session advertisement while registering bootstrap
	// carriers. It keeps routine IP traffic within a carrier's safe budget.
	MaxIPv4PacketBytes int
}

type LimitedCarrier interface{ CarrierLimits() CarrierLimits }

var (
	ErrCarrierQueueFull = errors.New("carrier recovery queue is full")
	ErrCarrierStopped   = errors.New("carrier recovery queue is stopped")
)

const fragmentHeader = 28

var fragmentMagic = []byte{'O', 'F', 'F', 1}

type RecoveryOptions struct {
	QueueBytes   int
	QueuePackets int
	PacketTTL    time.Duration
}

func DefaultRecoveryOptions() RecoveryOptions {
	return RecoveryOptions{QueueBytes: 4 << 20, QueuePackets: 256, PacketTTL: 30 * time.Second}
}

type recoveryFrame struct {
	data  []byte
	until time.Time
}
type fragmentAssembly struct {
	total, received int
	parts           [][]byte
	until           time.Time
}

// RecoveryTransport preserves FIFO ordering during short carrier outages.
// Acceptance means queued, not acknowledged by the remote peer. TCP still
// supplies delivery guarantees. Queues and unauthenticated reassembly are bounded.
type RecoveryTransport struct {
	Transport
	limits           CarrierLimits
	opts             RecoveryOptions
	mu               sync.Mutex
	queue            []recoveryFrame
	queuedBytes      int
	cb               func([]byte)
	assemblies       map[[16]byte]*fragmentAssembly
	assemblyBytes    int
	started, stopped bool
	done             chan struct{}
	wake             chan struct{}
	wg               sync.WaitGroup
	retries, expired uint64
}

func NewRecoveryTransport(inner Transport, opts RecoveryOptions) (*RecoveryTransport, error) {
	if opts.QueueBytes < 1 || opts.QueuePackets < 1 || opts.PacketTTL <= 0 {
		return nil, errors.New("invalid recovery queue limits")
	}
	limits := CarrierLimits{}
	if c, ok := inner.(LimitedCarrier); ok {
		limits = c.CarrierLimits()
	}
	if limits.MaxPayloadBytes != 0 && limits.MaxPayloadBytes <= fragmentHeader {
		return nil, errors.New("carrier payload limit is too small")
	}
	return &RecoveryTransport{Transport: inner, limits: limits, opts: opts, assemblies: make(map[[16]byte]*fragmentAssembly), done: make(chan struct{}), wake: make(chan struct{}, 1)}, nil
}

func (r *RecoveryTransport) Start() error {
	r.mu.Lock()
	if r.stopped {
		r.mu.Unlock()
		return ErrCarrierStopped
	}
	if r.started {
		r.mu.Unlock()
		return nil
	}
	r.started = true
	r.mu.Unlock()
	r.Transport.Receive(r.receive)
	if err := r.Transport.Start(); err != nil {
		r.mu.Lock()
		r.started = false
		r.mu.Unlock()
		return err
	}
	r.wg.Add(1)
	go r.writer()
	return nil
}

func (r *RecoveryTransport) Stop() error {
	r.mu.Lock()
	if !r.stopped {
		r.stopped = true
		close(r.done)
	}
	r.queue = nil
	r.queuedBytes = 0
	r.assemblies = make(map[[16]byte]*fragmentAssembly)
	r.assemblyBytes = 0
	r.mu.Unlock()
	err := r.Transport.Stop()
	r.wg.Wait()
	return err
}

func (r *RecoveryTransport) Send(data []byte) error {
	if len(data) == 0 || len(data) > 128<<10 {
		return errors.New("carrier frame size must be 1..131072 bytes")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.started || r.stopped {
		return ErrCarrierStopped
	}
	if len(r.queue) >= r.opts.QueuePackets || len(data) > r.opts.QueueBytes-r.queuedBytes {
		return ErrCarrierQueueFull
	}
	r.queue = append(r.queue, recoveryFrame{append([]byte(nil), data...), time.Now().Add(r.opts.PacketTTL)})
	r.queuedBytes += len(data)
	select {
	case r.wake <- struct{}{}:
	default:
	}
	return nil
}

func (r *RecoveryTransport) Receive(cb func([]byte)) { r.mu.Lock(); r.cb = cb; r.mu.Unlock() }

func (r *RecoveryTransport) frames(data []byte) ([][]byte, error) {
	limit := r.limits.MaxPayloadBytes
	if limit == 0 || len(data) <= limit {
		return [][]byte{data}, nil
	}
	chunk := limit - fragmentHeader
	count := (len(data) + chunk - 1) / chunk
	if count > 128 {
		return nil, errors.New("carrier frame requires too many fragments")
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, err
	}
	frames := make([][]byte, 0, count)
	for index, start := 0, 0; start < len(data); index, start = index+1, start+chunk {
		frame := make([]byte, fragmentHeader, fragmentHeader+min(chunk, len(data)-start))
		copy(frame, fragmentMagic)
		copy(frame[4:20], id[:])
		binary.BigEndian.PutUint32(frame[20:24], uint32(len(data)))
		binary.BigEndian.PutUint16(frame[24:26], uint16(index))
		binary.BigEndian.PutUint16(frame[26:28], uint16(count))
		frame = append(frame, data[start:min(start+chunk, len(data))]...)
		frames = append(frames, frame)
	}
	return frames, nil
}

func (r *RecoveryTransport) wait(delay time.Duration) bool {
	select {
	case <-r.done:
		return false
	case now := <-time.After(delay):
		r.mu.Lock()
		r.expireAssemblies(now)
		r.mu.Unlock()
		return true
	}
}

func (r *RecoveryTransport) expireAssemblies(now time.Time) {
	for id, part := range r.assemblies {
		if now.After(part.until) {
			r.assemblyBytes -= part.total
			delete(r.assemblies, id)
		}
	}
}

func (r *RecoveryTransport) writer() {
	defer r.wg.Done()
	sweep := time.NewTicker(time.Second)
	defer sweep.Stop()
	for {
		r.mu.Lock()
		if r.stopped {
			r.mu.Unlock()
			return
		}
		if len(r.queue) == 0 {
			r.mu.Unlock()
			select {
			case <-r.done:
				return
			case <-r.wake:
			case now := <-sweep.C:
				r.mu.Lock()
				r.expireAssemblies(now)
				r.mu.Unlock()
			}
			continue
		}
		item := r.queue[0]
		r.mu.Unlock()
		frames, err := r.frames(item.data)
		expired := false
		for _, frame := range frames {
			for err == nil {
				if time.Now().After(item.until) {
					expired = true
					break
				}
				if r.Transport.IsConnected() {
					if sendErr := r.Transport.Send(frame); sendErr == nil {
						break
					}
				}
				r.mu.Lock()
				r.retries++
				r.mu.Unlock()
				if !r.wait(100 * time.Millisecond) {
					return
				}
			}
			if expired || err != nil {
				break
			}
			if r.limits.MessagesPerSecond > 0 && !r.wait(time.Second/time.Duration(r.limits.MessagesPerSecond)) {
				return
			}
		}
		r.mu.Lock()
		if r.stopped {
			r.mu.Unlock()
			return
		}
		r.queue = r.queue[1:]
		r.queuedBytes -= len(item.data)
		if expired || err != nil {
			r.expired++
		}
		r.mu.Unlock()
		if expired || err != nil {
			utils.Infof("[RECOVERY] buffered frame expired or exceeded carrier limits; application may need to retry")
		}
	}
}

func (r *RecoveryTransport) receive(frame []byte) {
	var complete []byte
	r.mu.Lock()
	if r.stopped {
		r.mu.Unlock()
		return
	}
	if !bytes.HasPrefix(frame, fragmentMagic) {
		complete = frame
	} else if len(frame) > fragmentHeader {
		now := time.Now()
		for id, part := range r.assemblies {
			if now.After(part.until) {
				r.assemblyBytes -= part.total
				delete(r.assemblies, id)
			}
		}
		var id [16]byte
		copy(id[:], frame[4:20])
		total := int(binary.BigEndian.Uint32(frame[20:24]))
		index := int(binary.BigEndian.Uint16(frame[24:26]))
		count := int(binary.BigEndian.Uint16(frame[26:28]))
		payload := frame[fragmentHeader:]
		if total > 0 && total <= 128<<10 && count > 1 && count <= 128 && index < count && len(payload) <= total {
			part := r.assemblies[id]
			if part == nil && len(r.assemblies) < 16 && r.assemblyBytes+total <= 1<<20 {
				part = &fragmentAssembly{total: total, parts: make([][]byte, count), until: now.Add(15 * time.Second)}
				r.assemblies[id] = part
				r.assemblyBytes += total
			}
			if part != nil && part.total == total && len(part.parts) == count && part.parts[index] == nil && part.received+len(payload) <= total {
				part.parts[index] = append([]byte(nil), payload...)
				part.received += len(payload)
				all := part.received == total
				for _, p := range part.parts {
					all = all && p != nil
				}
				if all {
					complete = make([]byte, 0, total)
					for _, p := range part.parts {
						complete = append(complete, p...)
					}
					r.assemblyBytes -= total
					delete(r.assemblies, id)
				}
			}
		}
	}
	cb := r.cb
	r.mu.Unlock()
	if len(complete) > 0 && cb != nil {
		cb(complete)
	}
}

func (r *RecoveryTransport) QueueStatus() (packets, size int, retried, expired uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.queue), r.queuedBytes, r.retries, r.expired
}

func (r *RecoveryTransport) String() string {
	return fmt.Sprintf("recovery(maxPayload=%d)", r.limits.MaxPayloadBytes)
}
