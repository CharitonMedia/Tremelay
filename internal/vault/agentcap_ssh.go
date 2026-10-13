package vault

import (
	"context"
	"encoding/binary"
	"sync"
)

// capSSHEpoch belongs to one Serve call. It never escapes to raw Exchange.
// Tombstones count toward the bound and are not evicted or reset within an epoch.
// Only the MCP handler processes a stream; cancellation merely marks retirement.
// No epoch lock is held during vault work, callbacks, stream Close, or I/O.
type capSSHEpoch struct {
	mu     sync.Mutex
	closed bool
	slots  map[[32]byte]*capSSHSlot
}
type capSSHSlot struct {
	stream  *SSHUserAuth
	retired bool
	active  bool
}

func newCapSSHEpoch() *capSSHEpoch {
	return &capSSHEpoch{slots: make(map[[32]byte]*capSSHSlot)}
}

func (e *capSSHEpoch) stream(handle [32]byte, broker sshBroker, agentID string, bound agentCapGrant) (*SSHUserAuth, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil, false
	}
	slot := e.slots[handle]
	if slot == nil {
		if len(e.slots) >= maxAgentCapEntries {
			return nil, false
		}
		slot = &capSSHSlot{}
		e.slots[handle] = slot
	}
	if slot.retired || slot.active {
		return nil, false
	}
	if slot.stream == nil {
		slot.stream = &SSHUserAuth{broker: broker, agentID: agentID, bound: bound}
	}
	slot.active = true
	return slot.stream, true
}

// retire never waits on the stream. In particular the transport reader can
// forward cancellation while a handler is inside an unlocked vault callback.
func (e *capSSHEpoch) retire(handle [32]byte) *SSHUserAuth {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil
	}
	if slot := e.slots[handle]; slot != nil {
		slot.retired = true
		if !slot.active {
			stream := slot.stream
			slot.stream = nil
			return stream
		}
	} else if len(e.slots) < maxAgentCapEntries {
		e.slots[handle] = &capSSHSlot{retired: true}
	} else {
		e.closed = true
	}
	return nil
}

// release runs after roundTrip has relinquished the stream lock. Only a
// retired or stopped slot is detached; its tombstone remains until teardown.
func (e *capSSHEpoch) release(handle [32]byte, active *SSHUserAuth) {
	e.mu.Lock()
	var stream *SSHUserAuth
	if slot := e.slots[handle]; slot != nil && slot.active && slot.stream == active {
		slot.active = false
		if slot.retired || e.closed {
			stream = slot.stream
			slot.stream = nil
		}
	}
	e.mu.Unlock()
	stream.Close()
}

func (e *capSSHEpoch) retireAndClose(handle [32]byte) { e.retire(handle).Close() }

func (e *capSSHEpoch) usable(handle [32]byte) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	slot := e.slots[handle]
	return !e.closed && slot != nil && !slot.retired
}

// stop transfers ownership of idle streams to the caller, which closes them
// after releasing the endpoint lock. Active streams belong to handler release.
func (e *capSSHEpoch) stop() []*SSHUserAuth {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.closed = true
	var idle []*SSHUserAuth
	for _, slot := range e.slots {
		if !slot.active && slot.stream != nil {
			idle = append(idle, slot.stream)
			slot.stream = nil
		}
	}
	return idle
}

// close is called only after SDK dispatch and output have joined. Stream
// buffers are wiped, then this epoch and all its tombstones are discarded.
func (e *capSSHEpoch) close() {
	if e == nil {
		return
	}
	e.mu.Lock()
	e.closed = true
	slots := e.slots
	e.slots = nil
	e.mu.Unlock()
	for _, slot := range slots {
		if slot.stream != nil {
			slot.stream.Close()
		}
	}
}

func disclosedCapKey(op, key string) string {
	if op == OpLocalArtifactAttest {
		return key
	}
	return ""
}

func (a *AgentCapability) denySSH(bound agentCapGrant) error {
	broker, ok := a.broker.(sshBroker)
	if !ok {
		return ErrUnauthenticated
	}
	return broker.sshDeny(a.agentID, bound)
}

func (a *AgentCapability) invokeSSH(ctx context.Context, handle [32]byte, bound agentCapGrant, body []byte, epoch *capSSHEpoch) ([]byte, error) {
	broker, ok := a.broker.(sshBroker)
	if !ok {
		return nil, ErrUnauthenticated
	}
	deny := func() ([]byte, error) {
		if err := broker.sshDeny(a.agentID, bound); err != nil {
			return nil, err
		}
		return encodeCapError(capDenied)
	}
	if epoch == nil {
		return deny()
	}
	if ctx != nil && ctx.Err() != nil {
		epoch.retireAndClose(handle)
		return deny()
	}
	stream, ok := epoch.stream(handle, broker, a.agentID, bound)
	if !ok {
		return deny()
	}
	defer epoch.release(handle, stream)
	response, err := stream.roundTrip(body)
	defer wipe(response)
	if err != nil {
		epoch.retireAndClose(handle)
		if capHost(err) {
			return nil, err
		}
		return encodeCapError(capFromErr(err))
	}
	if ctx != nil && ctx.Err() != nil {
		epoch.retireAndClose(handle)
	}
	// This check also covers cancellation delivered after the SSH operation
	// finished but before its MCP response is constructed. A completed audit
	// remains a release approval, never a promise that the peer saw the bytes.
	if !epoch.usable(handle) {
		return encodeCapError(capDenied)
	}
	if !validCapSSHResponse(response) {
		epoch.retireAndClose(handle)
		return nil, ErrInvalid
	}
	return encodeCap(capMethodInvoke, []capWire{{id: capFieldSSHResponse, typ: capTypeBytes, val: response}})
}

// The bridge returns only the existing closed SSH-agent subset, unframed.
// No parser text, outer transport length, key comment, or generic signature.
func validCapSSHResponse(body []byte) bool {
	if len(body) == 0 || len(body) > 88 {
		return false
	}
	switch body[0] {
	case sshAgentFailure, sshAgentSuccess, sshAgentExtensionFailure:
		return len(body) == 1
	case sshAgentIdentitiesAnswer:
		if len(body) < 5 {
			return false
		}
		switch binary.BigEndian.Uint32(body[1:5]) {
		case 0:
			return len(body) == 5
		case 1:
			key, rest, ok := takeSSHBytes(body[5:], sshEd25519BlobLen)
			if !ok || !canonicalSSHEd25519Blob(key) {
				return false
			}
			comment, rest, ok := takeSSHBytes(rest, 0)
			return ok && len(comment) == 0 && len(rest) == 0
		}
	case sshAgentSignResponse:
		sig, rest, ok := takeSSHBytes(body[1:], sshEd25519SigLen)
		if !ok || len(rest) != 0 {
			return false
		}
		raw, ok := parseEd25519Sig(sig)
		wipe(raw)
		return ok
	}
	return false
}

// Called only for an admitted-shape invoke, before taking the endpoint lock.
// This resolution is for cancellation/denial attribution, never authorization.
func (a *AgentCapability) resolveSSHFrame(frame []byte, invoke bool) (*agentCapGrant, [32]byte) {
	var handle [32]byte
	if !invoke {
		return nil, handle
	}
	v, err := parseJSONValue(frame)
	if err != nil {
		return nil, handle
	}
	params, _ := v.field("params")
	args, _ := params.field("arguments")
	h, _ := args.field("handle")
	raw, ok := canonicalB64(h.s, 32)
	if !ok {
		return nil, handle
	}
	copy(handle[:], raw)
	bound, ok := a.lookup(handle)
	if !ok || bound.operation != OpSSHUserAuth {
		return nil, handle
	}
	return &bound, handle
}
