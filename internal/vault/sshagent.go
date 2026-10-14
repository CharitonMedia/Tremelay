package vault

import (
	"encoding/binary"
	"io"
	"sync"
)

// SSHAgent is one ssh-agent-protocol conversation for one agent principal. It
// owns one ADR 0013 stream per active ssh_userauth grant that principal holds
// and forwards each frame to those streams.
//
// It adds no authority of its own: the grant shape, the required host-key
// binding, the userauth preimage rules, the release checks and every audit
// row belong to the per-grant stream. A frame cannot choose the principal, a
// grant, a credential, the clock, or a host key. The only identity material
// that leaves is a granted public key, and only after that grant's own host
// proof. Private keys never leave the broker.
type SSHAgent struct {
	broker  sshBroker
	agentID string

	mu      sync.Mutex
	closed  bool
	streams []*SSHUserAuth
}

// SSHAgent binds one conversation to every active ssh_userauth grant this
// principal currently holds. Grants issued later need a new conversation; a
// grant revoked or expired later still fails on use. A grant that cannot be
// bound is skipped: it has no identity to disclose and no authority to use.
func (a *AgentPrincipal) SSHAgent() (*SSHAgent, error) {
	if a == nil || a.view == nil {
		return nil, ErrUnauthenticated
	}
	broker, ok := a.view.(sshBroker)
	if !ok {
		return nil, ErrUnauthenticated
	}
	caps, err := a.Capabilities()
	if err != nil {
		return nil, err
	}
	m := &SSHAgent{broker: broker, agentID: a.id}
	for _, c := range caps {
		if !soleSSH(c.Operations) || c.Status != GrantActive {
			continue
		}
		if len(m.streams) >= maxAgentCapEntries {
			m.Close()
			return nil, ErrInvalid
		}
		stream, err := a.SSHUserAuth(c.GrantID)
		if err != nil {
			if stopSSH(err) {
				m.Close()
				return nil, err
			}
			continue
		}
		m.streams = append(m.streams, stream)
	}
	return m, nil
}

// Serve reads agent frames from rw until EOF, with the per-grant stream's
// frame contract: a clean EOF before the next frame is nil, a short, partial
// or oversize frame is ErrInvalid, and any other transport failure is fixed.
// Close runs on every return and wipes every binding.
func (m *SSHAgent) Serve(rw io.ReadWriter) error {
	if m == nil || m.broker == nil {
		return ErrUnauthenticated
	}
	defer m.Close()
	for {
		body, err := readSSHFrame(rw)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return m.noteFrameErr(err)
		}
		resp, herr := m.dispatch(body)
		wipe(body)
		if herr != nil {
			return herr
		}
		if _, werr := rw.Write(frameSSH(resp)); werr != nil {
			wipe(resp)
			return errSSHTransport
		}
		wipe(resp)
	}
}

// Close wipes every stream's binding and refuses later frames. Like the
// per-grant stream it does not interrupt a blocked read or write: the host
// must close the transport and wait for Serve to return before locking the
// session.
func (m *SSHAgent) Close() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	for _, s := range m.streams {
		s.Close()
	}
}

func (m *SSHAgent) noteFrameErr(err error) error {
	for _, s := range m.streams {
		if e := s.noteFrameErr(err); stopSSH(e) {
			return e
		}
	}
	return fixedStreamErr(err)
}

func (m *SSHAgent) dispatch(body []byte) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, ErrInvalid
	}
	if len(body) == 1 && body[0] == sshAgentRequestIdentities {
		return m.identities()
	}
	// A principal whose grants are all absent, revoked or expired owns no
	// stream, so no stream can record the denial this attempt owes
	// (invariant 4). The row is the conversation's own: it names the
	// principal and the operation, and nothing from the frame. Listing
	// identities is not a credential attempt and is not recorded here.
	if len(m.streams) == 0 && len(body) > 0 && body[0] == sshAgentSignRequest {
		if err := m.broker.sshDenyNoGrant(m.agentID); err != nil {
			return nil, err
		}
		return []byte{sshAgentFailure}, nil
	}
	// Every other message is the per-grant codec's decision. A binding goes
	// to all of them, because each grant pins its own host key and needs its
	// own proof. Anything else stops at the first grant that answers with
	// something other than a failure byte, so one request releases at most
	// one signature and every grant that refused recorded its own denial.
	//
	// ponytail: that costs up to one denial row per other grant on every
	// signature, bounded by the 64-grant cap. Upgrade path: remember which
	// grant disclosed each identity and offer that grant first.
	broadcast := body[0] == sshAgentExtension
	var answer []byte
	for _, s := range m.streams {
		resp, err := s.roundTrip(body)
		if err != nil {
			wipe(answer)
			return nil, err
		}
		if !sshFailureByte(resp) && !broadcast {
			wipe(answer)
			return resp, nil
		}
		if answer == nil || (sshFailureByte(answer) && !sshFailureByte(resp)) {
			wipe(answer)
			answer = resp
			continue
		}
		wipe(resp)
	}
	if answer == nil {
		answer = []byte{sshAgentFailure}
	}
	return answer, nil
}

// identities merges the per-grant answers into one list. A grant that is not
// bound, or whose checks no longer pass, contributes no key.
func (m *SSHAgent) identities() ([]byte, error) {
	var blobs [][]byte
	for _, s := range m.streams {
		resp, err := s.roundTrip([]byte{sshAgentRequestIdentities})
		if err != nil {
			return nil, err
		}
		blob := identityBlob(resp)
		wipe(resp)
		if blob != nil && !containsBlob(blobs, blob) {
			blobs = append(blobs, blob)
		}
	}
	return sshIdentityList(blobs), nil
}

func containsBlob(blobs [][]byte, blob []byte) bool {
	for _, b := range blobs {
		if sshBytesEq(b, blob) {
			return true
		}
	}
	return false
}

func sshFailureByte(resp []byte) bool {
	return len(resp) == 1 && (resp[0] == sshAgentFailure || resp[0] == sshAgentExtensionFailure)
}

// identityBlob accepts only the closed one-key answer this codec emits.
func identityBlob(resp []byte) []byte {
	if len(resp) < 5 || resp[0] != sshAgentIdentitiesAnswer || binary.BigEndian.Uint32(resp[1:5]) != 1 {
		return nil
	}
	blob, rest, ok := takeSSHBytes(resp[5:], sshEd25519BlobLen)
	if !ok || !canonicalSSHEd25519Blob(blob) {
		return nil
	}
	comment, rest, ok := takeSSHBytes(rest, 0)
	if !ok || len(comment) != 0 || len(rest) != 0 {
		return nil
	}
	return dup(blob)
}

func sshIdentityList(blobs [][]byte) []byte {
	body := appendU32([]byte{sshAgentIdentitiesAnswer}, len(blobs))
	for _, blob := range blobs {
		body = appendSSHString(body, blob)
		body = appendSSHString(body, nil)
	}
	return body
}
