package vault

import (
	"io"
	"sort"
	"strings"
)

const redacted = "[redacted]"

// Redactor removes known secret bytes from log and error text.
// Matching is exact substring replacement, longest secret first, so a
// shorter value that is a prefix of a longer one cannot leave the tail in
// a log line. Secrets shorter than one byte are ignored because the vault
// rejects them.
type Redactor struct {
	secrets [][]byte
}

// Add copies secret into the redactor. Empty input is ignored.
func (r *Redactor) Add(secret []byte) {
	if r == nil || len(secret) == 0 {
		return
	}
	for _, existing := range r.secrets {
		if string(existing) == string(secret) {
			return
		}
	}
	r.secrets = append(r.secrets, append([]byte(nil), secret...))
}

// Contains reports whether secret was added.
func (r *Redactor) Contains(secret []byte) bool {
	if r == nil || len(secret) == 0 {
		return false
	}
	for _, existing := range r.secrets {
		if string(existing) == string(secret) {
			return true
		}
	}
	return false
}

// Redact returns msg with every added secret replaced.
func (r *Redactor) Redact(msg string) string {
	if r == nil || len(r.secrets) == 0 {
		return msg
	}
	order := make([][]byte, len(r.secrets))
	copy(order, r.secrets)
	sort.Slice(order, func(i, j int) bool {
		return len(order[i]) > len(order[j])
	})
	for _, secret := range order {
		if len(secret) == 0 {
			continue
		}
		msg = strings.ReplaceAll(msg, string(secret), redacted)
	}
	return msg
}

// Wipe best-effort zeroes retained copies. Go may still have copies.
func (r *Redactor) Wipe() {
	if r == nil {
		return
	}
	for i := range r.secrets {
		wipe(r.secrets[i])
		r.secrets[i] = nil
	}
	r.secrets = nil
}

// RedactingWriter filters writes through Redactor.
// It reports the input length so a logger does not retry a shortened write.
type RedactingWriter struct {
	Dst      io.Writer
	Redactor *Redactor
}

func (w RedactingWriter) Write(p []byte) (int, error) {
	if w.Dst == nil {
		return len(p), nil
	}
	msg := string(p)
	if w.Redactor != nil {
		msg = w.Redactor.Redact(msg)
	}
	if _, err := w.Dst.Write([]byte(msg)); err != nil {
		return 0, err
	}
	return len(p), nil
}
