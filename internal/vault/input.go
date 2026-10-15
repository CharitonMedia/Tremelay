package vault

import "errors"

// Fixed audit reason codes for grant_create denials. They are not caller input.
const (
	ReasonResourceHTTPS       = "resource_https"
	ReasonResourcePublicHost  = "resource_public_host"
	ReasonResourcePrivateHost = "resource_private_host"
)

type inputError struct {
	msg    string
	reason string
}

func (e *inputError) Error() string { return e.msg }

func (e *inputError) Is(target error) bool { return target == ErrInvalid }

func inputInvalid(msg, reason string) error {
	return &inputError{msg: msg, reason: reason}
}

func grantCreateAuditReason(err error) string {
	var ie *inputError
	if errors.As(err, &ie) {
		return ie.reason
	}
	return ""
}

func knownGrantCreateReason(s string) bool {
	switch s {
	case ReasonResourceHTTPS, ReasonResourcePublicHost, ReasonResourcePrivateHost:
		return true
	default:
		return false
	}
}
