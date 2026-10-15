package vault

import (
	"net"
	"net/url"
	"strings"
)

// brokerGrantResourcePolicy validates an http_broker grant resource before
// issuance. It returns a fixed CLI message and audit reason when a public-host
// rule fails; other malformed input stays ErrInvalid.
func brokerGrantResourcePolicy(resource string) error {
	if resource == "" || len(resource) > maxLabel || hasControl(resource) || strings.ContainsAny(resource, " \\@#%*") {
		return ErrInvalid
	}
	u, err := url.Parse(resource)
	if err != nil || u == nil {
		return ErrInvalid
	}
	host := u.Hostname()
	if u.Scheme != "https" {
		return inputInvalid("resource must use https", ReasonResourceHTTPS)
	}
	if host != "" {
		if ip := net.ParseIP(host); ip != nil || looksLikeObfuscatedIP(host) {
			return inputInvalid("resource host must be a public DNS name, not an IP address", ReasonResourcePublicHost)
		}
		if specialDestination(host) {
			return inputInvalid("resource host is loopback/private", ReasonResourcePrivateHost)
		}
	}
	if _, _, _, ok := brokerScope(resource); ok {
		return nil
	}
	return ErrInvalid
}
