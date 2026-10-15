package vault

import "time"

// authenticateAgentTokenDelay is non-zero only when tests call
// SetAuthenticateAgentTokenDelay. Production leaves it at zero.
var authenticateAgentTokenDelay time.Duration

// SetAuthenticateAgentTokenDelay sleeps during AuthenticateAgentToken after the
// session mutex is taken. For automated tests only; not reachable from agents.
func SetAuthenticateAgentTokenDelay(d time.Duration) {
	authenticateAgentTokenDelay = d
}
