package vault

import (
	"encoding/hex"
	"strings"
	"time"
)

// Fixed audit reason codes for grant_create input denials (not caller-controlled).
const (
	ReasonAgentRequired       = "agent_required"
	ReasonCredentialRequired  = "credential_required"
	ReasonCredentialConflict  = "credential_conflict"
	ReasonOperationRequired   = "operation_required"
	ReasonUnknownOperation    = "unknown_operation"
	ReasonDuplicateOperation  = "duplicate_operation"
	ReasonOperationInvalid    = "operation_invalid"
	ReasonResourceRequired    = "resource_required"
	ReasonResourceInvalid     = "resource_invalid"
	ReasonExpiresRequired     = "expires_required"
	ReasonExpiresInvalid      = "expires_invalid"
	ReasonExpiresNotFuture    = "expires_not_future"
	ReasonUnknownClass        = "unknown_class"
	ReasonInvalidCredentialID = "invalid_credential_id"
	ReasonSSHHostKeyInvalid   = "ssh_host_key_invalid"
	ReasonGrantExtraArgs      = "extra_arguments"
)

func grantOpsList() string {
	return strings.Join(GrantOperations(), ", ")
}

func grantTypesList() string {
	return strings.Join(CredentialTypes(), ", ")
}

// ValidateGrantCreateCLI checks human grant create flags before IssueGrant.
func ValidateGrantCreateCLI(agent, cred, class, resource, expires string, ops []string, extraArgs int) error {
	if extraArgs != 0 {
		return inputInvalid("grant create: unexpected arguments", ReasonGrantExtraArgs)
	}
	if agent == "" {
		return inputInvalid("grant create: --agent is required", ReasonAgentRequired)
	}
	credSet, classSet := cred != "", class != ""
	if !credSet && !classSet {
		return inputInvalid("grant create: --credential or --class is required", ReasonCredentialRequired)
	}
	if credSet && classSet {
		return inputInvalid("grant create: specify only one of --credential or --class", ReasonCredentialConflict)
	}
	if len(ops) == 0 {
		return inputInvalid("grant create: --operation is required", ReasonOperationRequired)
	}
	if resource == "" {
		return inputInvalid("grant create: --resource is required", ReasonResourceRequired)
	}
	if expires == "" {
		return inputInvalid("grant create: --expires is required", ReasonExpiresRequired)
	}
	return nil
}

func GrantCreateExpiresCLI(expires string) (time.Time, error) {
	exp, err := time.Parse(time.RFC3339, expires)
	if err != nil {
		return time.Time{}, inputInvalid("grant create: --expires is invalid", ReasonExpiresInvalid)
	}
	return exp.UTC(), nil
}

func GrantCreateSSHHostKeyCLI(hexKey string) ([]byte, error) {
	if hexKey == "" {
		return nil, nil
	}
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, inputInvalid("grant create: --ssh-host-key is invalid", ReasonSSHHostKeyInvalid)
	}
	return key, nil
}

func errGrantAgentRequired() error {
	return inputInvalid("--agent is required", ReasonAgentRequired)
}

func errGrantCredentialRequired() error {
	return inputInvalid("--credential or --class is required", ReasonCredentialRequired)
}

func errGrantCredentialConflict() error {
	return inputInvalid("specify only one of --credential or --class", ReasonCredentialConflict)
}

func errGrantOperationRequired() error {
	return inputInvalid("--operation is required", ReasonOperationRequired)
}

func errGrantUnknownOperation() error {
	return inputInvalid("unknown --operation; valid: "+grantOpsList(), ReasonUnknownOperation)
}

func errGrantDuplicateOperation() error {
	return inputInvalid("duplicate operation", ReasonDuplicateOperation)
}

func errGrantOperationInvalid() error {
	return inputInvalid("too many operations", ReasonOperationInvalid)
}

func errGrantResourceRequired() error {
	return inputInvalid("--resource is required", ReasonResourceRequired)
}

func errGrantResourceInvalid() error {
	return inputInvalid("--resource is invalid", ReasonResourceInvalid)
}

func errGrantExpiresInvalid() error {
	return inputInvalid("--expires is invalid", ReasonExpiresInvalid)
}

func errGrantExpiresNotFuture() error {
	return inputInvalid("--expires must be in the future", ReasonExpiresNotFuture)
}

func errGrantUnknownClass() error {
	return inputInvalid("unknown --class; valid: "+grantTypesList(), ReasonUnknownClass)
}

func errGrantInvalidCredentialID() error {
	return inputInvalid("--credential is invalid", ReasonInvalidCredentialID)
}
