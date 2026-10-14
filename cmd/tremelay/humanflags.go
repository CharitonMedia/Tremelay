package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
)

const (
	vaultCreateUsage         = "usage: tremelay vault create --path PATH"
	credentialPutUsage       = "usage: tremelay credential put --path PATH --label LABEL --type TYPE --secret-file PATH"
	credentialGetUsage       = "usage: tremelay credential get --path PATH --id ID"
	credentialListUsage      = "usage: tremelay credential list --path PATH"
	credentialReplaceUsage   = "usage: tremelay credential replace --path PATH --id ID --secret-file PATH"
	credentialLifecycleUsage = "usage: tremelay credential lifecycle --path PATH --id ID [--expires RFC3339] [--review RFC3339] [--rotation RFC3339] [--rotation-every DURATION] [--review-every DURATION]"
	credentialHealthUsage    = "usage: tremelay credential health --path PATH [--id ID]"
	credentialRefreshUsage   = "usage: tremelay credential refresh --path PATH [--id ID]"
	credentialPolicyUsage    = "usage: tremelay credential policy --path PATH [--min-length N] [--pattern-run N] [--freshness DURATION] [--reminder-lead DURATION] [--compromise-opt-in true|false]"
	auditVerifyUsage         = "usage: tremelay audit verify --path PATH"
	auditListUsage           = "usage: tremelay audit list --path PATH [--credential ID] [--agent ID] [--action ACTION] [--class CLASS] [--since RFC3339] [--until RFC3339] [--after SEQ] [--limit N]"
	auditGetUsage            = "usage: tremelay audit get --path PATH --seq SEQ"
	agentCreateUsage         = "usage: tremelay agent create --path PATH --label LABEL [--token-file PATH]"
	agentTokenIssueUsage     = "usage: tremelay agent token issue --path PATH --agent ID --token-file PATH"
	agentTokenRotateUsage    = "usage: tremelay agent token rotate --path PATH --agent ID --token-file PATH"
	agentTokenRevokeUsage    = "usage: tremelay agent token revoke --path PATH --agent ID"
	grantCreateUsage         = "usage: tremelay grant create --path PATH --agent ID (--credential ID | --class TYPE) --operation OP --resource SCOPE --expires RFC3339 [--ssh-user USER --ssh-host-key HEX] [--method M ... --inject STYLE [--inject-name NAME]]"
	grantRevokeUsage         = "usage: tremelay grant revoke --path PATH --id ID"
	capabilityListUsage      = "usage: tremelay capability list --path PATH --agent ID"
	capabilityAuthorizeUsage = "usage: tremelay capability authorize --path PATH --agent ID --credential ID --operation OP --resource SCOPE"
)

func newHumanFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

// parseHumanFlags discards flag-package diagnostics that may echo caller-supplied
// secret-like text. On failure it prints the fixed usage line and, when known,
// the bare flag name only. -h/--help still prints the flag set usage to stderr.
func parseHumanFlags(fs *flag.FlagSet, usageLine string, stderr io.Writer, args []string) error {
	err := fs.Parse(args)
	if err == nil {
		return nil
	}
	if errors.Is(err, flag.ErrHelp) {
		fs.SetOutput(stderr)
		fs.Usage()
		return err
	}
	fmt.Fprintln(stderr, usageLine)
	if name := flagNameFromParseError(err); name != "" {
		fmt.Fprintln(stderr, name)
	}
	return err
}

func flagNameFromParseError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	switch {
	case strings.HasPrefix(msg, "invalid boolean value "):
		if i := strings.Index(msg, " for -"); i >= 0 {
			return flagNameBeforeColon(msg[i+len(" for -"):])
		}
	case strings.HasPrefix(msg, "invalid value "):
		if i := strings.Index(msg, " for flag -"); i >= 0 {
			return flagNameBeforeColon(msg[i+len(" for flag -"):])
		}
		if i := strings.Index(msg, " for -"); i >= 0 {
			return flagNameBeforeColon(msg[i+len(" for -"):])
		}
	case strings.HasPrefix(msg, "flag provided but not defined: -"):
		return strings.TrimPrefix(msg, "flag provided but not defined: -")
	}
	return ""
}

func flagNameBeforeColon(rest string) string {
	if j := strings.Index(rest, ":"); j >= 0 {
		return rest[:j]
	}
	return rest
}
