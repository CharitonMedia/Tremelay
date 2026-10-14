package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
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

// parseHumanFlags discards flag-package diagnostics, which quote the offending
// argument and so can echo caller-supplied secret-like text. On failure it
// prints the command's usage line and nothing of the arguments: the flag
// package's error carries the value and the name in one string, and every way
// of splitting one from the other is a parse of attacker-chosen bytes.
// -h/--help still prints the flag set usage to stderr.
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
	return err
}
