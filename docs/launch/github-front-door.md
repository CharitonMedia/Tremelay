# GitHub front door — for Patrick to apply by hand

Drafts for the GitHub-side half of [V1.md](../../V1.md) item 8. Applied on
2026-10-14 from Patrick's account (not by the orchestrator): description and topics
set, Discussions enabled, roadmap issues #55–#63 opened with these labels.

Item 9's announcement drafts are in [announcements.md](announcements.md).

## Repo description

Settings → General → Description. 336 characters, under GitHub's 350 limit.

```
Local credential broker for AI agents. Keep API keys and SSH keys in an encrypted vault on your own machine; give each agent its own scoped, expiring, revocable grants; let it use a credential over MCP or ssh-agent without ever seeing it. Deny by default, every attempt in a hash-chained audit log. Single user, local only.
```

Website field: leave empty until there is a docs site.

## Topics

Settings → General → Topics (max 20). These 18:

```
ai-agents  mcp  model-context-protocol  claude-code  credential-management
secrets-management  secret-management  api-keys  ssh-agent  vault
capability-based-security  least-privilege  audit-log  deny-by-default
security  self-hosted  go  golang
```

## Discussions

Settings → General → Features → check **Discussions**. Suggested categories
beyond the defaults: **Quickstart help** (Q&A) for client setup problems, and
**Grant recipes** (Show and tell) for `http_broker` grants people have found
useful. Point the Q&A category description at
[docs/quickstarts/](../quickstarts/).

## Labels

Three labels do the work. Create any that do not exist:

| Label | Colour | Description |
| --- | --- | --- |
| `roadmap` | `#5319e7` | Out of v1; wanted, not scheduled |
| `help wanted` | `#008672` | Maintainer would welcome a contributor here |
| `good first issue` | `#7057ff` | Small, self-contained, no trust-boundary change |

`good first issue` is deliberately rare here. Most roadmap items move a trust
boundary and need an ADR first, which is not a first issue.

## Roadmap issues

One per [V1.md](../../V1.md) "Out of v1" item. Each body below is ready to paste.
Every one of them should say, and does, that an ADR comes before code.

---

### Multi-user and organizations

Labels: `roadmap`, `help wanted`

> v1 is deliberately one human with one vault. Multi-user is the most-requested
> shape we know of and the largest design change on this list.
>
> What it would need:
>
> - More than one human identity, with its own authentication, against one vault
>   or a set of vaults.
> - Authorization for humans, not just agents: who may add a credential, issue a
>   grant, read the audit log, change a lifecycle policy.
> - An audit chain that attributes every event to a human principal as well as an
>   agent principal.
> - A story for key custody when a member leaves.
>
> ADR 0002 (single-user vault key hierarchy) and ADR 0015 (the shared vault that
> v1 removed, superseded) are the history to read first. ADR 0015 was cut because
> the authorization model was not sound, not because the use case is wrong.
>
> Not a starter task. A written design proposal is more useful than a patch.

---

### OAuth refresh-token brokering

Labels: `roadmap`, `help wanted`

> `VISION.md` lists OAuth credentials as an intended type and an OAuth token
> broker as an intended mechanism. Neither exists.
>
> The shape: the vault holds a refresh token, Tremelay exchanges it for an access
> token at the provider's token endpoint, and the agent gets an authorized call —
> never the refresh token, and ideally never the access token either. Access-token
> caching, rotation on refresh (where the provider rotates), clock skew, and
> revocation on the provider side are all part of it.
>
> The hard part is not the HTTP. It is that the broker must hold both tokens and
> still satisfy invariants 1, 5 and 12: no agent-facing retrieval, no secret in
> the audit record, and no automatic return of a token-bearing response body.
>
> Needs an ADR before code.

---

### Database session brokering

Labels: `roadmap`, `help wanted`

> Let an agent run a query against a database it is granted, with the database
> credential staying inside Tremelay.
>
> Open questions that need answering before any code:
>
> - Where is the boundary — a connection the agent drives, or a statement the
>   broker runs on its behalf?
> - What does a grant scope: host, database, schema, table, statement class,
>   read-only?
> - Result rows are response data under invariant 12. What may the agent see?
> - Which wire protocols, and does Tremelay speak them or proxy them?
>
> A design proposal that answers those is worth more than an implementation that
> picks one silently. Needs an ADR.

---

### Browser form credential submission

Labels: `roadmap`, `help wanted`

> `VISION.md` lists controlled browser/form credential submission. v1 has nothing
> for a site with no API.
>
> The shape: an agent drives a browser, reaches a login form on a granted origin,
> and Tremelay types the credential into that form without the agent, the page,
> or the automation transcript ever holding it.
>
> This is the hardest destination-control problem on the list. The destination is
> a rendered page rather than an origin plus a path, so same-origin is necessary
> but nowhere near sufficient: an attacker-controlled iframe, an overlay, a
> redirected form action, or a devtools transcript all defeat a naive version.
> Expect to spend the design on *proving which field on which document* the
> credential is entering.
>
> Needs an ADR, and probably a prototype behind a flag before anything ships.

---

### TOTP seeds

Labels: `roadmap`, `help wanted`, `good first issue`

> `VISION.md` lists TOTP seeds as an intended credential type. Storing one already
> works (`--type totp`); generating a code from it does not.
>
> The smallest useful slice: a `totp_generate` grant operation that returns the
> current 6-digit code for one credential, with the seed staying in the vault, the
> code never written to an audit row, and RFC 6238 handled by a mature library
> rather than new code.
>
> This is the most self-contained item on this list — one operation, one
> credential type, no network destination to defend and no new wire format. It
> still changes what an agent may receive, so it needs a short ADR, and the code
> that answers "is a 6-digit code a secret for redaction purposes?" is the
> interesting part.

---

### Provider-assisted credential rotation

Labels: `roadmap`, `help wanted`

> Invariant 9 says automated rotation must validate the new credential before
> revoking the old one where a safe overlap is possible. v1 only reminds you to
> rotate (`tremelay credential lifecycle --rotation-every`); it never rotates
> anything.
>
> Per-provider work: ask the provider to mint a replacement, store it, prove it
> works, then revoke the predecessor — and keep the vault consistent if any step
> fails halfway. The failure modes, not the happy path, are the design.
>
> A single well-chosen provider behind a general interface is the right first
> slice. Needs an ADR for the interface.

---

### Remote and network MCP transport

Labels: `roadmap`, `help wanted`

> Today every transport is local: a user-only Unix socket for the daemon, and
> inherited stdio pipes for `tremelay mcp`. An agent on another host cannot reach
> your broker, which is a deliberate v1 simplification (ADR 0020, ADR 0024) and a
> real limitation for anyone running agents on a server.
>
> A remote transport needs mutual authentication, something that does the job the
> peer-uid check does today, protection against a token replayed from another
> host, and an answer for what "user-only endpoint" means when there is no shared
> uid.
>
> Needs an ADR. Please do not open a TCP listener on the existing daemon.

---

### Signed releases

Labels: `roadmap`, `help wanted`

> The release workflow produces archives, SBOMs and a `SHA256SUMS` file
> (ADR 0027). A checksum detects a corrupted download; it does not detect a
> substituted release. There is no signature.
>
> What is wanted: signed artifacts with a verification path a user can follow in
> one command, plus key custody that does not depend on one laptop. Sigstore/
> cosign keyless signing and provenance attestation are the obvious candidates;
> an argued comparison is welcome.
>
> Needs an ADR amending ADR 0027.

---

### Independent security audit

Labels: `roadmap`, `help wanted`

> Nobody outside the project has reviewed this code. The README says so.
>
> This issue is the place to coordinate that: scope, who, funding, and what gets
> published. Invariant 6 requires the audit design to permit external or
> independent checkpointing, so an independent checkpointing service for the audit
> chain belongs in the same conversation.
>
> Not a code task. Comments from anyone who has organized one are welcome.

---

## Order to apply

1. Description and topics.
2. Labels, then Discussions.
3. Issues last, so each one can link the Discussions categories.
