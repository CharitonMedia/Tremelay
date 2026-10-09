# ADR 0009: Claude checkpoint assessment through workload identity

Status: Proposed; installation and activation remain separate

## Context

The owner selected the existing Anthropic API-credit account for supervisor
assessments instead of creating a separately billed OpenAI route, with overages
disabled. The private account balance is not part of repository configuration. An auth-only GitHub
Actions test successfully exchanged its OIDC assertion for a 599-second
`workspace:developer` Bearer token. That federation rule trusts only the test
branch; production `main` access has not thereby been authorized.

ADR 0008's deterministic controller and every existing safety guard remain
unchanged in purpose. This ADR replaces its model transport and authentication,
not its eligibility, checkpoint budgets, ownership, review or merge policy.

## Decision

Use the pinned Claude API model `claude-sonnet-5-5` (Sonnet 5.5), adaptive
thinking at high effort, an 8192-token maximum output, and JSON-schema output.
No model tools, agent harness, shell, MCP, provider SDK, or provider/model fallback
is introduced. Retain complete bounded evidence rather than truncating it.
The current published standard prices are $2 per million input tokens and $10
per million output tokens; these are reference prices, not a computed dollar cap.

Keep GitHub's controller and the credential-bearing inference process separate.
The controller launches a trusted standalone Python helper in an empty temporary
directory with an explicit environment allowlist and isolated Python imports.
Only GitHub's ephemeral OIDC request URL/token cross that process boundary.
The helper receives no `GOAL_GITHUB_TOKEN`, Cursor key, API key, parent settings,
proxy overrides, or candidate repository files. Evidence reaches it as JSON on
stdin, not executable code or command-line arguments.

The helper uses standard-library HTTPS with redirects and environment proxies
disabled. It requests one GitHub assertion with the Anthropic audience, exchanges
it once at the fixed `/v1/oauth/token` endpoint using the existing rule,
organization, service-account and workspace IDs, validates the returned scope
and remaining lifetime, and sends at most one authenticated `/v1/messages`
request. Tokens remain in memory. A GitHub assertion's single-use identity must
never be retried after an uncertain exchange. No refresh or automatic retry is
allowed, including on credit exhaustion, 429, 5xx or a lost response.

Only the expected completed model response is accepted. The helper discards
thinking blocks and returns one text result with allowlisted numeric usage.
The controller independently rejects duplicate JSON keys, nonfinite values,
unexpected fields, wrong models, stale heads, fabricated protocol markers and
invalid decisions. Error text is fixed and does not interpolate provider bodies,
tokens or exception messages. Bounded response sizes and a process-group deadline
prevent unbounded local waits/output. A failed or ambiguous assessment retains
its durable reservation and never causes an automatic second inference request.

Failure diagnostics expose only a fixed stage name and an optional integer HTTP
status at request stages. The helper emits that exact small envelope on exit 1;
the controller independently validates its keys, stages and status range before
mapping it to fixed text. Unknown or malformed output remains a generic failure.
Raw stderr, response bodies, endpoints and credential values remain suppressed.
This lets an auth-only preflight distinguish a local URL/transport rejection
from an Anthropic exchange denial without weakening the credential boundary.

GitHub's OIDC request path is opaque and must be preserved, including literal
doubled slashes used by its hosted runner service. The runner supplies that URL;
the helper validates its HTTPS origin and appends the audience without rewriting
the path. Encoded separators, traversal, userinfo, fragments, redirects and
untrusted hosts remain refused.

Normal event/schedule/manual execution and the controller require the fresh
public `claude-wif-v2-5134b392b4a044deae9973b1c8757af2` release activation value.
The prior OpenAI value cannot activate this backend. The job and controller also
require the production `main` ref and exact workflow identity. No activation or
federation setting is changed by this patch.

Manual `preflight_only` may bypass the activation value only to check GitHub
owner/key setup and perform one auth-only exchange. It cannot call Messages or
Cursor. Production authorization should be constrained to the exact main subject
and `workflow_ref` documented in the setup guide. User approval is required to
change the existing test-only federation rule and later enable live operation.

A distinct, mutually exclusive manual `model_smoke_only` mode can make one
owner-approved small billed connection test before automatic activation. Its
input is fixed synthetic text, its schema only accepts `status: ok`, and its
output cap is 256 tokens. It cannot take candidate evidence, invoke the normal
assessment controller, write checkpoint/budget markers or launch a worker. It
uses the same main identity, federation and pinned model; errors never fall back
to another mode. Scheduled/event calls cannot select this manual test. At the
reference price its maximum output cost is $0.00256 plus fixed input usage;
expected total below one cent is an estimate, not a provider dollar cap.

## Consequences

- WIF removes a long-lived Anthropic/OpenAI key from this workflow. The
  `workspace:developer` credential remains privileged and is treated as secret.
- The workflow requires job-scoped `id-token: write`; runtime identity checks
  and the external federation rule both restrict which workflow can use it.
  Every step in that job can obtain its OIDC identity, so both first-party
  actions are pinned to reviewed full commit SHAs from their canonical
  repositories, not movable major-version tags. The regression suite rejects
  mutable, abbreviated, changed, or additional action references until reviewed.
- No new third-party runtime dependency is needed. Standard-library HTTPS keeps
  retry, redirect, token lifetime, response parsing and logging behavior explicit.
- Credits-only billing is an account control confirmed by the owner. The
  three-assessment-per-PR limit and three-cycle worker segments are work limits,
  not a global dollar ceiling. The code never buys credits or changes billing.
- Existing historical supervisor states still count. Active or ambiguous Cursor
  workers keep ownership; changing this backend cannot reset their budgets or
  create replacements. Cursor remains the implementer and Codex the independent
  reviewer. No autonomous merge or new goal is authorized.
- A successful token exchange proves federation, not model entitlement or
  inference quality. Live inference and production rollout require separate
  approval after offline tests and review.

## Validation

The existing automation suite must remain green. New offline tests cover the
real helper HTTP sequence with mocked services, no-retry behavior at each stage,
redirect/proxy refusal, scope/lifetime/model/status validation, thinking-block
discard, malformed and duplicate JSON, bounded I/O, credential redaction,
preflight without inference, a one-request/no-worker fixed smoke mode,
subprocess environment separation and timeout
termination. No token exchange or model call is made by those tests.

## Sources

- [WIF reference](https://platform.claude.com/docs/en/manage-claude/wif-reference)
- [GitHub Actions federation](https://platform.claude.com/docs/en/manage-claude/wif-providers/github-actions)
- [Sonnet 5.5 model and pricing](https://platform.claude.com/docs/en/models/sonnet-5-5/overview)
- [Structured output contract](https://platform.claude.com/docs/en/build-with-claude/structured-outputs)
- [GitHub runner OIDC environment](https://github.com/actions/runner/blob/main/src/Runner.Worker/Handlers/ScriptHandler.cs)
- [GitHub toolkit OIDC URL handling](https://github.com/actions/toolkit/blob/main/packages/core/src/oidc-utils.ts)
