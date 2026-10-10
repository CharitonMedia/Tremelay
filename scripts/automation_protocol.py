"""Pure readers for owner-authored automation control comments.

An owner token also posted checkpoint evidence before evidence escaping was
introduced. Authorship alone never makes the controls copied into that evidence
executable. Keep this check shared by every control reader, including recovery.
"""
from __future__ import annotations

import json
import re

HUMAN_RESUME_MARKER = "<!-- tremelay-human-resume -->"
SUPERVISOR_MARKER = "<!-- tremelay-supervisor-v1 "
WORKER_TERMINAL_STATUSES = frozenset({"FINISHED", "ERROR", "CANCELLED", "EXPIRED"})
_SUPERVISOR_PREFIX = "<!-- tremelay-supervisor-"
_SUPERVISOR_NON_STATE = re.compile(
    r"<!-- tremelay-supervisor-(?:budget|review:[0-9a-f]{40}) -->"
)
_CHECKPOINT_HEADER = re.compile(
    r"Automation stopped after [0-9]+ counted attempts(?: in this segment)? "
    r"\(limit (?P<limit>[0-9]+)\)\."
)
_OLD_STATUS_HEADER = re.compile(
    r"Automation stopped after (?P<limit>three|[0-9]+) implementation/remediation cycles "
    r"for this (?:supervised segment|pull-request lineage)\. "
)
_AUTHORITY_PREFIXES = ("<!-- tremelay-supervisor-", "<!-- goal-review-", "<!-- goal-initial",
                       "<!-- codex-cursor-worker", "<!-- codex-cursor-claim",
                       "<!-- tremelay-human-resume", "<!-- codex-cursor-remediation",
                       "A cloud agent is working through the review findings:",
                       "A cloud agent is implementing this issue:",
                       "Cursor review launch claimed.", "Cursor remediation round ")


class AmbiguousCheckpoint(ValueError):
    """Historical evidence may have been rewritten into actual worker state."""


def is_checkpoint_evidence(body: str) -> bool:
    """Recognize both original stop formats before examining copied controls.

    The fixed header precedes every attacker-controlled field in both b0fed
    formats. Interior markers need not be unique or well-formed. If authoritative
    looking state replaced the genuine final footer, however, a prior vulnerable
    controller may already have acted on it: stop for explicit reconciliation
    rather than erasing possible budget/worker history or executing that state.
    """
    if not isinstance(body, str):
        return False
    lines = body.lstrip().splitlines()
    if not lines:
        return False
    header = _CHECKPOINT_HEADER.fullmatch(lines[0]) or _OLD_STATUS_HEADER.match(lines[0])
    if not header:
        return False
    if any(prefix in body for prefix in _AUTHORITY_PREFIXES):
        head = re.search(r"Latest head: `([0-9a-f]{40})`\.", body)
        limit = "3" if header["limit"] == "three" else header["limit"]
        if head is None or not _stop_body_matches(body, head[1], limit):
            raise AmbiguousCheckpoint("Ambiguous historical checkpoint; reconcile possible worker and budget history")
    return True


def stop_comment_matches(comment: dict, head: str, limit: int | str) -> bool:
    """Only a recognized writer's genuine stop footer can suppress a new stop."""
    if (not isinstance(comment, dict) or not isinstance(comment.get("user"), dict)
            or comment["user"].get("login") not in {"pattalkslaw-del", "github-actions[bot]"}
            or not isinstance(head, str) or not re.fullmatch(r"[0-9a-f]{40}", head)
            or isinstance(limit, bool) or not re.fullmatch(r"[1-9][0-9]*", str(limit))):
        return False
    body = comment.get("body")
    if not is_checkpoint_evidence(body):
        return False
    return _stop_body_matches(body, head, limit)


def _stop_body_matches(body, head, limit):
    body = body.rstrip("\r\n")
    marker = f"<!-- tremelay-cycle-stop head:{head} limit:{limit} -->"
    lines = body.splitlines()
    header = _CHECKPOINT_HEADER.fullmatch(lines[0])
    if header:
        return (header["limit"] == str(limit) and len(lines) >= 5
                and lines[1] == "A documented independent supervisor assessment is required before more implementation."
                and lines[2] == f"Latest head: `{head}`."
                and lines[-1] == marker)
    # Prior shell writers used fixed text with literal \\n separators; accept
    # their exact original form (and real line breaks), never a quoted suffix.
    initial = f"Automation stopped after {limit} implementation/remediation cycles for this supervised segment. "
    supervision = ("A documented supervisor assessment is required before another Cursor run. "
                   "The implementation worker must not authorize its own further cycles. "
                   f"Latest head: `{head}`. Review the unresolved Codex/CI findings and resume only after that assessment.")
    human = (f"Human review is required before another Cursor run. Latest head: `{head}`. "
             "Review the unresolved Codex/CI findings and explicitly resume only after deciding the next approach.")
    candidates = [(initial + supervision, marker), (initial + human, marker)]
    if str(limit) == "3":
        candidates.append(("Automation stopped after three implementation/remediation cycles for this pull-request lineage. " + human,
                           f"<!-- tremelay-three-cycle-stop head:{head} -->"))
    return any(body == text + separator + footer for text, footer in candidates
               for separator in ("\n\n", r"\n\n"))


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate supervisor metadata field")
        result[key] = value
    return result


def supervisor_state(body: str) -> dict | None:
    """Read one canonical final envelope, or fail closed on intended state.

    Known checkpoint evidence is inert, even when its copied state is malformed.
    Other ambiguous owner state must not be silently dropped from the lifetime
    budget or interpreted as permission to replace a possibly running worker.
    """
    if not isinstance(body, str) or is_checkpoint_evidence(body) or _SUPERVISOR_PREFIX not in body:
        return None
    # Only the two existing standalone non-state controls are exempt. Unknown
    # versions and malformed intended envelopes must not disappear from either
    # ownership or checkpoint-budget readers.
    candidates = [line for line in body.splitlines()
                  if _SUPERVISOR_PREFIX in line and not _SUPERVISOR_NON_STATE.fullmatch(line)]
    if not candidates:
        return None
    line = body.rstrip("\r\n").splitlines()[-1]
    if (len(candidates) != 1 or candidates[0] != line or line.count(_SUPERVISOR_PREFIX) != 1
            or not line.startswith(SUPERVISOR_MARKER)
            or not line.endswith(" -->")):
        raise ValueError("Expected one final supervisor state envelope")
    state = json.loads(line[len(SUPERVISOR_MARKER):-4], object_pairs_hook=_unique_object)
    if (not isinstance(state, dict)
            or line != SUPERVISOR_MARKER + json.dumps(state, sort_keys=True, separators=(",", ":")) + " -->"):
        raise ValueError("Noncanonical supervisor state envelope")
    return state


def supervisor_owns_work(state: dict) -> bool:
    """A lifecycle change is never evidence that an accepted worker stopped.

    Old completed/escalated records lack a verified terminal receipt. Retain
    their ownership until GET-only reconciliation upgrades that same record.
    A review reservation remains owning until its final durable write.
    """
    phase = state.get("phase")
    if not isinstance(phase, str):
        return True
    if phase in {"reserved", "dispatch_ready", "dispatch_reserved", "working", "review_reserved"}:
        return True
    if "agent_id" in state or "run_id" in state:
        if (phase not in {"terminal", "completed", "escalate"}
                or not isinstance(state.get("terminal_status"), str)
                or state["terminal_status"] not in WORKER_TERMINAL_STATUSES
                or not isinstance(state.get("agent_id"), str)
                or not re.fullmatch(r"bc-[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", state["agent_id"])
                or not isinstance(state.get("run_id"), str)
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", state["run_id"])):
            return True
        return False
    # Unknown or malformed owning state fails closed instead of granting work.
    return phase not in {"obsolete", "escalate"}


def validate_supervisor_receipts(comments, states, author):
    """A separate launch receipt cannot disappear with its state comment."""
    prefix = "Cursor remediation round 1: supervisor worker launch reserved."
    pattern = (re.escape(prefix) + r"\n\nAgent: `(bc-[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})`\. "
               r"Correction is recorded above\. An ambiguous create is reconciled by this identity, never replayed\.")
    identities = {state.get("agent_id") for state in states if isinstance(state.get("agent_id"), str)}
    for comment in comments:
        if not isinstance(comment, dict) or comment.get("user", {}).get("login") != author:
            continue
        body = comment.get("body")
        if not isinstance(body, str) or is_checkpoint_evidence(body) or prefix not in body:
            continue
        match = re.fullmatch(pattern, body.rstrip("\r\n"))
        if not match or match[1] not in identities:
            raise ValueError("Orphan or malformed supervisor launch receipt; reconcile existing worker")


def has_control_marker(body: str, marker: str) -> bool:
    """A standalone control outside checkpoint evidence (identity checked by caller)."""
    return (isinstance(body, str) and not is_checkpoint_evidence(body)
            and marker in body.splitlines())


def is_resume_authorization(body: str) -> bool:
    """Honor existing manual boundary markers and recorded supervisor resumes."""
    if (not has_control_marker(body, HUMAN_RESUME_MARKER)
            or body.count("<!-- tremelay-human-resume") != 1):
        return False
    lines = body.strip("\r\n").splitlines()
    index = lines.index(HUMAN_RESUME_MARKER)
    if _SUPERVISOR_PREFIX in body:
        try:
            state = supervisor_state(body)
        except (ValueError, TypeError):
            return False
        # Resume remains valid after a genuine assessment's later phase edits,
        # including an appended obsolescence explanation. Model prose may have
        # arbitrary Markdown; the controller-authored envelope is authoritative.
        return state is not None and body.count("<!--") == 2
    # An unclosed Markdown code fence cannot turn its last quoted line into a
    # manual authorization. Indented and blockquoted markers are not standalone.
    fence = None
    for line in lines[:index]:
        match = re.match(r"^ {0,3}(`{3,}|~{3,})(.*)$", line)
        if match:
            delimiter, rest = match.groups()
            if fence is None:
                fence = delimiter
            elif delimiter[0] == fence[0] and len(delimiter) >= len(fence) and not rest.strip():
                fence = None
    if fence is not None:
        return False
    # Manual assessments historically put the marker first or last (or alone).
    # Interior/inline examples and comments carrying other protocols are inert.
    return body.count("<!--") == 1 and index in {0, len(lines) - 1}
