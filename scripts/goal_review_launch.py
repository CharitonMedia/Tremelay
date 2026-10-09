#!/usr/bin/env python3
"""Durable ordinary goal-review ownership and GET-only worker reconciliation.

The trusted workflow serializes prepare/dispatch/recovery per PR. It persists
prepared before dispatch_reserved, persists dispatch_reserved before its sole
Cursor POST, and never repeats that POST. Recovery cannot create a worker.
Legacy claims have no pre-create guarantee and need separate GET-only evidence.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
import uuid

from automation_protocol import AmbiguousCheckpoint, is_checkpoint_evidence as protocol_checkpoint_evidence
from checkpoint_supervisor import REPO, Stop, cursor, gh
from goal_agent_request import (TRUSTED_AUTOMATION_LOGIN, accepted_launch_body, released_body,
                                reservation_body, review_claim_marker)

MARKER = "<!-- goal-review-launch-v1 "
LEGACY_MARKER = "<!-- goal-review-legacy-v1 "
LEGACY_AGENT = re.compile(r"bc-[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
LEGACY_CLAIM = re.compile(r"<!-- goal-review-claim review:([1-9][0-9]*) head:([0-9a-f]{40}) -->")
LEGACY_PREFIX = "A cloud agent is working through the review findings:"
SHA = re.compile(r"[0-9a-f]{40}")
RUN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}")
TERMINAL = frozenset({"FINISHED", "ERROR", "CANCELLED", "EXPIRED"})
LEGACY_PHASE_STATUSES = {"working": frozenset({"CREATING", "RUNNING"}), "terminal": TERMINAL}
BASE_KEYS = {"repo", "pr", "review", "head", "agent_id", "phase"}
PHASE_KEYS = {
    "prepared": set(), "dispatch_reserved": set(), "working": {"run_id"},
    "review_reserved": {"run_id", "completed_head"},
    "completed": {"run_id", "completed_head"},
    "terminal": {"run_id", "status"},
}


def positive_int(value):
    return type(value) is int and value > 0


def owner_authored(comment):
    return (isinstance(comment, dict) and isinstance(comment.get("user"), dict)
            and comment["user"].get("login") == TRUSTED_AUTOMATION_LOGIN)


def validate_target(repository, pr):
    if repository != REPO or not positive_int(pr):
        raise Stop("Goal-review repository or PR is not authorized")


def agent_identity(repository, pr, review, head):
    validate_target(repository, pr)
    if (not isinstance(review, str) or not re.fullmatch(r"[1-9][0-9]*", review)
            or not isinstance(head, str) or not SHA.fullmatch(head)):
        raise Stop("Invalid exact review/head identity")
    return "bc-" + str(uuid.uuid5(uuid.NAMESPACE_URL,
        f"goal-review:{repository}|pr:{pr}|review:{review}|head:{head}"))


def validate_state(state):
    if not isinstance(state, dict) or not isinstance(state.get("phase"), str):
        raise Stop("Invalid goal-review launch state")
    fields = PHASE_KEYS.get(state["phase"])
    if fields is None or set(state) != BASE_KEYS | fields:
        raise Stop("Invalid goal-review launch state fields")
    expected = agent_identity(state["repo"], state["pr"], state["review"], state["head"])
    if state["agent_id"] != expected:
        raise Stop("Goal-review worker identity does not match claim")
    if "run_id" in fields and (not isinstance(state["run_id"], str) or not RUN_ID.fullmatch(state["run_id"])):
        raise Stop("Invalid worker run identity")
    if "completed_head" in fields:
        head = state["completed_head"]
        if not isinstance(head, str) or not SHA.fullmatch(head) or head == state["head"]:
            raise Stop("Invalid completed review head")
    if "status" in fields and (not isinstance(state["status"], str) or state["status"] not in TERMINAL):
        raise Stop("Invalid terminal worker status")
    return state


def state_body(state):
    validate_state(state)
    marker = review_claim_marker(state["review"], state["head"])
    body = reservation_body(marker).rstrip()
    phase = state["phase"]
    descriptions = {
        "prepared": "Prepared locally; no worker create attempted.",
        "dispatch_reserved": "Worker dispatch reserved; an uncertain create must not be replayed.",
        "working": "Existing worker recorded; recovery only reads this worker.",
        "review_reserved": "Worker finished; independent exact-head review reserved.",
        "completed": "Worker finished; independent exact-head review requested.",
        "terminal": "Worker stopped; ownership and the consumed cycle remain recorded.",
    }
    body += "\n\n" + descriptions[phase]
    if phase not in {"prepared", "dispatch_reserved"}:
        body += f"\nWorker: https://cursor.com/agents/{state['agent_id']}"
    if phase == "terminal":
        body += f"\nTerminal status: {state['status']}."
        if state["status"] == "FINISHED":
            body += " No advancing commits; no replacement or review requested."
    return body + "\n\n" + MARKER + json.dumps(state, sort_keys=True, separators=(",", ":")) + " -->\n"


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Stop("Duplicate launch metadata field")
        result[key] = value
    return result


def load_json(text):
    try:
        return json.loads(text, object_pairs_hook=unique_object)
    except (ValueError, TypeError):
        raise Stop("Invalid launch JSON") from None


def parse_body(body):
    if not isinstance(body, str) or body.count(MARKER) != 1:
        raise Stop("Expected exactly one goal-review launch record")
    line = body.rstrip("\n").split("\n")[-1]
    if not line.startswith(MARKER) or not line.endswith(" -->"):
        raise Stop("Goal-review launch record must be the final line")
    state = validate_state(load_json(line[len(MARKER):-4]))
    # Generated prose is fixed, too: it must not contain a second claim, a
    # resume marker, injected URL, or a misleading phase/header.
    if body.rstrip("\n") != state_body(state).rstrip("\n"):
        raise Stop("Goal-review claim body does not match its launch record")
    return state


def checkpoint_evidence(body):
    # The supervisor can run as __main__: use our controlled exception so its
    # ordinary_worker_pending adapter can fail only this PR, not the whole scan.
    try:
        return protocol_checkpoint_evidence(body)
    except AmbiguousCheckpoint as error:
        raise Stop(str(error)) from None


def legacy_candidate(body):
    return (isinstance(body, str) and not checkpoint_evidence(body)
            and ("<!-- goal-review-claim" in body
                 or "<!-- goal-review-legacy" in body
                 or LEGACY_PREFIX in body
                 or "Cursor review launch claimed." in body))


def parse_legacy_claim(body):
    """Read exact historical bodies; they never establish a pre-create phase."""
    if not isinstance(body, str) or checkpoint_evidence(body):
        raise Stop("Expected an original legacy worker claim")
    text = body.rstrip("\n")
    claims = list(LEGACY_CLAIM.finditer(text))
    identity = {}
    if len(claims) == 1:
        match = claims[0]
        identity = {"review": match[1], "head": match[2]}
        marker = match[0]
        if text in {reservation_body(marker).rstrip("\n"),
                    "Cursor review launch claimed.\n\n" + marker}:
            return dict(identity, phase="legacy_reserved")
    elif claims:
        raise Stop("Ambiguous legacy review identity; manual reconciliation required")
    # Pre-claim-marker accepted comments also counted an attempt. Keep that
    # exact URL-only form, without inventing an original review or head.
    match = re.fullmatch(re.escape(LEGACY_PREFIX) + r" https://cursor\.com/agents/(" +
                         LEGACY_AGENT.pattern + r")(?:\n\n" + LEGACY_CLAIM.pattern + r")?", text)
    if match:
        return dict(identity, phase="legacy_accepted", agent_id=match[1])
    raise Stop("Unrecognized legacy worker claim; manual reconciliation required")


def validate_legacy_state(state):
    required = {"repo", "pr", "comment_id", "agent_id", "run_id", "status", "phase"}
    if (not isinstance(state, dict)
            or set(state) not in (required, required | {"review", "head"})):
        raise Stop("Invalid legacy reconciliation fields")
    validate_target(state["repo"], state["pr"])
    if (not positive_int(state["comment_id"])
            or not isinstance(state["agent_id"], str) or not LEGACY_AGENT.fullmatch(state["agent_id"])
            or not isinstance(state["run_id"], str) or not RUN_ID.fullmatch(state["run_id"])
            or not isinstance(state["status"], str)
            or not isinstance(state["phase"], str)
            or state["status"] not in LEGACY_PHASE_STATUSES.get(state["phase"], ())):
        raise Stop("Invalid legacy worker identity or status")
    if "review" in state and (not isinstance(state["review"], str)
            or not re.fullmatch(r"[1-9][0-9]*", state["review"])
            or not isinstance(state["head"], str) or not SHA.fullmatch(state["head"])):
        raise Stop("Invalid original legacy review identity")
    return state


def legacy_state_body(state):
    validate_legacy_state(state)
    url = "https://cursor.com/agents/" + state["agent_id"]
    body = (accepted_launch_body(url, review_claim_marker(state["review"], state["head"]))
            if "review" in state else LEGACY_PREFIX + " " + url + "\n").rstrip("\n")
    body += "\n\nLegacy worker reconciled by read-only lookup. No new worker or review authorized."
    body += f"\nVerified run status: {state['status']}."
    body += ("\nVerified terminal worker; its consumed cycle remains recorded."
             if state["phase"] == "terminal" else "\nExisting worker still owns this PR.")
    return body + "\n\n" + LEGACY_MARKER + json.dumps(state, sort_keys=True, separators=(",", ":")) + " -->\n"


def parse_legacy_state(body):
    if not isinstance(body, str) or body.count(LEGACY_MARKER) != 1:
        raise Stop("Expected exactly one legacy reconciliation record")
    line = body.rstrip("\n").split("\n")[-1]
    if not line.startswith(LEGACY_MARKER) or not line.endswith(" -->"):
        raise Stop("Legacy reconciliation record must be the final line")
    state = validate_legacy_state(load_json(line[len(LEGACY_MARKER):-4]))
    if body.rstrip("\n") != legacy_state_body(state).rstrip("\n"):
        raise Stop("Legacy claim body does not match its reconciliation record")
    return state


def pending_claim(comments, repository, pr, trusted_login):
    """Keep newer reviews from replacing any unresolved ordinary worker."""
    validate_target(repository, pr)
    if trusted_login != TRUSTED_AUTOMATION_LOGIN:
        raise Stop("Goal-review ownership requires the approved owner identity")
    if not isinstance(comments, list):
        raise Stop("Invalid goal-review comment list")
    pending = False
    for comment in comments:
        if not owner_authored(comment):
            continue
        body = comment.get("body")
        if not isinstance(body, str) or checkpoint_evidence(body):
            continue
        if "<!-- goal-review-launch" in body:
            saved = parse_body(body)
        elif "<!-- goal-review-legacy" in body:
            saved = parse_legacy_state(body)
            if saved["comment_id"] != comment.get("id"):
                raise Stop("Legacy reconciliation targets another comment")
        elif legacy_candidate(body):
            saved = parse_legacy_claim(body)
        else:
            continue
        if (saved.get("repo", repository) != repository or saved.get("pr", pr) != pr
                or not positive_int(comment.get("id"))
                or comment.get("issue_url") != f"https://api.github.com/repos/{REPO}/issues/{pr}"):
            raise Stop("Pending launch comment does not match its PR")
        if saved["phase"] not in {"terminal", "completed"}:
            pending = True
    return pending


def prepare(repository, pr, claim, payload):
    validate_target(repository, pr)
    if (not isinstance(claim, dict)
            or set(claim) != {"status", "owned", "marker", "review_id", "head"}
            or claim["status"] != "free" or claim["owned"] is not False):
        raise Stop("An exact free review claim is required")
    agent_id = agent_identity(repository, pr, claim["review_id"], claim["head"])
    if claim["marker"] != review_claim_marker(claim["review_id"], claim["head"]):
        raise Stop("Review claim marker does not match its identity")
    required = {"name", "prompt", "repos", "workOnCurrentBranch", "autoCreatePR", "skipReviewerRequest"}
    if (not isinstance(payload, dict) or set(payload) not in (required, required | {"agentId"})
            or payload.get("repos") != [{"url": f"https://github.com/{REPO}",
                                           "prUrl": f"https://github.com/{REPO}/pull/{pr}"}]
            or payload.get("workOnCurrentBranch") is not True
            or payload.get("autoCreatePR") is not False
            or payload.get("skipReviewerRequest") is not True
            or not isinstance(payload.get("name"), str)
            or not isinstance(payload.get("prompt"), dict)
            or set(payload["prompt"]) != {"text"}
            or not isinstance(payload["prompt"]["text"], str)
            or not payload["prompt"]["text"].strip()
            or ("agentId" in payload and payload["agentId"] != agent_id)):
        raise Stop("Review payload destination or options are not authorized")
    state = {"repo": repository, "pr": pr, "review": claim["review_id"],
             "head": claim["head"], "agent_id": agent_id, "phase": "prepared"}
    return state, dict(payload, agentId=agent_id)


def transition(state, phase, response=None):
    validate_state(state)
    if phase == "dispatch_reserved" and state["phase"] == "prepared" and response is None:
        return dict(state, phase=phase)
    if phase != "working" or state["phase"] != "dispatch_reserved" or not isinstance(response, dict):
        raise Stop("Invalid local launch transition")
    agent, run = response.get("agent"), response.get("run")
    if (not isinstance(agent, dict) or agent.get("id") != state["agent_id"]
            or not isinstance(run, dict)
            or ("agentId" in run and run["agentId"] != state["agent_id"])
            or not isinstance(run.get("id"), str) or not RUN_ID.fullmatch(run["id"])):
        raise Stop("Cursor create response does not match reserved worker")
    return validate_state(dict(state, phase=phase, run_id=run["id"]))


def update_comment(comment, state):
    body = state_body(state)
    if comment["body"].rstrip("\n") != body.rstrip("\n"):
        gh(f"repos/{REPO}/issues/comments/{comment['id']}", method="PATCH", data={"body": body})
        comment["body"] = body


def pull_head(pr):
    pull = gh(f"repos/{REPO}/pulls/{pr}")
    if (not isinstance(pull, dict) or pull.get("number") != pr or pull.get("state") != "open"
            or pull.get("draft") is not False
            or pull.get("user", {}).get("login") != TRUSTED_AUTOMATION_LOGIN
            or pull.get("head", {}).get("repo", {}).get("full_name") != REPO
            or pull.get("base", {}).get("repo", {}).get("full_name") != REPO
            or pull.get("base", {}).get("ref") != "main"
            or "goal" not in {item.get("name") for item in pull.get("labels", []) if isinstance(item, dict)}
            or len(re.findall(r"^Goal-Issue: #[1-9][0-9]*$", pull.get("body") or "", re.M)) != 1):
        raise Stop("PR no longer eligible for ordinary worker completion")
    head = pull.get("head", {}).get("sha")
    if not isinstance(head, str) or not SHA.fullmatch(head):
        raise Stop("Invalid current PR head")
    return head


def review_body(state):
    head = state["completed_head"]
    marker = f"<!-- goal-review-rereview-v1 agent:{state['agent_id']} head:{head} -->"
    return (f"@codex review\n\nCursor worker finished. Review exact commit `{head}`. "
            f"Independent review is required before merge.\n\n{marker}\n")


def finish_review(comment, state):
    pr = state["pr"]
    if pull_head(pr) != state["completed_head"]:
        raise Stop("PR changed after exact-head review reservation")
    response = gh(f"repos/{REPO}/issues/{pr}/comments?per_page=100", paginate=True)
    if not isinstance(response, list) or any(not isinstance(page, list) for page in response):
        raise Stop("Cannot verify prior independent review request")
    expected = review_body(state)
    found = any(owner_authored(item)
                and isinstance(item.get("body"), str) and item["body"].rstrip("\n") == expected.rstrip("\n")
                for page in response for item in page)
    if not found:
        # Recheck after pagination before the only outward review request.
        if pull_head(pr) != state["completed_head"]:
            raise Stop("PR changed before independent review request")
        gh(f"repos/{REPO}/issues/{pr}/comments", method="POST", data={"body": expected})
    done = dict(state, phase="completed")
    update_comment(comment, done)
    return done


def verify_legacy_target(agent, run, pr):
    """Require service evidence of this repository and PR, never a URL guess.

    Cursor GET Agent returns repos/workOnCurrentBranch. GET Run git.branches
    uses scheme-less repoUrl and is agent-wide, not proof of a reviewed commit.
    See https://cursor.com/docs/cloud-agent/api/endpoints#get-a-run.
    """
    repos = agent.get("repos")
    if (not isinstance(repos, list) or len(repos) != 1 or not isinstance(repos[0], dict)
            or repos[0].get("url") != f"https://github.com/{REPO}"
            or agent.get("workOnCurrentBranch") is not True):
        raise Stop("Legacy worker repository or branch ownership is unverified")
    expected = f"https://github.com/{REPO}/pull/{pr}"
    destination = repos[0].get("prUrl")
    if destination is not None and destination != expected:
        raise Stop("Legacy worker targets another PR")
    matched = destination == expected
    if "git" in run:
        git = run["git"]
        branches = git.get("branches") if isinstance(git, dict) else None
        if not isinstance(branches, list):
            raise Stop("Legacy worker branch evidence is invalid")
        for branch in branches:
            if (not isinstance(branch, dict) or branch.get("repoUrl") != f"github.com/{REPO}"
                    or (branch.get("prUrl") is not None and branch["prUrl"] != expected)):
                raise Stop("Legacy worker branch evidence targets another repository or PR")
            matched = matched or branch.get("prUrl") == expected
    if not matched:
        raise Stop("Legacy worker PR association is unverified; manual reconciliation required")


def recover_legacy(comment, state, repository, pr):
    if "repo" in state and (state["repo"] != repository or state["pr"] != pr
                           or state["comment_id"] != comment["id"]):
        raise Stop("Legacy reconciliation targets another repository, PR or comment")
    if state["phase"] == "legacy_reserved":
        raise Stop("Legacy reservation has no recorded worker identity; manual reconciliation required")
    if state["phase"] == "terminal":
        return state
    agent_id = state["agent_id"]
    agent = cursor("/" + agent_id)
    if not isinstance(agent, dict) or agent.get("id") != agent_id:
        raise Stop("Cursor lookup did not establish legacy worker identity")
    run_id = agent.get("latestRunId")
    if (not isinstance(run_id, str) or not RUN_ID.fullmatch(run_id)
            or ("run_id" in state and state["run_id"] != run_id)):
        raise Stop("Cursor lookup did not establish the same legacy run; manual reconciliation required")
    run = cursor(f"/{agent_id}/runs/{run_id}")
    if (not isinstance(run, dict) or run.get("id") != run_id or run.get("agentId") != agent_id
            or not isinstance(run.get("status"), str)
            or run["status"] not in TERMINAL | {"CREATING", "RUNNING"}):
        raise Stop("Cursor lookup did not establish the legacy run status")
    verify_legacy_target(agent, run, pr)
    terminal = run["status"] in TERMINAL
    if terminal:
        # A historical run finishing does not release a newer run on this agent.
        # Recheck the current service identity before persisting final ownership.
        current = cursor("/" + agent_id)
        if (not isinstance(current, dict) or current.get("id") != agent_id
                or current.get("latestRunId") != run_id):
            raise Stop("Legacy worker changed during reconciliation")
        verify_legacy_target(current, run, pr)
    saved = dict(state, repo=repository, pr=pr, comment_id=comment["id"], run_id=run_id,
                 status=run["status"], phase="terminal" if terminal else "working")
    body = legacy_state_body(saved)
    if comment["body"].rstrip("\n") != body.rstrip("\n"):
        gh(f"repos/{REPO}/issues/comments/{comment['id']}", method="PATCH", data={"body": body})
        comment["body"] = body
    # Ownership reconciliation cannot attribute historical FINISHED work to a
    # current head. Never create a worker, request review, or clear the stop.
    return saved


def recover(repository, pr, comment_id):
    """Reconcile one serialized claim. Cursor calls here are always GET-only."""
    validate_target(repository, pr)
    if not positive_int(comment_id):
        raise Stop("Invalid launch comment identity")
    account = gh("user")
    if not isinstance(account, dict) or account.get("login") != TRUSTED_AUTOMATION_LOGIN:
        raise Stop("Goal-review recovery requires the approved owner identity")
    comment = gh(f"repos/{REPO}/issues/comments/{comment_id}")
    if (not isinstance(comment, dict) or comment.get("id") != comment_id
            or not owner_authored(comment)
            or comment.get("issue_url") != f"https://api.github.com/repos/{REPO}/issues/{pr}"):
        raise Stop("Launch comment owner or PR does not match")
    # An interrupted release is idempotent, but arbitrary marker-free comments
    # are not evidence that a reserved worker was never created.
    if isinstance(comment.get("body"), str) and comment["body"].rstrip("\n") == released_body().rstrip("\n"):
        return {"phase": "released"}
    body = comment.get("body")
    if checkpoint_evidence(body):
        raise Stop("Checkpoint evidence is not an original worker claim")
    if isinstance(body, str) and "<!-- goal-review-legacy" in body:
        return recover_legacy(comment, parse_legacy_state(body), repository, pr)
    if not isinstance(body, str) or "<!-- goal-review-launch" not in body:
        return recover_legacy(comment, parse_legacy_claim(body), repository, pr)
    state = parse_body(body)
    if state["repo"] != repository or state["pr"] != pr:
        raise Stop("Launch record targets another repository or PR")
    if state["phase"] == "prepared":
        gh(f"repos/{REPO}/issues/comments/{comment_id}", method="PATCH", data={"body": released_body()})
        return {"phase": "released"}
    if state["phase"] in {"terminal", "completed"}:
        return state
    if state["phase"] == "review_reserved":
        return finish_review(comment, state)
    agent_id = state["agent_id"]
    agent = cursor("/" + agent_id)
    if not isinstance(agent, dict) or agent.get("id") != agent_id:
        raise Stop("Cursor lookup did not establish reserved worker identity")
    run_id = state.get("run_id") or agent.get("latestRunId")
    if not isinstance(run_id, str) or not RUN_ID.fullmatch(run_id):
        raise Stop("Cursor lookup did not establish a safe worker run")
    state = validate_state(dict(state, phase="working", run_id=run_id))
    # Persist recovered identity before the run lookup, including when that
    # lookup subsequently fails. A 404 never proves that no worker was created.
    update_comment(comment, state)
    run = cursor(f"/{agent_id}/runs/{run_id}")
    if (not isinstance(run, dict) or run.get("id") != run_id or run.get("agentId") != agent_id
            or not isinstance(run.get("status"), str)
            or run["status"] not in TERMINAL | {"CREATING", "RUNNING"}):
        raise Stop("Cursor lookup did not establish the reserved run status")
    status = run["status"]
    if status not in TERMINAL:
        return state
    if status != "FINISHED":
        state = dict(state, phase="terminal", status=status)
        update_comment(comment, state)
        return state
    head = pull_head(pr)
    if head == state["head"]:
        state = dict(state, phase="terminal", status=status)
        update_comment(comment, state)
        return state
    comparison = gh(f"repos/{REPO}/compare/{state['head']}...{head}")
    if not isinstance(comparison, dict) or comparison.get("status") != "ahead":
        raise Stop("Finished worker head is not an advancing descendant")
    state = dict(state, phase="review_reserved", completed_head=head)
    update_comment(comment, state)
    return finish_review(comment, state)


def write_json(path, value):
    Path(path).write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare_cmd = commands.add_parser("prepare")
    for name in ("repository", "claim", "payload", "state", "body"):
        prepare_cmd.add_argument("--" + name, required=True)
    prepare_cmd.add_argument("--pr", type=int, required=True)
    body_cmd = commands.add_parser("body")
    for name in ("state", "body"):
        body_cmd.add_argument("--" + name, required=True)
    body_cmd.add_argument("--phase", choices=("dispatch_reserved", "working"), required=True)
    body_cmd.add_argument("--response")
    recover_cmd = commands.add_parser("recover")
    recover_cmd.add_argument("--repository", required=True)
    recover_cmd.add_argument("--pr", type=int, required=True)
    recover_cmd.add_argument("--comment", type=int, required=True)
    args = parser.parse_args(argv)
    if args.command == "prepare":
        state, payload = prepare(args.repository, args.pr,
            load_json(Path(args.claim).read_text(encoding="utf-8")),
            load_json(Path(args.payload).read_text(encoding="utf-8")))
        write_json(args.state, state)
        write_json(args.payload, payload)
        Path(args.body).write_text(state_body(state), encoding="utf-8")
    elif args.command == "body":
        state = load_json(Path(args.state).read_text(encoding="utf-8"))
        response = load_json(Path(args.response).read_text(encoding="utf-8")) if args.response else None
        state = transition(state, args.phase, response)
        write_json(args.state, state)
        Path(args.body).write_text(state_body(state), encoding="utf-8")
    else:
        state = recover(args.repository, args.pr, args.comment)
        print(f"PR #{args.pr}: ordinary goal-review claim is {state['phase']}; no worker create was attempted")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (Stop, OSError) as error:
        # OSError may contain file names; never echo response bodies or keys.
        print(str(error) if isinstance(error, Stop) else "Local launch file operation failed", file=sys.stderr)
        sys.exit(1)
