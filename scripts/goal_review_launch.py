#!/usr/bin/env python3
"""Durable ordinary goal-review ownership and GET-only worker reconciliation.

The trusted workflow serializes prepare/dispatch/recovery per PR. It persists
prepared before dispatch_reserved, persists dispatch_reserved before its sole
Cursor POST, and never repeats that POST. Recovery cannot create a worker.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
import uuid

from checkpoint_supervisor import REPO, Stop, cursor, gh
from goal_agent_request import TRUSTED_AUTOMATION_LOGIN, released_body, reservation_body, review_claim_marker

MARKER = "<!-- goal-review-launch-v1 "
SHA = re.compile(r"[0-9a-f]{40}")
RUN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}")
TERMINAL = frozenset({"FINISHED", "ERROR", "CANCELLED", "EXPIRED"})
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


def pending_claim(comments, repository, pr, trusted_login):
    """Keep newer reviews from replacing a still-owned ordinary worker."""
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
        if not isinstance(body, str) or "<!-- goal-review-launch-v1" not in body:
            continue
        saved = parse_body(body)
        if (saved["repo"] != repository or saved["pr"] != pr
                or not positive_int(comment.get("id"))
                or comment.get("issue_url") != f"https://api.github.com/repos/{REPO}/issues/{pr}"):
            raise Stop("Pending launch comment does not match its PR")
        if saved["phase"] in {"prepared", "dispatch_reserved", "working", "review_reserved"}:
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
    state = parse_body(comment.get("body"))
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
