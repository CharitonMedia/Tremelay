#!/usr/bin/env python3
"""Serialized generic remediation dispatch and durable GET-only recovery."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import uuid

from checkpoint_supervisor import REPO, Stop, cursor, gh
from codex_cursor_remediation import LOOP_LABEL, _round_markers, remediation_marker
from goal_review_launch import (RUN_ID, SHA, TERMINAL, checkpoint_evidence, load_json,
                                owner_authored, positive_int, verify_legacy_target)

OWNER = "pattalkslaw-del"
MARKER = "<!-- codex-cursor-worker-v1 "
BASE_KEYS = {"repo", "pr", "review", "head", "agent_id", "round", "findings", "phase"}
PHASE_KEYS = {"prepared": set(), "released": set(), "dispatch_reserved": set(), "working": {"run_id"},
              "terminal": {"run_id", "status"}}


def validate_target(pr):
    if not positive_int(pr):
        raise Stop("Invalid generic worker PR")


def identity(pr, review, head):
    validate_target(pr)
    if (not isinstance(review, str) or not review.isascii() or not review.isdigit()
            or str(int(review)) != review or int(review) <= 0
            or not isinstance(head, str) or not SHA.fullmatch(head)):
        raise Stop("Invalid generic worker review/head identity")
    return "bc-" + str(uuid.uuid5(uuid.NAMESPACE_URL,
        f"https://github.com/{REPO}|pr:{pr}|review:{review}|head:{head}"))


def validate_state(state):
    if not isinstance(state, dict) or not isinstance(state.get("phase"), str):
        raise Stop("Invalid generic worker state")
    fields = PHASE_KEYS.get(state["phase"])
    if (fields is None or set(state) != BASE_KEYS | fields or state["repo"] != REPO
            or state["agent_id"] != identity(state["pr"], state["review"], state["head"])
            or not positive_int(state["round"]) or state["round"] > 3
            or not positive_int(state["findings"])):
        raise Stop("Invalid generic worker state fields")
    if "run_id" in fields and (not isinstance(state["run_id"], str) or not RUN_ID.fullmatch(state["run_id"])):
        raise Stop("Invalid generic worker run identity")
    if "status" in fields and (not isinstance(state["status"], str) or state["status"] not in TERMINAL):
        raise Stop("Invalid generic worker terminal status")
    return state


def state_body(state):
    validate_state(state)
    descriptions = {
        "prepared": "Prepared; no worker create has been attempted.",
        "dispatch_reserved": "Dispatch reserved; an uncertain create must not be replayed.",
        "working": "Existing worker recorded; recovery only reads this worker.",
        "terminal": "Worker verified terminal; its consumed remediation round remains recorded.",
    }
    if state["phase"] == "released":
        return ("Generic remediation reservation released before any create attempt.\n\n"
                + MARKER + json.dumps(state, sort_keys=True, separators=(",", ":")) + " -->\n")
    text = (f"Cursor remediation round {state['round']} reserved for {state['findings']} Codex finding(s).\n"
            f"Agent id: {state['agent_id']}\n{descriptions[state['phase']]}")
    if state["phase"] == "terminal":
        text += f"\nTerminal status: {state['status']}."
    return (text + "\n\n" + remediation_marker(state["review"], state["head"]) + "\n\n"
            + MARKER + json.dumps(state, sort_keys=True, separators=(",", ":")) + " -->\n")


def parse_body(body):
    if not isinstance(body, str) or body.count(MARKER) != 1:
        raise Stop("Unknown or legacy generic worker receipt; manual reconciliation required")
    line = body.rstrip("\n").split("\n")[-1]
    if not line.startswith(MARKER) or not line.endswith(" -->"):
        raise Stop("Generic worker record must be the final line")
    state = validate_state(load_json(line[len(MARKER):-4]))
    if body.rstrip("\n") != state_body(state).rstrip("\n"):
        raise Stop("Generic worker receipt does not match its launch record")
    return state


def candidate(body):
    return (isinstance(body, str) and not checkpoint_evidence(body)
            and any(prefix in body for prefix in ("<!-- codex-cursor-worker",
                    "<!-- codex-cursor-claim", "<!-- codex-cursor-remediation")))


def records(comments, pr, *, ignore_comment_id=None):
    validate_target(pr)
    if not isinstance(comments, list):
        raise Stop("Invalid generic worker comment history")
    result = []
    seen = set()
    for comment in comments:
        if not owner_authored(comment) or not candidate(comment.get("body")):
            continue
        state = parse_body(comment["body"])
        if (not positive_int(comment.get("id"))
                or comment.get("issue_url") != f"https://api.github.com/repos/{REPO}/issues/{pr}"
                or state["pr"] != pr):
            raise Stop("Generic worker receipt targets another PR")
        if comment["id"] != ignore_comment_id and comment["id"] not in seen:
            result.append((comment, state))
            seen.add(comment["id"])
    return result


def pending_generic_claim(comments, pr, *, ignore_comment_id=None):
    return any(state["phase"] not in {"terminal", "released"} for _, state in
               records(comments, pr, ignore_comment_id=ignore_comment_id))


def pages(path):
    from goal_lineage import bounded_pages
    return bounded_pages(path, read=gh)


def authorize():
    if (os.environ.get("GITHUB_REPOSITORY") != REPO
            or os.environ.get("TREMELAY_WORKER_ADMISSION") != "serialized-v1"):
        raise Stop("Generic worker operations require serialized repository admission")
    account = gh("user")
    if not isinstance(account, dict) or account.get("login") != OWNER:
        raise Stop("Generic worker operations require the approved owner identity")


def live_target(pr, head):
    pull = gh(f"repos/{REPO}/pulls/{pr}")
    if not isinstance(pull, dict):
        raise Stop("Missing live generic PR")
    raw_labels = pull.get("labels")
    if (not isinstance(raw_labels, list) or any(not isinstance(label, dict)
            or not isinstance(label.get("name"), str) for label in raw_labels)):
        raise Stop("Missing generic PR labels")
    labels = {label["name"] for label in raw_labels}
    if (pull.get("number") != pr or pull.get("state") != "open"
            or (pull.get("head") or {}).get("sha") != head
            or ((pull.get("head") or {}).get("repo") or {}).get("full_name") != REPO
            or ((pull.get("base") or {}).get("repo") or {}).get("full_name") != REPO
            or LOOP_LABEL not in labels or labels & {"goal", "human-review-required"}):
        raise Stop("Live PR is no longer eligible for exact-head generic remediation")


def prepare(plan):
    if not isinstance(plan, dict) or plan.get("action") != "launch":
        raise Stop("Generic worker requires a launch plan")
    payload = plan.get("payload")
    if not isinstance(payload, dict):
        raise Stop("Generic worker requires a valid payload")
    state = validate_state({"repo": REPO, "pr": plan.get("pr_number"),
        "review": str(plan.get("review_id")), "head": plan.get("head_sha"),
        "agent_id": payload.get("agentId"),
        "round": plan.get("round"), "findings": plan.get("findings"), "phase": "prepared"})
    required = {"agentId", "name", "prompt", "repos", "workOnCurrentBranch", "autoCreatePR", "skipReviewerRequest"}
    if (set(payload) != required
            or plan.get("marker") != remediation_marker(state["review"], state["head"])
            or plan.get("pr_url") != f"https://github.com/{REPO}/pull/{state['pr']}"
            or payload.get("repos") != [{"url": f"https://github.com/{REPO}",
                                          "prUrl": plan["pr_url"]}]
            or payload.get("workOnCurrentBranch") is not True
            or payload.get("autoCreatePR") is not False or payload.get("skipReviewerRequest") is not True
            or not isinstance(payload.get("name"), str)
            or not isinstance(payload.get("prompt"), dict) or set(payload["prompt"]) != {"text"}
            or not isinstance(payload["prompt"]["text"], str) or not payload["prompt"]["text"].strip()):
        raise Stop("Generic payload destination or options are not authorized")
    return state, payload


def persist(comment, state):
    body = state_body(state)
    if comment["body"].rstrip("\n") != body.rstrip("\n"):
        gh(f"repos/{REPO}/issues/comments/{comment['id']}", method="PATCH", data={"body": body})
        comment["body"] = body


def reconcile_one(comment, state):
    if state["phase"] in {"terminal", "released"}:
        return state
    if state["phase"] == "prepared":
        released = dict(state, phase="released")
        persist(comment, released)
        return released
    agent_id = state["agent_id"]
    agent = cursor("/" + agent_id)
    if not isinstance(agent, dict) or agent.get("id") != agent_id:
        raise Stop("Cursor lookup did not establish generic worker identity")
    run_id = state.get("run_id") or agent.get("latestRunId")
    if (not isinstance(run_id, str) or not RUN_ID.fullmatch(run_id)
            or agent.get("latestRunId") != run_id):
        raise Stop("Cursor lookup did not establish the same generic worker run")
    working = validate_state(dict(state, phase="working", run_id=run_id))
    persist(comment, working)
    run = cursor(f"/{agent_id}/runs/{run_id}")
    if (not isinstance(run, dict) or run.get("id") != run_id or run.get("agentId") != agent_id
            or not isinstance(run.get("status"), str) or run["status"] not in TERMINAL | {"CREATING", "RUNNING"}):
        raise Stop("Cursor lookup did not establish generic worker status")
    verify_legacy_target(agent, run, state["pr"])
    if run["status"] not in TERMINAL:
        return working
    current = cursor("/" + agent_id)
    if (not isinstance(current, dict) or current.get("id") != agent_id
            or current.get("latestRunId") != run_id):
        raise Stop("Generic worker changed during terminal reconciliation")
    verify_legacy_target(current, run, state["pr"])
    terminal = validate_state(dict(working, phase="terminal", status=run["status"]))
    persist(comment, terminal)
    return terminal


def reconcile(pr):
    validate_target(pr)
    authorize()
    comments = pages(f"repos/{REPO}/issues/{pr}/comments")
    return [reconcile_one(comment, state) for comment, state in records(comments, pr)]


def launch(plan):
    from goal_lineage import ensure_unowned_repository
    authorize()
    state, payload = prepare(plan)
    pr = state["pr"]
    comments = pages(f"repos/{REPO}/issues/{pr}/comments")
    existing = records(comments, pr)
    same = [(comment, saved) for comment, saved in existing
            if saved["review"] == state["review"] and saved["head"] == state["head"]
            and saved["phase"] != "released"]
    if same:
        if len(same) != 1:
            raise Stop("Multiple generic receipts need explicit reconciliation")
        comment, saved = same[0]
        return reconcile_one(comment, saved), comment["id"]
    live_target(pr, state["head"])
    markers = _round_markers(comments, trusted_login=OWNER)
    if len(markers) >= 3 or state["round"] != len(markers) + 1:
        raise Stop("Generic three-round budget changed before admission")
    ensure_unowned_repository(pages=pages)
    body = state_body(state)
    comment = gh(f"repos/{REPO}/issues/{pr}/comments", method="POST", data={"body": body})
    if not isinstance(comment, dict) or records([comment], pr) != [(comment, state)]:
        raise Stop("Generic reservation was not durably acknowledged; no worker create attempted")
    comment_id = comment["id"]
    # All fallible admission reads happen while this is definitely unlaunched.
    try:
        live_target(pr, state["head"])
        ensure_unowned_repository(pages=pages, ignore_comment_id=comment_id)
        saved = gh(f"repos/{REPO}/issues/comments/{comment_id}")
        if not isinstance(saved, dict) or records([saved], pr) != [(saved, state)] or saved.get("id") != comment_id:
            raise Stop("Generic reservation changed before dispatch")
    except RuntimeError:
        # Do not overwrite a changed or malformed trusted claim with a release.
        current = gh(f"repos/{REPO}/issues/comments/{comment_id}")
        if not isinstance(current, dict) or records([current], pr) != [(current, state)] or current.get("id") != comment_id:
            raise Stop("Generic preparation changed; explicit reconciliation required")
        persist(comment, dict(state, phase="released"))
        raise
    state = dict(state, phase="dispatch_reserved")
    persist(comment, state)
    # Exactly one create. Transport errors and 404 recovery never remove this receipt.
    response = cursor("", payload=payload)
    agent = response.get("agent") if isinstance(response, dict) else None
    run = response.get("run") if isinstance(response, dict) else None
    if (not isinstance(agent, dict) or agent.get("id") != state["agent_id"]
            or not isinstance(run, dict) or ("agentId" in run and run["agentId"] != state["agent_id"])
            or not isinstance(run.get("id"), str) or not RUN_ID.fullmatch(run["id"])):
        raise Stop("Cursor create response does not match generic reservation")
    working = validate_state(dict(state, phase="working", run_id=run["id"]))
    persist(comment, working)
    return working, comment_id


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("launch")
    create.add_argument("--plan", required=True)
    recovery = commands.add_parser("reconcile")
    recovery.add_argument("--pr", type=int, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "reconcile":
            states = reconcile(args.pr)
            print(f"Reconciled {len(states)} generic worker receipt(s); no worker create attempted")
        else:
            state, comment_id = launch(load_json(Path(args.plan).read_text(encoding="utf-8")))
            if state["phase"] != "working":
                raise Stop("Existing generic worker is terminal; no replacement created")
            Path("agent_id.txt").write_text(state["agent_id"] + "\n", encoding="utf-8")
            Path("run_id.txt").write_text(state["run_id"] + "\n", encoding="utf-8")
            with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
                output.write(f"agent_id={state['agent_id']}\nrun_id={state['run_id']}\nclaim_id={comment_id}\n")
    except (RuntimeError, ValueError, KeyError, TypeError) as error:
        print(f"Generic worker stopped: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
