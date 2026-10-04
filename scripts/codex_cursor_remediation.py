#!/usr/bin/env python3
"""Plan opt-in Codex -> Cursor remediation runs for pull requests.

The GitHub workflow owns side effects. This module decides whether a submitted
Codex review should launch Cursor, binds the work to the exact reviewed head,
deduplicates review events, and enforces a bounded remediation loop.
"""

from __future__ import annotations

import argparse
import json
import re
import uuid
from pathlib import Path
from typing import Any

CODEX_LOGINS = frozenset({"codex", "chatgpt-codex-connector[bot]"})
LOOP_LABEL = "codex-cursor-loop"
MARKER_PREFIX = "<!-- codex-cursor-remediation "
MARKER_RE = re.compile(
    r"<!-- codex-cursor-remediation review:(?P<review_id>[0-9]+) "
    r"head:(?P<head>[0-9a-fA-F]{40}) -->"
)
DEFAULT_MAX_ROUNDS = 3
DEFAULT_REPO_URL = "https://github.com/CharitonMedia/Tremelay"
DEFAULT_TRUSTED_MARKER_LOGIN = "pattalkslaw-del"


def _actor_login(value: Any) -> str:
    if not isinstance(value, dict):
        return ""
    for key in ("user", "author"):
        actor = value.get(key)
        if isinstance(actor, dict):
            login = actor.get("login")
            if isinstance(login, str):
                return login
    return ""


def _is_codex(login: str) -> bool:
    return (login or "").casefold() in CODEX_LOGINS


def _label_names(pull: dict[str, Any]) -> set[str]:
    names: set[str] = set()
    for label in pull.get("labels") or []:
        if isinstance(label, str):
            names.add(label)
        elif isinstance(label, dict):
            name = label.get("name")
            if isinstance(name, str):
                names.add(name)
    return names


def _head_sha(pull: dict[str, Any]) -> str | None:
    for key in ("headRefOid", "head_sha", "headSha"):
        value = pull.get(key)
        if isinstance(value, str) and value:
            return value
    head = pull.get("head")
    if isinstance(head, dict):
        value = head.get("sha")
        if isinstance(value, str) and value:
            return value
    return None


def _review_sha(review: dict[str, Any]) -> str | None:
    for key in ("commit_id", "commitId"):
        value = review.get(key)
        if isinstance(value, str) and value:
            return value
    commit = review.get("commit")
    if isinstance(commit, dict):
        value = commit.get("oid") or commit.get("sha")
        if isinstance(value, str) and value:
            return value
    return None


def _same_commit(left: str | None, right: str | None) -> bool:
    if not isinstance(left, str) or not isinstance(right, str):
        return False
    a = left.strip().casefold()
    b = right.strip().casefold()
    if len(a) < 7 or len(b) < 7:
        return False
    return a == b or a.startswith(b) or b.startswith(a)


def _flatten_pages(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, list):
        return []
    if payload and all(isinstance(page, list) for page in payload):
        result: list[dict[str, Any]] = []
        for page in payload:
            result.extend(item for item in page if isinstance(item, dict))
        return result
    return [item for item in payload if isinstance(item, dict)]


def remediation_marker(review_id: int | str, head_sha: str) -> str:
    return f"{MARKER_PREFIX}review:{review_id} head:{head_sha} -->"


def _round_markers(
    issue_comments: list[dict[str, Any]],
    *,
    trusted_login: str,
) -> list[str]:
    trusted = trusted_login.casefold()
    found: list[str] = []
    seen: set[str] = set()
    for comment in issue_comments:
        if _actor_login(comment).casefold() != trusted:
            continue
        body = comment.get("body")
        if not isinstance(body, str):
            continue
        for line in body.splitlines():
            marker = line.strip()
            if not MARKER_RE.fullmatch(marker) or marker in seen:
                continue
            seen.add(marker)
            found.append(marker)
    return found


def _finding_key(comment: dict[str, Any], body: str) -> tuple[Any, ...]:
    comment_id = comment.get("id")
    if isinstance(comment_id, (int, str)) and str(comment_id).strip():
        return ("id", str(comment_id))
    return (
        "location",
        comment.get("path") if isinstance(comment.get("path"), str) else "",
        comment.get("line") if isinstance(comment.get("line"), int) else None,
        comment.get("start_line") if isinstance(comment.get("start_line"), int) else None,
        comment.get("position") if isinstance(comment.get("position"), int) else None,
        comment.get("side") if isinstance(comment.get("side"), str) else "",
        body,
    )


def _format_finding(comment: dict[str, Any], body: str) -> str:
    path = comment.get("path")
    if not isinstance(path, str) or not path:
        return body
    line = comment.get("line")
    if isinstance(line, int):
        return f"{path}:{line}\n{body}"
    position = comment.get("position")
    if isinstance(position, int):
        return f"{path} (diff position {position})\n{body}"
    return f"{path}\n{body}"


def _collect_findings(review_comments: list[dict[str, Any]]) -> list[str]:
    findings: list[str] = []
    seen: set[tuple[Any, ...]] = set()
    for comment in review_comments:
        if not _is_codex(_actor_login(comment)):
            continue
        body = comment.get("body")
        if not isinstance(body, str):
            continue
        text = body.strip()
        if not text:
            continue
        key = _finding_key(comment, text)
        if key in seen:
            continue
        seen.add(key)
        findings.append(_format_finding(comment, text))
    return findings


def _prompt(
    *,
    pr_number: int,
    pr_url: str,
    head_sha: str,
    findings: list[str],
    round_number: int,
) -> str:
    numbered = "\n\n".join(
        f"Finding {index}:\n{finding}" for index, finding in enumerate(findings, start=1)
    )
    return (
        f"You are remediating Codex findings on pull request #{pr_number}: {pr_url}\n"
        f"Exact reviewed head: {head_sha}\n"
        f"Automation remediation round: {round_number}\n\n"
        "Read AGENTS.md, the pull request body, the current diff, and relevant tests before changing code. "
        "The findings below are the only new remediation scope. Fix legitimate defects completely, add "
        "focused regression tests, and preserve behavior already established by this pull request. Do not "
        "widen permissions, capabilities, conversion semantics, or release scope merely to make a test pass.\n\n"
        f"{numbered}\n\n"
        "Work on this pull request's existing branch. Do not create another branch or pull request. "
        "Run `go test ./...` and `go vet ./...`; fix failures caused by your changes. "
        "Commit and push the remediation.\n\n"
        "Do not merge. Do not package or publish a release. Do not request Codex and do not mention @codex. "
        "The workflow will request the next independent review only after exact-head Linux and Windows CI pass. "
        "If the reviewed head no longer matches the branch you were given, or a finding requires a product or "
        "architecture decision that conflicts with AGENTS.md, stop and report the blocker instead of guessing."
    )


def build_plan(
    event: dict[str, Any],
    pull: dict[str, Any],
    review_comments_payload: Any,
    issue_comments_payload: Any,
    *,
    max_rounds: int = DEFAULT_MAX_ROUNDS,
    repo_url: str = DEFAULT_REPO_URL,
    trusted_marker_login: str = DEFAULT_TRUSTED_MARKER_LOGIN,
) -> dict[str, Any]:
    if event.get("action") != "submitted":
        return {"action": "skip", "reason": "not a submitted review"}

    review = event.get("review")
    if not isinstance(review, dict) or not _is_codex(_actor_login(review)):
        return {"action": "skip", "reason": "review is not from Codex"}

    if LOOP_LABEL not in _label_names(pull):
        return {"action": "skip", "reason": f"pull request lacks {LOOP_LABEL} label"}

    if not isinstance(trusted_marker_login, str) or not trusted_marker_login.strip():
        return {"action": "stop", "reason": "trusted automation identity is unavailable"}

    pr_number = pull.get("number")
    pr_url = pull.get("url") or pull.get("html_url")
    if not isinstance(pr_number, int) or not isinstance(pr_url, str) or not pr_url:
        return {"action": "stop", "reason": "live pull request metadata is incomplete"}

    head_sha = _head_sha(pull)
    reviewed_sha = _review_sha(review)
    if not _same_commit(reviewed_sha, head_sha):
        return {
            "action": "stop",
            "reason": "Codex reviewed a stale head; exact-head binding refused the launch",
            "reviewed_sha": reviewed_sha,
            "head_sha": head_sha,
        }
    assert head_sha is not None

    review_id = review.get("id")
    if not isinstance(review_id, (int, str)) or str(review_id).strip() == "":
        return {"action": "stop", "reason": "Codex review has no stable review id"}

    issue_comments = _flatten_pages(issue_comments_payload)
    marker = remediation_marker(review_id, head_sha)
    markers = _round_markers(
        issue_comments,
        trusted_login=trusted_marker_login.strip(),
    )
    if marker in markers:
        return {"action": "skip", "reason": "this Codex review was already dispatched"}

    if len(markers) >= max_rounds:
        return {
            "action": "stop",
            "reason": f"remediation circuit breaker reached {max_rounds} rounds",
            "rounds": len(markers),
        }

    findings = _collect_findings(_flatten_pages(review_comments_payload))
    if not findings:
        return {
            "action": "skip",
            "reason": "Codex review contains no inline findings to remediate",
            "head_sha": head_sha,
        }

    round_number = len(markers) + 1
    agent_id = "bc-" + str(
        uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"{repo_url}|pr:{pr_number}|review:{review_id}|head:{head_sha}",
        )
    )
    payload = {
        "agentId": agent_id,
        "name": f"Codex remediation PR #{pr_number} round {round_number}",
        "prompt": {
            "text": _prompt(
                pr_number=pr_number,
                pr_url=pr_url,
                head_sha=head_sha,
                findings=findings,
                round_number=round_number,
            )
        },
        "repos": [{"url": repo_url, "prUrl": pr_url}],
        "workOnCurrentBranch": True,
        "autoCreatePR": False,
        "skipReviewerRequest": True,
    }
    return {
        "action": "launch",
        "pr_number": pr_number,
        "pr_url": pr_url,
        "head_sha": head_sha,
        "review_id": review_id,
        "round": round_number,
        "marker": marker,
        "findings": len(findings),
        "payload": payload,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    build = sub.add_parser("build")
    build.add_argument("--event", required=True)
    build.add_argument("--pull", required=True)
    build.add_argument("--review-comments", required=True)
    build.add_argument("--issue-comments", required=True)
    build.add_argument("--out", required=True)
    build.add_argument("--max-rounds", type=int, default=DEFAULT_MAX_ROUNDS)
    build.add_argument("--repo-url", default=DEFAULT_REPO_URL)
    build.add_argument("--trusted-marker-login", default=DEFAULT_TRUSTED_MARKER_LOGIN)

    args = parser.parse_args(argv)
    event = json.loads(Path(args.event).read_text(encoding="utf-8"))
    pull = json.loads(Path(args.pull).read_text(encoding="utf-8"))
    review_comments = json.loads(Path(args.review_comments).read_text(encoding="utf-8"))
    issue_comments = json.loads(Path(args.issue_comments).read_text(encoding="utf-8"))
    plan = build_plan(
        event,
        pull,
        review_comments,
        issue_comments,
        max_rounds=args.max_rounds,
        repo_url=args.repo_url,
        trusted_marker_login=args.trusted_marker_login,
    )
    Path(args.out).write_text(json.dumps(plan, indent=2), encoding="utf-8")
    print(plan["action"])
    if plan.get("reason"):
        print(plan["reason"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
