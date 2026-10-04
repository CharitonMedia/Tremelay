#!/usr/bin/env python3
"""Recognize Codex's clean-review GitHub comment as a terminal goal signal."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

GOAL_LABEL = "goal"
GOAL_READY_LABEL = "goal-ready"
GOAL_READY_COLOR = "0E8A16"
GOAL_READY_DESCRIPTION = "Codex completed a clean review of this goal pull request."
_GOAL_ISSUE_LINE = re.compile(r"^Goal-Issue: #(\d+)$")
_CLEAN_REVIEW = re.compile(r"^Codex Review: Didn't find any major issues\.", re.MULTILINE)
_REVIEWED_COMMIT = re.compile(r"\*\*Reviewed commit:\*\* `([0-9a-fA-F]{7,40})`")


def _is_codex_login(login: str) -> bool:
    return (login or "").casefold() == "chatgpt-codex-connector[bot]"


def _label_names(pull: dict) -> set[str]:
    names: set[str] = set()
    for label in pull.get("labels") or []:
        if isinstance(label, str):
            names.add(label)
        elif isinstance(label, dict) and label.get("name"):
            names.add(label["name"])
    return names


def _goal_issue(body: str) -> int | None:
    for line in (body or "").splitlines():
        match = _GOAL_ISSUE_LINE.match(line.strip())
        if match:
            return int(match.group(1))
    return None


def reviewed_commit(body: str) -> str | None:
    """Return the commit named by a Codex review comment, when one is present."""
    match = _REVIEWED_COMMIT.search(body or "")
    if not match:
        return None
    return match.group(1)


def is_terminal_clean_review(body: str) -> bool:
    """A Codex comment that reports no findings for a specific commit."""
    text = body or ""
    return _CLEAN_REVIEW.search(text) is not None and reviewed_commit(text) is not None


def completion_plan(event: dict, pull: dict) -> dict | None:
    # Codex edits the in-progress review comment into the clean result.
    if event.get("action") not in {"created", "edited"}:
        return None
    issue = event.get("issue") or {}
    if not issue.get("pull_request"):
        return None
    comment = event.get("comment") or {}
    login = ((comment.get("user") or {}).get("login") or "")
    if not _is_codex_login(login):
        return None
    body = comment.get("body") or ""
    if not is_terminal_clean_review(body):
        return None
    reviewed_sha = reviewed_commit(body)

    pr_number = pull.get("number")
    if not isinstance(pr_number, int) or issue.get("number") != pr_number:
        return None
    issue_number = _goal_issue(pull.get("body") or "")
    if issue_number is None:
        return None

    head = pull.get("headRefOid") or pull.get("head_sha") or pull.get("headSha")
    if not isinstance(head, str) or not head:
        return None
    if not isinstance(reviewed_sha, str) or not head.casefold().startswith(reviewed_sha.casefold()):
        return None

    labels = _label_names(pull)
    if GOAL_LABEL not in labels:
        return None

    return {
        "pr_number": pr_number,
        "issue_number": issue_number,
        "add_goal_ready": GOAL_READY_LABEL not in labels,
        "remove_goal": True,
    }


def _run(argv: list[str]) -> str:
    completed = subprocess.run(argv, check=False, capture_output=True, text=True)
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        raise RuntimeError(detail or f"command failed: {argv[0]}")
    return completed.stdout.strip()


def apply_plan(plan: dict) -> None:
    _run([
        "gh", "label", "create", GOAL_READY_LABEL,
        "--color", GOAL_READY_COLOR,
        "--description", GOAL_READY_DESCRIPTION,
        "--force",
    ])
    pr = str(plan["pr_number"])
    if plan["add_goal_ready"]:
        _run(["gh", "pr", "edit", pr, "--add-label", GOAL_READY_LABEL])

    message = (
        f"Goal complete. PR #{plan['pr_number']} is implemented, tested, "
        "and has a clean Codex review."
    )
    issue = str(plan["issue_number"])
    comments = _run(["gh", "issue", "view", issue, "--json", "comments", "--jq", ".comments[].body"])
    if message not in comments.splitlines():
        _run(["gh", "issue", "comment", issue, "--body", message])

    if plan["remove_goal"]:
        _run(["gh", "pr", "edit", pr, "--remove-label", GOAL_LABEL])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--event", required=True)
    parser.add_argument("--pull", required=True)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    event = json.loads(Path(args.event).read_text(encoding="utf-8"))
    pull = json.loads(Path(args.pull).read_text(encoding="utf-8"))
    plan = completion_plan(event, pull)
    if plan is None:
        print("skip", file=sys.stderr)
        return 2
    if not args.dry_run:
        apply_plan(plan)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
