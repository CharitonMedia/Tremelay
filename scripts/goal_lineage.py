#!/usr/bin/env python3
"""Fresh, fail-closed guards for one goal issue's complete PR lineage."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

REPO = "CharitonMedia/Tremelay"
OWNER = "pattalkslaw-del"
MAX_HISTORY_PAGES = 100
ISSUE_LINE = re.compile(r"^Goal-Issue: #([1-9][0-9]*)$")


class LineageStop(RuntimeError):
    pass


def _number(value):
    return type(value) is int and value > 0


def _markers(body):
    if not isinstance(body, str):
        raise LineageStop("Missing goal PR body")
    return {int(match[1]) for line in body.splitlines()
            if (match := ISSUE_LINE.fullmatch(line.strip()))}


def source_issue(pull):
    """Bind one live PR to its exact source issue and canonical goal branch."""
    if not isinstance(pull, dict):
        raise LineageStop("Missing live goal PR")
    if (pull.get("user", {}).get("login") != OWNER
            or pull.get("base", {}).get("ref") != "main"):
        raise LineageStop("Goal PR author or base is not authorized")
    markers = _markers(pull.get("body") or "")
    if len(markers) != 1:
        raise LineageStop("Goal PR does not identify exactly one source issue")
    issue = next(iter(markers))
    head = pull.get("head") or {}
    if (head.get("ref") != f"goal/issue-{issue}"
            or (head.get("repo") or {}).get("full_name") != REPO):
        raise LineageStop("Goal PR branch does not match its source issue")
    return issue


def ensure_open_lineage(issue_number, *, read, pages):
    """Return all branch/marker-related PRs; retired or uncertain goals stop."""
    if not _number(issue_number):
        raise LineageStop("Invalid source issue number")
    issue = read(f"repos/{REPO}/issues/{issue_number}")
    if (not isinstance(issue, dict) or issue.get("number") != issue_number
            or issue.get("state") != "open" or issue.get("pull_request")):
        raise LineageStop("Source goal issue is closed or unavailable")
    history = pages(f"repos/{REPO}/pulls?state=all")
    if not isinstance(history, list):
        raise LineageStop("Incomplete goal PR history")
    related = []
    for pull in history:
        if (not isinstance(pull, dict) or not _number(pull.get("number"))
                or not isinstance(pull.get("head"), dict)
                or "body" not in pull):
            raise LineageStop("Malformed goal PR history")
        head = pull["head"]
        branch_matches = (head.get("ref") == f"goal/issue-{issue_number}"
                          and (head.get("repo") or {}).get("full_name") == REPO)
        if not branch_matches and issue_number not in _markers(pull.get("body") or ""):
            continue
        if (pull.get("state") not in {"open", "closed"} or "merged_at" not in pull
                or (pull["merged_at"] is not None and not isinstance(pull["merged_at"], str))):
            raise LineageStop("Missing goal PR lifecycle state")
        if pull["merged_at"] is not None:
            raise LineageStop("A prior PR already merged this goal lineage")
        related.append(pull)
    return related


def ensure_not_held(pulls):
    for pull in pulls:
        raw = pull.get("labels")
        if not isinstance(raw, list) or any(not isinstance(label, dict) or not isinstance(label.get("name"), str) for label in raw):
            raise LineageStop("Missing goal PR labels")
        labels = {label["name"] for label in raw}
        if pull["state"] == "open" and "human-review-required" in labels and "goal" not in labels:
            raise LineageStop("Goal PR is held for manual review")


def ensure_unowned_lineage(pulls, *, pages, ignore_comment_id=None):
    from goal_review_launch import pending_claim
    for pull in pulls:
        comments = pages(f"repos/{REPO}/issues/{pull['number']}/comments")
        if pending_claim(comments, REPO, pull["number"], OWNER,
                         ignore_comment_id=ignore_comment_id):
            raise LineageStop("An existing worker or supervisor owns this goal lineage")


def ensure_unowned_repository(*, pages, ignore_comment_id=None):
    """A new issue cannot start while an older goal/review worker still owns work."""
    pulls = pages(f"repos/{REPO}/pulls?state=all")
    if not isinstance(pulls, list):
        raise LineageStop("Incomplete repository PR ownership history")
    for pull in pulls:
        if (not isinstance(pull, dict) or not _number(pull.get("number"))
                or not isinstance(pull.get("head"), dict)):
            raise LineageStop("Malformed repository PR ownership history")
    own = [pull for pull in pulls if (pull["head"].get("repo") or {}).get("full_name") == REPO]
    ensure_unowned_lineage(own, pages=pages, ignore_comment_id=ignore_comment_id)


def gh_read(path):
    return _gh_json(["gh", "api", path])


def gh_pages(path):
    return bounded_pages(path, read=gh_read)


def bounded_pages(path, *, read):
    """Read the complete bounded history or fail; never authorize a prefix."""
    prefix = path + ("&" if "?" in path else "?") + "per_page=100&page="
    result = []
    for page in range(1, MAX_HISTORY_PAGES + 1):
        rows = read(prefix + str(page))
        if not isinstance(rows, list) or len(rows) > 100:
            raise LineageStop("Incomplete paginated GitHub response")
        result.extend(rows)
        if len(rows) < 100:
            return result
    raise LineageStop("Goal history exceeds bounded pagination; explicit reconciliation required")


def _gh_json(argv):
    result = subprocess.run(argv, capture_output=True, text=True, check=False)
    if result.returncode:
        raise LineageStop("Could not read fresh goal lineage state")
    try:
        return json.loads(result.stdout)
    except (ValueError, TypeError):
        raise LineageStop("Could not decode goal lineage state") from None


def guard(*, issue_number=None, pr_number=None, head=None, launch=False,
          ignore_comment_id=None, repository_ownership=False, read=gh_read, pages=gh_pages):
    if pr_number is not None:
        pull = read(f"repos/{REPO}/pulls/{pr_number}")
        if (not isinstance(pull, dict) or pull.get("number") != pr_number
                or pull.get("state") != "open"):
            raise LineageStop("Target goal PR is no longer open")
        bound = source_issue(pull)
        if issue_number is not None and bound != issue_number:
            raise LineageStop("Target PR belongs to another source issue")
        issue_number = bound
        if head is not None and pull["head"].get("sha") != head:
            raise LineageStop("Goal PR head changed before launch")
    pulls = ensure_open_lineage(issue_number, read=read, pages=pages)
    if pr_number is not None and not any(p["number"] == pr_number for p in pulls):
        raise LineageStop("Target PR missing from goal lineage")
    ensure_not_held(pulls)
    if launch:
        if repository_ownership:
            ensure_unowned_repository(pages=pages, ignore_comment_id=ignore_comment_id)
        else:
            ensure_unowned_lineage(pulls, pages=pages, ignore_comment_id=ignore_comment_id)
    return pulls


def open_pr_records(pulls):
    # Broad marker history may deny work, but cannot nominate a fork or unrelated
    # branch as a mutation/worker destination.
    result = []
    for pull in pulls:
        if pull["state"] != "open":
            continue
        try:
            source_issue(pull)
        except LineageStop:
            continue
        result.append(dict(pull, url=pull.get("html_url"), headRefName=pull["head"]["ref"],
                           baseRefName=pull["base"]["ref"]))
    if len(result) > 1:
        raise LineageStop("Multiple open canonical goal PRs require reconciliation")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--issue", type=int)
    parser.add_argument("--pr", type=int)
    parser.add_argument("--head")
    parser.add_argument("--launch", action="store_true")
    parser.add_argument("--ignore-comment-id", type=int)
    parser.add_argument("--repository-ownership", action="store_true")
    parser.add_argument("--open-prs-out")
    args = parser.parse_args(argv)
    try:
        pulls = guard(issue_number=args.issue, pr_number=args.pr, head=args.head,
                      launch=args.launch, ignore_comment_id=args.ignore_comment_id,
                      repository_ownership=args.repository_ownership)
        if args.open_prs_out:
            Path(args.open_prs_out).write_text(json.dumps(open_pr_records(pulls)) + "\n", encoding="utf-8")
    except (LineageStop, RuntimeError, ValueError) as error:
        print(f"Goal lineage stopped: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
