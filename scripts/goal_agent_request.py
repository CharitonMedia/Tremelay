#!/usr/bin/env python3
"""Build Cursor cloud-agent requests and the GitHub calls that wrap them.

`build` writes the Cloud Agents API body. Exit 2 means the event is not a
goal dispatch. `apply-sync` is the only pull-request creator: the agent
payload always sets autoCreatePR to false. `codex-rereview` prints
`@codex review` when a finished remediation pushed new commits.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

from complete_codex_clean_review import is_terminal_clean_review, reviewed_commit

DEFAULT_BASE_REF = "main"
DEFAULT_REPO_URL = "https://github.com/CharitonMedia/Tremelay"
GOAL_LABEL = "goal"
GOAL_READY_LABEL = "goal-ready"
GOAL_READY_COLOR = "0E8A16"
GOAL_READY_DESCRIPTION = "Codex approved this goal pull request."
GOAL_BRANCH_PREFIX = "goal/issue-"
CODEX_REVIEW_COMMENT = "@codex review"
_CODEX_LOGINS = frozenset({"codex", "chatgpt-codex-connector[bot]"})
_GOAL_ISSUE_LINE = re.compile(r"^Goal-Issue: #(\d+)$")
NAME_LIMIT = 100
SKIP_ACTORS = frozenset(
    {"cursor[bot]", "cursor", "github-actions[bot]", "cursoragent"}
)
TERMINAL_RUN_STATUSES = frozenset({"FINISHED", "ERROR", "CANCELLED", "EXPIRED"})


def goal_branch(issue_number: int) -> str:
    return f"{GOAL_BRANCH_PREFIX}{issue_number}"


def parse_goal_branch(branch: str) -> int | None:
    if not branch.startswith(GOAL_BRANCH_PREFIX):
        return None
    number = branch[len(GOAL_BRANCH_PREFIX) :]
    if not number.isdigit():
        return None
    return int(number)


def goal_marker(issue_number: int) -> str:
    return f"Goal-Issue: #{issue_number}"


def build_payload(
    event: dict,
    event_name: str,
    *,
    repo_url: str = DEFAULT_REPO_URL,
    base_ref: str = DEFAULT_BASE_REF,
    open_prs: list | None = None,
) -> dict | None:
    if event_name == "issues":
        return _issue_payload(event, repo_url, base_ref, open_prs or [])
    if event_name in {"pull_request_review", "pull_request_review_comment", "issue_comment"}:
        return _review_payload(event, event_name, repo_url)
    return None


def branch_to_ensure(payload: dict) -> str | None:
    """Branch the workflow must create before launch, when no pull request exists yet."""
    repo = payload["repos"][0]
    if "prUrl" in repo:
        return None
    ref = repo.get("startingRef")
    if isinstance(ref, str) and parse_goal_branch(ref) is not None:
        return ref
    return None


def _issue_payload(event: dict, repo_url: str, base_ref: str, open_prs: list) -> dict | None:
    if event.get("action") != "labeled":
        return None
    label = (event.get("label") or {}).get("name")
    if label != GOAL_LABEL:
        return None
    issue = event.get("issue") or {}
    if issue.get("pull_request"):
        return None
    number = issue.get("number")
    if not isinstance(number, int):
        return None
    title = _single_line(issue.get("title") or f"Issue {number}")
    body = issue.get("body") or ""
    existing = _matching_pr(open_prs, number)
    prompt = _implement_prompt(
        number=number,
        title=title,
        body=body,
        repo_url=repo_url,
        base_ref=base_ref,
        existing=existing,
    )
    repo = {"url": repo_url}
    if existing:
        repo["prUrl"] = existing["url"]
    else:
        repo["startingRef"] = goal_branch(number)
    return {
        "name": _agent_name(f"Goal #{number}: {title}"),
        "prompt": {"text": prompt},
        "repos": [repo],
        "workOnCurrentBranch": True,
        "autoCreatePR": False,
        "skipReviewerRequest": True,
    }


def _review_payload(event: dict, event_name: str, repo_url: str) -> dict | None:
    if _skipped_actor(event):
        return None
    if event_name == "pull_request_review":
        if event.get("action") != "submitted":
            return None
        review = event.get("review") or {}
        if review.get("state") == "approved":
            return None
        event_text = review.get("body") or ""
    elif event_name == "pull_request_review_comment":
        if event.get("action") != "created":
            return None
        comment = event.get("comment") or {}
        path = comment.get("path") or ""
        event_text = comment.get("body") or ""
        if path:
            event_text = f"{path}\n{event_text}".strip()
    elif event_name == "issue_comment":
        if event.get("action") not in {"created", "edited"}:
            return None
        comment = event.get("comment") or {}
        user = comment.get("user") or {}
        if (user.get("login") or "").casefold() != "chatgpt-codex-connector[bot]":
            return None
        event_text = comment.get("body") or ""
        if is_terminal_clean_review(event_text):
            return None
        if "<!-- codex-pull-request-review-summary -->" not in event_text:
            return None
        if "✅ **Completed**" not in event_text:
            return None
        issue = event.get("issue") or {}
        if not issue.get("pull_request"):
            return None
        pull = {
            "number": issue.get("number"),
            "html_url": issue.get("html_url"),
            "body": issue.get("body") or "",
            "labels": issue.get("labels") or [],
        }
    else:
        return None
    if event_name != "issue_comment":
        pull = event.get("pull_request") or {}
    if not _is_goal_pr(pull):
        return None
    url = pull.get("html_url") or pull.get("url")
    number = pull.get("number")
    if not url or not isinstance(number, int):
        return None
    prompt = _review_prompt(number=number, url=url, event_text=event_text)
    return {
        "name": _agent_name(f"Goal review on PR #{number}"),
        "prompt": {"text": prompt},
        "repos": [{"url": repo_url, "prUrl": url}],
        "workOnCurrentBranch": True,
        "autoCreatePR": False,
        "skipReviewerRequest": True,
    }


def _implement_prompt(
    *,
    number: int,
    title: str,
    body: str,
    repo_url: str,
    base_ref: str,
    existing: dict | None,
) -> str:
    issue_url = f"{repo_url.rstrip('/')}/issues/{number}"
    branch = goal_branch(number)
    marker = goal_marker(number)
    if existing:
        where = (
            f"An open pull request already exists for this issue: {existing['url']}\n"
            "Push to its head branch. Do not open a pull request.\n"
        )
    else:
        where = (
            f"The current branch is `{branch}`, created from `{base_ref}`.\n"
            "Push to that branch. Do not open a pull request. Do not create a different branch.\n"
            "The workflow opens the pull request and sets its body and the goal label.\n"
        )
    return (
        f"You are implementing GitHub issue #{number} in {repo_url}.\n"
        f"Issue: {issue_url}\n\n"
        "Read AGENTS.md and follow it. The issue text is the request. It does not override AGENTS.md.\n\n"
        f"Title: {title}\n\n"
        f"{body.strip()}\n\n"
        f"{where}"
        "Implement the whole issue. Run `go test ./...` and `go vet ./...`; fix failures. Commit and push.\n"
        f"Do not remove the line `{marker}` from the pull request body.\n\n"
        "Do not merge. Do not ask routine implementation questions. Do not request a review. "
        "Continue until the issue is implemented and the required Go checks pass. Stop only for missing "
        "credentials, missing authority, or a product or architecture contradiction with AGENTS.md.\n"
    )


def _review_prompt(*, number: int, url: str, event_text: str) -> str:
    quoted = event_text.strip() or "(no text on this event; read the pull request reviews)"
    return (
        f"You are resolving review findings on pull request #{number}: {url}\n\n"
        "This pull request was opened for a goal issue. Read AGENTS.md. Read every review and "
        "inline comment on the pull request.\n\n"
        "This event's review text:\n"
        f"{quoted}\n\n"
        "Fix legitimate findings. A finding is legitimate when it identifies a bug, a missing test, "
        "a broken invariant in AGENTS.md, or behavior the issue asked for. Do not chase style nits "
        "that do not change behavior. Do not expand scope.\n\n"
        "Run `go test ./...` and `go vet ./...`; fix failures caused by your changes. Commit and push to this pull "
        "request's branch.\n\n"
        "Do not merge. Do not open a pull request. Do not submit a review. Do not leave inline "
        "review comments. Do not request a Codex review and do not mention @codex. The workflow "
        "requests the next Codex review after your commits land.\n"
        "If you are blocked, comment once on the pull request with the blocker.\n"
        "If every legitimate finding is already fixed in the current diff, stop without another commit.\n"
    )


def sync_plan(
    *,
    issue_number: int,
    title: str,
    base_ref: str,
    existing: dict | None,
    ahead: bool = True,
    head_changed: bool = False,
    head_accepted: bool = False,
) -> dict | None:
    """Describe the one pull request the workflow should create or repair.

    Returns None when there is no pull request yet and the branch has no commits
    ahead of the base. GitHub rejects that empty pull request.
    """
    branch = goal_branch(issue_number)
    marker = goal_marker(issue_number)
    if existing is None:
        if not ahead:
            return None
        return {
            "action": "create",
            "branch": branch,
            "base": base_ref,
            "title": _single_line(title) or f"Goal #{issue_number}",
            "body": marker + "\n",
            "label": GOAL_LABEL,
            "add_label": True,
            "update_body": False,
            "retarget_base": False,
        }
    body = existing.get("body") or ""
    has_marker = any(line.strip() == marker for line in body.splitlines())
    new_body = body if has_marker else _append_marker(body, marker)
    base_name = existing.get("baseRefName") or existing.get("base")
    labels = _label_names(existing)
    # A review can finish during the publish job's wait. That head is already
    # done, so syncing must not clear goal-ready or put the goal label back.
    stale_ready = head_changed and not head_accepted and GOAL_READY_LABEL in labels
    return {
        "action": "update",
        "number": existing["number"],
        "branch": branch,
        "base": base_ref,
        "title": _single_line(title) or f"Goal #{issue_number}",
        "body": new_body,
        "label": GOAL_LABEL,
        "add_label": GOAL_LABEL not in labels and not head_accepted,
        "remove_label": GOAL_READY_LABEL if stale_ready else None,
        "request_review": stale_ready,
        "update_body": not has_marker,
        "retarget_base": bool(base_name) and base_name != base_ref,
    }


def apply_plan(plan: dict | None, run) -> str | None:
    """Run the gh commands for a sync plan. Returns the pull request number."""
    if plan is None:
        return None

    if plan["action"] == "create":
        try:
            output = run(
                [
                    "gh",
                    "pr",
                    "create",
                    "--base",
                    plan["base"],
                    "--head",
                    plan["branch"],
                    "--title",
                    plan["title"],
                    "--body",
                    plan["body"],
                ]
            )
        except RuntimeError as exc:
            if "already exists" not in str(exc).lower():
                raise
            return None
        number = _pr_number_from_url(output)
        run(["gh", "pr", "edit", number, "--add-label", plan["label"]])
        return number

    number = str(plan["number"])
    if plan.get("update_body"):
        run(["gh", "pr", "edit", number, "--body", plan["body"]])
    if plan.get("add_label"):
        run(["gh", "pr", "edit", number, "--add-label", plan["label"]])
    if plan.get("remove_label"):
        run(["gh", "pr", "edit", number, "--remove-label", plan["remove_label"]])
    if plan.get("retarget_base"):
        run(["gh", "pr", "edit", number, "--base", plan["base"]])
    if plan.get("request_review"):
        run(["gh", "pr", "comment", number, "--body", CODEX_REVIEW_COMMENT])
    return number


def parse_goal_issue(body: str) -> int | None:
    """Return the issue number from an exact `Goal-Issue: #<n>` line."""
    for line in (body or "").splitlines():
        match = _GOAL_ISSUE_LINE.match(line.strip())
        if match:
            return int(match.group(1))
    return None


def completion_comment(pr_number: int) -> str:
    return f"Goal complete. PR #{pr_number} is implemented, tested, and approved by Codex."


def _completion_candidate(event: dict, event_name: str) -> dict | None:
    """Completion plan before the reviewed commit is compared with the live head."""
    if event_name != "pull_request_review" or event.get("action") != "submitted":
        return None
    if not _is_codex_approval(event):
        return None
    pull = event.get("pull_request") or {}
    if not _is_goal_pr(pull):
        return None
    pr_number = pull.get("number")
    issue_number = parse_goal_issue(pull.get("body") or "")
    if not isinstance(pr_number, int) or issue_number is None:
        return None
    labels = _label_names(pull)
    return {
        "action": "complete",
        "pr_number": pr_number,
        "issue_number": issue_number,
        "add_label": GOAL_READY_LABEL,
        "remove_label": GOAL_LABEL if GOAL_LABEL in labels else None,
        "issue_comment": completion_comment(pr_number),
        "launch": False,
        "request_codex": False,
    }


def _exact_commit(reviewed: str | None, head: str | None) -> bool:
    if not isinstance(reviewed, str) or not isinstance(head, str):
        return False
    left = reviewed.strip()
    right = head.strip()
    return bool(left) and left.casefold() == right.casefold()


def terminal_plan(event: dict, event_name: str, *, head_sha: str | None = None) -> dict | None:
    """Stop plan for a Codex APPROVED review of the current pull-request head.

    Returns None for every other event, including approvals that are not from
    Codex, approvals whose body has no exact Goal-Issue line, and approvals
    whose commit is not exactly `head_sha`. Callers must pass the live head;
    the webhook payload's head can be stale by the time this job runs.
    """
    plan = _completion_candidate(event, event_name)
    if plan is None:
        return None
    reviewed = _review_commit(event.get("review") or {})
    if not _exact_commit(reviewed, head_sha):
        return None
    return plan


def apply_terminal_plan(plan: dict | None, run) -> None:
    """Create goal-ready if needed, retag the pull request, and close the issue thread."""
    if plan is None:
        return
    run(
        [
            "gh",
            "label",
            "create",
            GOAL_READY_LABEL,
            "--color",
            GOAL_READY_COLOR,
            "--description",
            GOAL_READY_DESCRIPTION,
            "--force",
        ]
    )
    pr_number = str(plan["pr_number"])
    run(["gh", "pr", "edit", pr_number, "--add-label", plan["add_label"]])
    if plan.get("remove_label"):
        run(["gh", "pr", "edit", pr_number, "--remove-label", plan["remove_label"]])
    run(["gh", "issue", "comment", str(plan["issue_number"]), "--body", plan["issue_comment"]])


def codex_rereview_comment(
    *,
    run_status: str,
    before_sha: str,
    after_sha: str,
    reviews: list | None = None,
) -> str | None:
    """Request a fresh Codex review only after a finished remediation pushed commits.

    An approval of the new head stops the loop, so this returns None when that
    head already has an approved review.
    """
    if run_status != "FINISHED":
        return None
    before = before_sha.strip()
    after = after_sha.strip()
    if not before or not after or before == after:
        return None
    for review in reviews or []:
        if _review_state(review) != "approved":
            continue
        if _review_commit(review) == after:
            return None
    return CODEX_REVIEW_COMMENT


def select_open_pr(pulls: list, issue_number: int) -> dict | None:
    branch = goal_branch(issue_number)
    marker = goal_marker(issue_number)
    headed = []
    for pr in pulls:
        head = pr.get("headRefName") or pr.get("head")
        if head == branch:
            headed.append(pr)
    pool = headed or pulls
    for pr in pool:
        body = pr.get("body") or ""
        if any(line.strip() == marker for line in body.splitlines()):
            return pr
    if len(headed) == 1:
        return headed[0]
    return None


def _append_marker(body: str, marker: str) -> str:
    base = body.rstrip()
    if base:
        return base + "\n" + marker + "\n"
    return marker + "\n"


def _matching_pr(open_prs: list, number: int) -> dict | None:
    needle = goal_marker(number)
    matches = []
    for pr in open_prs:
        body = pr.get("body") or ""
        if any(line.strip() == needle for line in body.splitlines()):
            matches.append(pr)
    if not matches:
        return None
    labeled = [pr for pr in matches if GOAL_LABEL in _label_names(pr)]
    chosen = (labeled or matches)[0]
    url = chosen.get("url") or chosen.get("html_url")
    if not url:
        return None
    return {"url": url, "number": chosen.get("number")}


def _is_goal_pr(pull: dict) -> bool:
    if GOAL_LABEL in _label_names(pull):
        return True
    body = pull.get("body") or ""
    return any(line.strip().startswith("Goal-Issue: #") for line in body.splitlines())


def _label_names(pull: dict) -> set[str]:
    names = set()
    for label in pull.get("labels") or []:
        if isinstance(label, str):
            names.add(label)
        elif isinstance(label, dict) and label.get("name"):
            names.add(label["name"])
    return names


def _is_codex_login(login: str) -> bool:
    return (login or "").casefold() in _CODEX_LOGINS


def _is_codex_approval(event: dict) -> bool:
    review = event.get("review") or {}
    if _review_state(review) != "approved":
        return False
    logins = []
    sender = (event.get("sender") or {}).get("login")
    if sender:
        logins.append(sender)
    user = (review.get("user") or {}).get("login")
    if user:
        logins.append(user)
    author = (review.get("author") or {}).get("login")
    if author:
        logins.append(author)
    return any(_is_codex_login(login) for login in logins)


def _review_state(review: dict) -> str:
    return (review.get("state") or "").casefold()


def _review_commit(review: dict) -> str | None:
    commit = review.get("commit_id") or review.get("commitId")
    if isinstance(commit, str) and commit:
        return commit
    nested = review.get("commit")
    if isinstance(nested, dict):
        oid = nested.get("oid")
        if isinstance(oid, str) and oid:
            return oid
    return None


def _actor_login(record: dict) -> str:
    for key in ("user", "author"):
        actor = record.get(key) or {}
        if isinstance(actor, dict):
            login = actor.get("login")
            if isinstance(login, str) and login:
                return login
    return ""


def _commits_match(reviewed: str | None, head: str | None) -> bool:
    """True when both SHAs name the same commit, including a 7+ character prefix."""
    if not isinstance(reviewed, str) or not isinstance(head, str):
        return False
    left = reviewed.strip().casefold()
    right = head.strip().casefold()
    if len(left) < 7 or len(right) < 7:
        return False
    return left == right or right.startswith(left) or left.startswith(right)


def flatten_pages(payload: object) -> list:
    """Collapse ``gh api --paginate --slurp`` output into one list of records.

    ``--paginate`` prints each page as its own JSON value, so ``json.load``
    raises ``Extra data`` once a list endpoint returns a second page.
    ``--slurp`` wraps those pages in one array. A bare list of records is
    left unchanged so a single page fetched without ``--slurp`` still parses.
    """
    if not isinstance(payload, list):
        return []
    if payload and all(isinstance(page, list) for page in payload):
        return [item for page in payload for item in page]
    return payload


def head_already_reviewed(head_sha: str, state: dict | None) -> bool:
    """True when Codex has already approved this head or posted a clean review of it.

    The publish job sleeps before syncing pull-request labels. A review can
    finish during that wait; clearing goal-ready for the same commit restarts
    the loop.
    """
    payload = state or {}
    for review in payload.get("reviews") or []:
        if not isinstance(review, dict):
            continue
        if not _is_codex_login(_actor_login(review)):
            continue
        if _review_state(review) != "approved":
            continue
        if _commits_match(_review_commit(review), head_sha):
            return True
    for comment in payload.get("comments") or []:
        if not isinstance(comment, dict):
            continue
        if not _is_codex_login(_actor_login(comment)):
            continue
        body = comment.get("body") or ""
        if not is_terminal_clean_review(body):
            continue
        if _commits_match(reviewed_commit(body), head_sha):
            return True
    return False


def _skipped_actor(event: dict) -> bool:
    logins = []
    sender = event.get("sender") or {}
    if sender.get("login"):
        logins.append(sender["login"])
    for key in ("review", "comment"):
        user = (event.get(key) or {}).get("user") or {}
        if user.get("login"):
            logins.append(user["login"])
    return any(login.casefold() in SKIP_ACTORS for login in logins)


def _agent_name(text: str) -> str:
    collapsed = _single_line(text)
    if len(collapsed) <= NAME_LIMIT:
        return collapsed
    return collapsed[: NAME_LIMIT - 1].rstrip() + "…"


def _single_line(text: str) -> str:
    return " ".join(text.split())


def _pr_number_from_url(output: str) -> str:
    match = re.search(r"/pull/(\d+)\s*$", output.strip())
    if not match:
        raise RuntimeError(f"gh pr create did not return a pull request URL: {output.strip()}")
    return match.group(1)


def _run_gh(argv: list[str]) -> str:
    completed = subprocess.run(argv, check=False, capture_output=True, text=True)
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        raise RuntimeError(detail or f"command failed: {argv[0]}")
    return completed.stdout.strip()


def _load_json(path: str | None):
    if not path:
        return None
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _cmd_build(args: argparse.Namespace) -> int:
    event = json.loads(Path(args.event).read_text(encoding="utf-8"))
    open_prs = _load_json(args.open_prs)
    payload = build_payload(
        event,
        args.event_name,
        repo_url=args.repo_url,
        base_ref=args.base_ref,
        open_prs=open_prs,
    )
    if payload is None:
        print("skip", file=sys.stderr)
        return 2
    Path(args.out).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return 0


def _cmd_head_already_reviewed(args: argparse.Namespace) -> int:
    state = _load_json(args.state) or {}
    print("yes" if head_already_reviewed(args.head, state) else "no")
    return 0


def _cmd_apply_sync(args: argparse.Namespace) -> int:
    pulls = _load_json(args.existing) or []
    if isinstance(pulls, dict):
        pulls = [pulls]
    if args.pr_number is not None:
        existing = next((pr for pr in pulls if pr.get("number") == args.pr_number), None)
        if existing is None:
            print(f"pull request #{args.pr_number} was not found", file=sys.stderr)
            return 1
    else:
        existing = select_open_pr(pulls, args.issue_number)
    plan = sync_plan(
        issue_number=args.issue_number,
        title=args.title,
        base_ref=args.base_ref,
        existing=existing,
        ahead=args.ahead,
        head_changed=args.head_changed,
        head_accepted=args.head_accepted,
    )
    number = apply_plan(plan, _run_gh)
    if number:
        print(number)
    return 0


def _cmd_complete(args: argparse.Namespace) -> int:
    event = json.loads(Path(args.event).read_text(encoding="utf-8"))
    if _completion_candidate(event, args.event_name) is None:
        print("skip", file=sys.stderr)
        return 2
    if args.dry_run:
        return 0
    pr_number = (event.get("pull_request") or {}).get("number")
    try:
        head_sha = _run_gh(
            ["gh", "pr", "view", str(pr_number), "--json", "headRefOid", "--jq", ".headRefOid"]
        )
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    plan = terminal_plan(event, args.event_name, head_sha=head_sha)
    if plan is None:
        print("skip", file=sys.stderr)
        return 2
    apply_terminal_plan(plan, _run_gh)
    return 0


def _cmd_codex_rereview(args: argparse.Namespace) -> int:
    reviews = _load_json(args.reviews)
    if isinstance(reviews, dict):
        reviews = reviews.get("reviews", [])
    comment = codex_rereview_comment(
        run_status=args.status,
        before_sha=args.before,
        after_sha=args.after,
        reviews=reviews,
    )
    if comment is None:
        print("skip", file=sys.stderr)
        return 2
    print(comment)
    return 0


def review_claim_marker(review_id: int | str, head_sha: str) -> str:
    """Stable ownership marker for one Codex review of one head."""
    return f"<!-- goal-review-claim review:{review_id} head:{head_sha.strip().lower()} -->"


def _summary_commit(body: str) -> str | None:
    named = reviewed_commit(body)
    if named:
        return named
    found = re.findall(r"`([0-9a-fA-F]{7,40})`", body or "")
    if not found:
        return None
    return found[-1]


def review_launch_identity(
    event: dict,
    event_name: str,
    reviews: list | None = None,
) -> tuple[str, str] | None:
    """Review id and full head shared by a review, an inline comment, and a summary.

    Returns None when this event cannot be bound to one review of one commit.
    """
    if event_name == "pull_request_review":
        review = event.get("review") or {}
        return _identity_from_review(review)
    if event_name == "pull_request_review_comment":
        comment = event.get("comment") or {}
        review_id = comment.get("pull_request_review_id")
        head = comment.get("commit_id") or comment.get("commitId")
        if review_id is None or not isinstance(head, str):
            return None
        return _full_identity(review_id, head)
    if event_name == "issue_comment":
        body = ((event.get("comment") or {}).get("body") or "")
        if "<!-- codex-pull-request-review-summary -->" not in body:
            return None
        short = _summary_commit(body)
        if not short:
            return None
        for review in reviews or []:
            if not isinstance(review, dict) or not _is_codex_login(_actor_login(review)):
                continue
            full = _review_commit(review)
            if not _commits_match(short, full):
                continue
            found = _identity_from_review(review)
            if found is not None:
                return found
        return None
    return None


def _identity_from_review(review: dict) -> tuple[str, str] | None:
    return _full_identity(review.get("id"), _review_commit(review))


def _full_identity(review_id: object, head: object) -> tuple[str, str] | None:
    if not isinstance(review_id, (int, str)) or str(review_id).strip() == "":
        return None
    if not isinstance(head, str) or len(head.strip()) != 40:
        return None
    return str(review_id).strip(), head.strip().lower()


def review_claim_owned(
    comments: list | None,
    review_id: str,
    head_sha: str,
    trusted_login: str,
) -> bool:
    """True when the trusted automation identity already claimed this review and head."""
    trusted = (trusted_login or "").strip().casefold()
    if not trusted:
        return False
    marker = review_claim_marker(review_id, head_sha)
    for comment in comments or []:
        if not isinstance(comment, dict):
            continue
        login = ((comment.get("user") or {}).get("login") or "").casefold()
        if login != trusted:
            continue
        if marker in (comment.get("body") or ""):
            return True
    return False


def review_launch_decision(
    event: dict,
    event_name: str,
    *,
    reviews: list | None = None,
    comments: list | None = None,
    trusted_login: str = "",
) -> dict:
    """Whether this event may start a worker for its review and head."""
    identity = review_launch_identity(event, event_name, reviews)
    if identity is None:
        return {"status": "unbound", "owned": False, "marker": "", "review_id": "", "head": ""}
    review_id, head = identity
    marker = review_claim_marker(review_id, head)
    owned = review_claim_owned(comments, review_id, head, trusted_login)
    return {
        "status": "owned" if owned else "free",
        "owned": owned,
        "marker": marker,
        "review_id": review_id,
        "head": head,
    }


def create_outcome(http_code: str) -> str:
    """Classify a Cursor create HTTP status.

    accept: 2xx, the worker exists.
    reject: 4xx, the server refused and did not create a worker.
    ambiguous: 5xx, redirects, and any other status. The worker may exist.
    """
    code = (http_code or "").strip()
    if len(code) == 3 and code.isdigit():
        if code[0] == "2":
            return "accept"
        if code[0] == "4":
            return "reject"
    return "ambiguous"


def claim_survives_cancel(*, accepted: bool, create_settled: bool) -> bool:
    """A cancelled run keeps the claim once a worker was accepted or the create is unknown.

    create_settled is true only for a definitive outcome: the worker was accepted,
    or the server returned a 4xx client rejection. A 5xx or other ambiguous HTTP
    status is not settled. A settled rejection deletes the claim so a later event
    can launch. Cancellation while the create call is in flight keeps the claim
    and does not start a replacement.
    """
    if accepted:
        return True
    return not create_settled


def _cmd_review_claim(args: argparse.Namespace) -> int:
    event = json.loads(Path(args.event).read_text(encoding="utf-8"))
    state = _load_json(args.state) or {}
    decision = review_launch_decision(
        event,
        args.event_name,
        reviews=state.get("reviews") or [],
        comments=state.get("comments") or [],
        trusted_login=args.trusted_login or "",
    )
    Path(args.out).write_text(json.dumps(decision) + "\n", encoding="utf-8")
    return 0


def _cmd_claim_release(args: argparse.Namespace) -> int:
    accepted = args.accepted == "true"
    settled = args.settled == "true"
    print("keep" if claim_survives_cancel(accepted=accepted, create_settled=settled) else "delete")
    return 0


def _cmd_create_outcome(args: argparse.Namespace) -> int:
    print(create_outcome(args.http_code))
    return 0


def _cmd_self_check(_args: argparse.Namespace) -> int:
    _self_check()
    print("ok")
    return 0


def _self_check() -> None:
    head = "a" * 40
    other = "b" * 40
    review_id = 5449353687
    review = {
        "id": review_id,
        "commit_id": head,
        "state": "COMMENTED",
        "user": {"login": "chatgpt-codex-connector[bot]"},
    }
    review_event = {"action": "submitted", "review": review}
    comment_event = {
        "action": "created",
        "comment": {
            "pull_request_review_id": review_id,
            "commit_id": head.upper(),
            "user": {"login": "chatgpt-codex-connector[bot]"},
        },
    }
    summary_event = {
        "action": "created",
        "comment": {
            "user": {"login": "chatgpt-codex-connector[bot]"},
            "body": (
                "<!-- codex-pull-request-review-summary -->\n"
                "| Review | Status | Commit |\n"
                "| --- | --- | --- |\n"
                "| Code Review | ✅ **Completed** | `aaaaaaaa` |\n"
            ),
        },
    }
    reviews = [review]
    identities = [
        review_launch_identity(review_event, "pull_request_review", reviews),
        review_launch_identity(comment_event, "pull_request_review_comment", reviews),
        review_launch_identity(summary_event, "issue_comment", reviews),
    ]
    if any(item is None for item in identities) or len(set(identities)) != 1:
        raise SystemExit(f"review identity diverged: {identities}")
    marker = review_claim_marker(review_id, head)
    trusted = "pattalkslaw-del"
    comments = [{"user": {"login": trusted}, "body": "claimed\n\n" + marker}]
    if not review_claim_owned(comments, str(review_id), head, trusted):
        raise SystemExit("trusted claim was not honored")
    if review_claim_owned(comments, str(review_id), other, trusted):
        raise SystemExit("claim matched a different head")
    forged = [{"user": {"login": "someone-else"}, "body": marker}]
    if review_claim_owned(forged, str(review_id), head, trusted):
        raise SystemExit("untrusted claim was honored")
    if review_claim_owned(comments, str(review_id), head, ""):
        raise SystemExit("empty trusted login honored a claim")
    owned = review_launch_decision(
        comment_event,
        "pull_request_review_comment",
        reviews=reviews,
        comments=comments,
        trusted_login=trusted,
    )
    if not owned["owned"] or owned["marker"] != marker:
        raise SystemExit(f"inline comment did not see the review claim: {owned}")
    free = review_launch_decision(
        summary_event,
        "issue_comment",
        reviews=reviews,
        comments=[],
        trusted_login=trusted,
    )
    if free["owned"] or free["status"] != "free" or free["marker"] != marker:
        raise SystemExit(f"summary was not a free launch of the same review: {free}")
    if review_launch_identity(summary_event, "issue_comment", []) is not None:
        raise SystemExit("summary bound without a review list")
    if not claim_survives_cancel(accepted=True, create_settled=True):
        raise SystemExit("accepted worker lost its claim")
    if not claim_survives_cancel(accepted=False, create_settled=False):
        raise SystemExit("unsettled create lost its claim")
    if claim_survives_cancel(accepted=False, create_settled=True):
        raise SystemExit("settled rejection kept its claim")
    outcomes = {
        "200": "accept",
        "201": "accept",
        "400": "reject",
        "401": "reject",
        "409": "reject",
        "422": "reject",
        "429": "reject",
        " 404 ": "reject",
        "500": "ambiguous",
        "502": "ambiguous",
        "503": "ambiguous",
        "302": "ambiguous",
        "000": "ambiguous",
        "": "ambiguous",
        "99": "ambiguous",
        "2000": "ambiguous",
    }
    for code, want in outcomes.items():
        got = create_outcome(code)
        if got != want:
            raise SystemExit(f"create outcome {code!r}: {got} != {want}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    build = sub.add_parser("build")
    build.add_argument("--event", required=True)
    build.add_argument("--event-name", required=True)
    build.add_argument("--open-prs")
    build.add_argument("--out", required=True)
    build.add_argument("--repo-url", default=DEFAULT_REPO_URL)
    build.add_argument("--base-ref", default=DEFAULT_BASE_REF)
    build.set_defaults(func=_cmd_build)

    reviewed = sub.add_parser("head-already-reviewed")
    reviewed.add_argument("--head", required=True)
    reviewed.add_argument("--state", required=True)
    reviewed.set_defaults(func=_cmd_head_already_reviewed)

    sync = sub.add_parser("apply-sync")
    sync.add_argument("--issue-number", required=True, type=int)
    sync.add_argument("--title", required=True)
    sync.add_argument("--base-ref", default=DEFAULT_BASE_REF)
    sync.add_argument("--existing")
    sync.add_argument("--pr-number", type=int)
    sync.add_argument("--ahead", action=argparse.BooleanOptionalAction, default=True)
    sync.add_argument("--head-changed", action="store_true")
    sync.add_argument("--head-accepted", action="store_true")
    sync.set_defaults(func=_cmd_apply_sync)

    complete = sub.add_parser("complete")
    complete.add_argument("--event", required=True)
    complete.add_argument("--event-name", required=True)
    complete.add_argument("--dry-run", action="store_true")
    complete.set_defaults(func=_cmd_complete)

    rereview = sub.add_parser("codex-rereview")
    rereview.add_argument("--status", required=True)
    rereview.add_argument("--before", required=True)
    rereview.add_argument("--after", required=True)
    rereview.add_argument("--reviews")
    rereview.set_defaults(func=_cmd_codex_rereview)

    claim = sub.add_parser("review-claim")
    claim.add_argument("--event", required=True)
    claim.add_argument("--event-name", required=True)
    claim.add_argument("--state", required=True)
    claim.add_argument("--trusted-login", default="")
    claim.add_argument("--out", required=True)
    claim.set_defaults(func=_cmd_review_claim)

    release = sub.add_parser("claim-release")
    release.add_argument("--accepted", required=True, choices=("true", "false"))
    release.add_argument("--settled", required=True, choices=("true", "false"))
    release.set_defaults(func=_cmd_claim_release)

    outcome = sub.add_parser("create-outcome")
    outcome.add_argument("--http-code", required=True)
    outcome.set_defaults(func=_cmd_create_outcome)

    check = sub.add_parser("self-check")
    check.set_defaults(func=_cmd_self_check)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
