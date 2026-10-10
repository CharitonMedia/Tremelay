#!/usr/bin/env python3
"""Read-only review filtering before and after shared worker admission.

Preflight is advisory. It never reserves ownership or authorizes a later write;
the admitted job repeats these reads and retains its existing runtime guards.
"""
from __future__ import annotations

import argparse
import copy
import json
import os
from pathlib import Path
import re
import time

import goal_agent_request as goal
import goal_lineage as lineage
from codex_cursor_remediation import _collect_findings
from checkpoint_supervisor import has_review_feedback

REPO = lineage.REPO
CODEX = {"codex", "chatgpt-codex-connector[bot]"}
SHA = re.compile(r"[0-9a-fA-F]{40}")
SUMMARY = "<!-- codex-pull-request-review-summary -->"


def number(value):
    return type(value) is int and value > 0


def codex(record):
    return isinstance(record, dict) and (record.get('user') or {}).get('login', '').casefold() in CODEX


def eligible(pull, mode, *, issue=False):
    if not isinstance(pull, dict) or not number(pull.get('number')) or pull.get('state') != 'open':
        return False
    labels = goal._label_names(pull)
    if 'human-review-required' in labels:
        return False
    if mode == 'goal':
        if (pull.get('user') or {}).get('login') != lineage.OWNER or not goal._is_goal_pr(pull):
            return False
    elif mode == 'generic':
        if 'goal' in labels or 'codex-cursor-loop' not in labels:
            return False
    else:
        return False
    if issue:
        return mode == 'goal' and bool(pull.get('pull_request'))
    head, base = pull.get('head') or {}, pull.get('base') or {}
    return (pull.get('draft') is False and isinstance(head.get('sha'), str)
            and SHA.fullmatch(head['sha']) is not None
            and (head.get('repo') or {}).get('full_name') == REPO
            and (base.get('repo') or {}).get('full_name') == REPO
            and (mode != 'goal' or base.get('ref') == 'main'))


def snapshot_candidate(event, event_name, mode):
    if not isinstance(event, dict) or (event.get('repository') or {}).get('full_name') != REPO:
        return False
    if event_name == 'issue_comment':
        comment = event.get('comment') or {}
        body = comment.get('body') or ''
        return (mode == 'goal' and event.get('action') in {'created', 'edited'}
                and (comment.get('user') or {}).get('login') == 'chatgpt-codex-connector[bot]'
                and number(comment.get('id')) and isinstance(body, str)
                and SUMMARY in body and '✅ **Completed**' in body
                and not goal.is_terminal_clean_review(body)
                and eligible(event.get('issue'), mode, issue=True))
    pull = event.get('pull_request') or {}
    if not eligible(pull, mode):
        return False
    if event_name == 'pull_request_review':
        record = event.get('review') or {}
        return (event.get('action') == 'submitted' and codex(record) and number(record.get('id'))
                and record.get('commit_id') == pull['head']['sha']
                and str(record.get('state', '')).casefold() in
                ({'commented', 'changes_requested', 'approved'} if mode == 'goal' else {'commented', 'changes_requested'}))
    if event_name == 'pull_request_review_comment':
        record = event.get('comment') or {}
        return (event.get('action') == 'created' and codex(record)
                and number(record.get('id')) and number(record.get('pull_request_review_id'))
                and isinstance(record.get('body'), str) and bool(record['body'].strip())
                and record.get('commit_id') == pull['head']['sha'])
    return False


def prepare_event(event, event_name, mode, *, read=lineage.gh_read,
                  pages=lineage.gh_pages, settle=False, sleep=time.sleep):
    """Return a freshly checked event, or None; injected services are GET-only."""
    if not snapshot_candidate(event, event_name, mode):
        return None
    event = copy.deepcopy(event)
    approval = event_name == 'pull_request_review' and goal._review_state(event['review']) == 'approved'
    if settle and not approval:
        sleep(20)
    pr = (event.get('pull_request') or event.get('issue'))['number']
    if event_name == 'issue_comment':
        previous = event['comment']
        current = read(f'repos/{REPO}/issues/comments/{previous["id"]}')
        if (not isinstance(current, dict) or current.get('id') != previous['id']
                or current.get('issue_url') != f'https://api.github.com/repos/{REPO}/issues/{pr}'):
            return None
        event['comment'] = current
        if not snapshot_candidate(event, event_name, mode):
            return None
    elif event_name == 'pull_request_review_comment':
        previous = event['comment']
        current = read(f'repos/{REPO}/pulls/comments/{previous["id"]}')
        if (not isinstance(current, dict) or not codex(current)
                or any(current.get(key) != previous.get(key) for key in ('id', 'pull_request_review_id', 'commit_id'))
                or current.get('pull_request_url') != f'https://api.github.com/repos/{REPO}/pulls/{pr}'
                or not isinstance(current.get('body'), str) or not current['body'].strip()):
            return None
        event['comment'] = current

    if event_name != 'issue_comment':
        review_id = (event.get('review') or {}).get('id') or event['comment']['pull_request_review_id']
        for attempt in range(60 if settle else 1):
            review = read(f'repos/{REPO}/pulls/{pr}/reviews/{review_id}')
            if not isinstance(review, dict) or review.get('id') != review_id or not codex(review):
                return None
            if goal._review_state(review) != 'pending':
                break
            if not settle or attempt == 59:
                return None
            sleep(5)
        if event_name == 'pull_request_review':
            # A formerly actionable event must not become a different completion
            # path merely because the live review changed while it was queued.
            if ((goal._review_state(review) == 'approved') != approval
                    or review.get('commit_id') != event['review'].get('commit_id')):
                return None
            # REST uses uppercase states; the existing webhook builder expects
            # lowercase and must keep approvals on its completion-only path.
            event['review'] = dict(review, state=goal._review_state(review))

    pull = read(f'repos/{REPO}/pulls/{pr}')
    if not eligible(pull, mode) or pull.get('number') != pr:
        return None
    reviews = pages(f'repos/{REPO}/pulls/{pr}/reviews')
    identity = goal.review_launch_identity(event, event_name, reviews)
    if identity is None or identity[1] != pull['head']['sha']:
        return None
    review_id, head = identity
    if event_name != 'issue_comment' and goal._identity_from_review(review) != identity:
        return None
    if mode == 'goal':
        # Same source/lineage checks again inside admission. Ownership remains
        # with the existing serialized claim/create and receipt-recovery guards.
        lineage.guard(pr_number=pr, head=head, read=read, pages=pages)
        newest = goal._newest_submitted_review(reviews, head)
        if (newest is None or goal._identity_from_review(newest) != identity
                or (goal._review_state(newest) == 'approved') != approval
                or (not approval and not goal.review_is_current(review_id, head, reviews))):
            return None
    else:
        if not goal.review_is_current(review_id, head, reviews):
            return None
    if not approval:
        comments = pages(f'repos/{REPO}/pulls/{pr}/reviews/{review_id}/comments')
        # Always reread the whole review after settling/queueing. A webhook's
        # single inline finding is not the complete dispatch snapshot.
        findings = _collect_findings(comments)
        if not (has_review_feedback(newest, findings) if mode == 'goal' else findings):
            return None
    event['pull_request'] = pull
    if event_name == 'issue_comment':
        event['issue'] = dict(pull, pull_request={'url': f'https://api.github.com/repos/{REPO}/pulls/{pr}'})
    return event


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=['goal', 'generic'], required=True)
    parser.add_argument('--event', required=True)
    parser.add_argument('--event-name', required=True)
    parser.add_argument('--out', required=True)
    parser.add_argument('--settle', action='store_true')
    args = parser.parse_args(argv)
    event = json.loads(Path(args.event).read_text())
    result = prepare_event(event, args.event_name, args.mode, settle=args.settle)
    if result is not None:
        Path(args.out).write_text(json.dumps(result) + '\n')
    with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
        output.write('allowed=' + ('true' if result is not None else 'false') + '\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
