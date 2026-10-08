#!/usr/bin/env python3
"""Build the durable three-cycle checkpoint evidence; never launch a worker."""
import argparse
import json
import os
from pathlib import Path

from checkpoint_supervisor import gh, pages, newest_review
from goal_agent_request import CYCLE_LIMIT, HUMAN_RESUME_MARKER, TRUSTED_AUTOMATION_LOGIN, comment_counts_cycle, flatten_pages


def stop_body(head, comments, review, findings, runs):
    start = 0
    for i, comment in enumerate(comments):
        if comment.get('user', {}).get('login') == TRUSTED_AUTOMATION_LOGIN and HUMAN_RESUME_MARKER in (comment.get('body') or ''):
            start = i + 1
    attempts = [c for c in comments[start:] if comment_counts_cycle(c.get('body') or '')]
    lines = [f'Automation stopped after {len(attempts)} counted attempts in this segment (limit {CYCLE_LIMIT}).',
             'A documented independent supervisor assessment is required before more implementation.',
             f'Latest head: `{head}`.', '', 'Counted attempts (claims do not prove accepted workers or progress):']
    for index, comment in enumerate(attempts, 1):
        lines.append(f"{index}. {comment.get('html_url') or 'Comment ' + str(comment.get('id'))} — {comment.get('created_at') or 'time unavailable'}")
        lines.append((comment.get('body') or '').replace(HUMAN_RESUME_MARKER, '')[:4000])
    lines += ['', 'Unresolved problem and current independent review findings:']
    if review:
        lines.append(f"Review {review['id']} of `{head}`: {review['state']}; {review.get('html_url') or 'URL unavailable'}")
        lines.append(review.get('body') or 'No review-level text.')
    else:
        lines.append('No actionable exact-head Codex review is available yet; wait for review before assessment.')
    for finding in findings:
        lines.append(f"{finding.get('path', '')}: {finding.get('html_url') or 'URL unavailable'}\n{finding.get('body') or ''}")
    lines += ['', 'CI / verification evidence for this exact head:']
    if not runs:
        lines.append('No exact-head workflow runs found yet.')
    for run in runs:
        lines.append(f"- {run['name']}: {run['status']} / {run.get('conclusion') or 'pending'} — {run.get('html_url') or run['id']}")
    lines += ['', f'<!-- tremelay-cycle-stop head:{head} limit:{CYCLE_LIMIT} -->']
    body = '\n'.join(lines)
    if len(body) > 60000:
        raise ValueError('Checkpoint evidence exceeds comment bound; do not omit findings')
    return body


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--head', required=True)
    parser.add_argument('--comments', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    repo, number = os.environ['GITHUB_REPOSITORY'], os.environ['PR_NUMBER']
    review = newest_review(pages(f'repos/{repo}/pulls/{number}/reviews'), args.head)
    findings = pages(f"repos/{repo}/pulls/{number}/reviews/{review['id']}/comments") if review else []
    runs = gh(f'repos/{repo}/actions/runs?head_sha={args.head}&per_page=100')['workflow_runs']
    comments = flatten_pages(json.loads(Path(args.comments).read_text()))
    Path(args.output).write_text(stop_body(args.head, comments, review, findings, runs))


if __name__ == '__main__':
    main()
