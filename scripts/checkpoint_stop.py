#!/usr/bin/env python3
"""Build the durable three-cycle checkpoint evidence; never launch a worker."""
import argparse
from html import escape
import json
import os
from pathlib import Path

from checkpoint_supervisor import gh, pages, newest_review
from goal_agent_request import CYCLE_COUNT_MARKERS, CYCLE_LIMIT, HUMAN_RESUME_MARKER, TRUSTED_AUTOMATION_LOGIN, comment_counts_cycle, flatten_pages


def evidence_text(text):
    """Keep quoted evidence readable without granting it comment authority."""
    text = escape(text, quote=False)
    # Cycle parsers also recognize plain prose. HTML escaping alone would leave
    # copied attempt descriptions looking like a new launch by the owner token.
    for marker in CYCLE_COUNT_MARKERS:
        text = text.replace(marker, f'&#{ord(marker[0])};' + marker[1:])
    return text


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
        lines.append((comment.get('body') or '')[:4000])
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
    # Everything above is evidence, including URLs, paths, IDs and CI metadata.
    # Escape it as one unit before appending our only trusted protocol marker.
    marker = f'<!-- tremelay-cycle-stop head:{evidence_text(head)} limit:{CYCLE_LIMIT} -->'
    body = evidence_text('\n'.join(lines)) + '\n\n' + marker
    if len(body) > 60000:
        # A durable checkpoint must exist even for oversized evidence. All full
        # material remains linked; this summary is not the model evidence input.
        review_url = (review or {}).get('html_url') or f'https://github.com/{os.environ.get("GITHUB_REPOSITORY", "CharitonMedia/Tremelay")}/pull/{os.environ.get("PR_NUMBER", "11")}/files'
        lines = [f'Automation stopped after {len(attempts)} counted attempts (limit {CYCLE_LIMIT}).',
                 'A documented independent supervisor assessment is required before more implementation.',
                 f'Latest head: `{head}`.', '', 'Counted attempts (claims do not prove accepted workers or progress):']
        for index, comment in enumerate(attempts[:CYCLE_LIMIT], 1):
            lines.append(f"{index}. {comment.get('html_url') or 'Comment ' + str(comment.get('id'))} — {(comment.get('body') or '')[:1000]}")
        lines += ['', f'Unresolved review: {review_url}', f'{len(findings)} inline findings; first 20 summarized below. Follow review links for complete evidence.']
        for finding in findings[:20]:
            lines.append(f"{finding.get('path', '')[:300]}: {(finding.get('body') or '')[:1000]} — {finding.get('html_url') or review_url}")
        lines += ['', f'CI: {len(runs)} exact-head runs; first 20 below. Full state is available in the PR checks.']
        for run in runs[:20]:
            lines.append(f"- {run['name'][:200]}: {run['status']} / {run.get('conclusion') or 'pending'} — {run.get('html_url') or run['id']}")
        body = evidence_text('\n'.join(lines))
        available = 60000 - len(marker) - 2
        if len(body) > available:
            notice = '\n\nEvidence excerpt truncated; follow the review and PR checks for complete evidence.'
            body = body[:available - len(notice)] + notice
        body += '\n\n' + marker
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
