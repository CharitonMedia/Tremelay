#!/usr/bin/env python3
"""Serialized initial-goal reservation, single create, and GET-only recovery."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sys
import uuid

from automation_protocol import is_checkpoint_evidence
from checkpoint_supervisor import REPO, AUTHOR, Stop, cursor, gh
from goal_lineage import bounded_pages, LineageStop
from goal_review_launch import LEGACY_AGENT, RUN_ID, TERMINAL, load_json

MARKER = '<!-- goal-initial-v1 '
PREFIX = '<!-- goal-initial'
LEGACY_PREFIX = 'A cloud agent is implementing this issue: '
LEGACY_SUFFIX = ('. The workflow opens the pull request, with the Goal-Issue line and the goal label, '
                 'after the branch has commits. The agent does not open one.')
BASE = {'repo', 'issue', 'agent_id', 'phase', 'legacy'}
PHASE_FIELDS = {'prepared': set(), 'released': set(), 'dispatch_reserved': set(),
                'working': {'run_id'}, 'terminal': {'run_id', 'status'}}
ADMISSION = 'serialized-v1'


def require_admission():
    if os.environ.get('TREMELAY_WORKER_ADMISSION') != ADMISSION:
        raise Stop('Initial worker mutation requires serialized repository admission')


def pages(path):
    try:
        return bounded_pages(path, read=gh)
    except LineageStop as error:
        raise Stop(str(error)) from None


def agent_identity(issue):
    if type(issue) is not int or issue <= 0:
        raise Stop('Invalid initial goal issue')
    return 'bc-' + str(uuid.uuid5(uuid.NAMESPACE_URL, f'initial-goal:{REPO}|issue:{issue}'))


def validate_state(state):
    if not isinstance(state, dict) or not isinstance(state.get('phase'), str):
        raise Stop('Invalid initial worker state')
    fields = PHASE_FIELDS.get(state['phase'])
    if fields is None or set(state) != BASE | fields or state.get('repo') != REPO or type(state.get('legacy')) is not bool:
        raise Stop('Invalid initial worker state fields')
    expected = agent_identity(state['issue'])
    if (not isinstance(state.get('agent_id'), str) or not LEGACY_AGENT.fullmatch(state['agent_id'])
            or (not state['legacy'] and state['agent_id'] != expected)
            or (state['legacy'] and state['phase'] not in {'working', 'terminal'})):
        raise Stop('Initial worker identity does not match its issue')
    if 'run_id' in fields and (not isinstance(state['run_id'], str) or not RUN_ID.fullmatch(state['run_id'])):
        raise Stop('Invalid initial worker run identity')
    if 'status' in fields and (not isinstance(state['status'], str) or state['status'] not in TERMINAL):
        raise Stop('Invalid initial worker terminal status')
    return state


def state_body(state):
    validate_state(state)
    text = ('Initial goal worker reservation. Repository ownership remains held until the existing run is verified terminal.'
            if state['phase'] not in {'released', 'terminal'} else
            'Initial goal worker is verified terminal; its implementation attempt remains recorded.'
            if state['phase'] == 'terminal' else
            'Initial goal reservation released before any worker create was attempted.')
    return text + '\n\n' + MARKER + json.dumps(state, sort_keys=True, separators=(',', ':')) + ' -->'


def parse_body(body, issue):
    if not isinstance(body, str) or is_checkpoint_evidence(body):
        return None
    if PREFIX in body:
        line = body.rstrip('\r\n').splitlines()[-1]
        if body.count(PREFIX) != 1 or not line.startswith(MARKER) or not line.endswith(' -->'):
            raise Stop('Unknown or malformed initial worker envelope')
        state = validate_state(load_json(line[len(MARKER):-4]))
        if state['issue'] != issue or body.rstrip('\r\n') != state_body(state):
            raise Stop('Initial worker comment does not match its issue or state')
        return state
    if LEGACY_PREFIX.rstrip() in body:
        match = re.fullmatch(re.escape(LEGACY_PREFIX + 'https://cursor.com/agents/') +
                             '(' + LEGACY_AGENT.pattern + ')' + re.escape(LEGACY_SUFFIX), body.rstrip('\r\n'))
        if not match:
            raise Stop('Unknown initial accepted-worker receipt; explicit reconciliation required')
        return {'repo': REPO, 'issue': issue, 'agent_id': match[1], 'legacy': True, 'phase': 'legacy_accepted'}
    return None


def records(comments, issue):
    agent_identity(issue)
    if not isinstance(comments, list):
        raise Stop('Invalid initial ownership comments')
    found = []
    seen = set()
    for comment in comments:
        if not isinstance(comment, dict) or comment.get('user', {}).get('login') != AUTHOR:
            continue
        state = parse_body(comment.get('body'), issue)
        if state is None:
            continue
        if (type(comment.get('id')) is not int or comment['id'] <= 0
                or comment.get('issue_url') != f'https://api.github.com/repos/{REPO}/issues/{issue}'):
            raise Stop('Initial worker receipt is not bound to its source issue')
        if comment['id'] not in seen:
            found.append((comment, state))
            seen.add(comment['id'])
    return found


def pending_claim(comments, issue, *, ignore_comment_id=None):
    return any(comment['id'] != ignore_comment_id and state['phase'] not in {'terminal', 'released'}
               for comment, state in records(comments, issue))


def update(comment, state):
    body = state_body(state)
    if comment.get('body', '').rstrip('\r\n') != body:
        gh(f"repos/{REPO}/issues/comments/{comment['id']}", method='PATCH', data={'body': body})
        comment['body'] = body


def verify_target(agent, run, issue):
    repos = agent.get('repos')
    branch = f'goal/issue-{issue}'
    if (not isinstance(repos, list) or len(repos) != 1 or not isinstance(repos[0], dict)
            or repos[0].get('url') != f'https://github.com/{REPO}'
            or agent.get('workOnCurrentBranch') is not True):
        raise Stop('Initial worker repository or branch ownership is unverified')
    target = repos[0]
    if target.get('prUrl') is None and target.get('startingRef') not in {None, branch}:
        raise Stop('Initial worker targets another source branch')
    matched = target.get('startingRef') == branch and target.get('prUrl') is None
    if target.get('prUrl') is not None:
        match = re.fullmatch(re.escape(f'https://github.com/{REPO}/pull/') + r'([1-9][0-9]*)', target['prUrl']) if isinstance(target['prUrl'], str) else None
        if not match:
            raise Stop('Initial worker PR target is unverified')
        pull = gh(f'repos/{REPO}/pulls/{match[1]}')
        from goal_lineage import source_issue
        try:
            matched = source_issue(pull) == issue
        except LineageStop:
            matched = False
        if not matched:
            raise Stop('Initial worker PR belongs to another source issue')
    if 'git' in run:
        branches = run['git'].get('branches') if isinstance(run['git'], dict) else None
        if not isinstance(branches, list):
            raise Stop('Initial worker pushed-branch evidence is invalid')
        for item in branches:
            if (not isinstance(item, dict) or item.get('repoUrl') != f'github.com/{REPO}'
                    or (item.get('branch') is not None and item['branch'] != branch)):
                raise Stop('Initial worker pushed another repository or branch')
            matched = matched or item.get('branch') == branch
    if not matched:
        raise Stop('Initial worker source-branch association is unverified')


def recover(issue, comment_id):
    """Read the same current run; never create, review, relabel or publish."""
    require_admission()
    account = gh('user')
    if not isinstance(account, dict) or account.get('login') != AUTHOR:
        raise Stop('Initial recovery requires the approved owner identity')
    comment = gh(f'repos/{REPO}/issues/comments/{comment_id}')
    found = records([comment], issue)
    if len(found) != 1 or comment['id'] != comment_id:
        raise Stop('Initial worker receipt was not found')
    state = found[0][1]
    if state['phase'] in {'terminal', 'released'}:
        return state
    if state['phase'] == 'prepared':
        state = dict(state, phase='released')
        update(comment, state)
        return state
    agent = cursor('/' + state['agent_id'])
    run_id = agent.get('latestRunId') if isinstance(agent, dict) else None
    if (not isinstance(agent, dict) or agent.get('id') != state['agent_id']
            or not isinstance(run_id, str) or not RUN_ID.fullmatch(run_id)
            or ('run_id' in state and state['run_id'] != run_id)):
        raise Stop('Initial worker current run is unknown or changed')
    run = cursor(f"/{state['agent_id']}/runs/{run_id}")
    if (not isinstance(run, dict) or run.get('id') != run_id or run.get('agentId') != state['agent_id']
            or not isinstance(run.get('status'), str) or run['status'] not in TERMINAL | {'CREATING', 'RUNNING'}):
        raise Stop('Initial worker run status is unverified')
    verify_target(agent, run, issue)
    state = dict(state, phase='working', run_id=run_id)
    if run['status'] in TERMINAL:
        current = cursor('/' + state['agent_id'])
        if (not isinstance(current, dict) or current.get('id') != state['agent_id']
                or current.get('latestRunId') != run_id):
            raise Stop('Initial worker changed during terminal reconciliation')
        verify_target(current, run, issue)
        state.update(phase='terminal', status=run['status'])
    update(comment, state)
    return state


def launch(issue, payload):
    require_admission()
    account = gh('user')
    if not isinstance(account, dict) or account.get('login') != AUTHOR:
        raise Stop('Initial launch requires the approved owner identity')
    from goal_lineage import guard, source_issue
    try:
        guard(issue_number=issue, launch=True, repository_ownership=True, read=gh, pages=pages)
    except LineageStop as error:
        raise Stop(str(error)) from None
    prior = records(pages(f'repos/{REPO}/issues/{issue}/comments'), issue)
    if any(state['phase'] != 'released' for _, state in prior):
        raise Stop('Initial implementation already reserved or attempted; reconcile the existing worker')
    required = {'name', 'prompt', 'repos', 'workOnCurrentBranch', 'autoCreatePR', 'skipReviewerRequest'}
    repos = payload.get('repos') if isinstance(payload, dict) else None
    if (not isinstance(payload, dict) or set(payload) != required
            or not isinstance(repos, list) or len(repos) != 1 or not isinstance(repos[0], dict)
            or repos[0].get('url') != f'https://github.com/{REPO}'
            or payload.get('workOnCurrentBranch') is not True or payload.get('autoCreatePR') is not False
            or payload.get('skipReviewerRequest') is not True
            or not isinstance(payload.get('name'), str)
            or not isinstance(payload.get('prompt'), dict) or set(payload['prompt']) != {'text'}
            or not isinstance(payload['prompt']['text'], str) or not payload['prompt']['text'].strip()):
        raise Stop('Initial worker payload is not authorized')
    target = repos[0]
    if set(target) == {'url', 'startingRef'}:
        if target['startingRef'] != f'goal/issue-{issue}':
            raise Stop('Initial payload source branch mismatch')
    elif set(target) == {'url', 'prUrl'}:
        match = re.fullmatch(re.escape(f'https://github.com/{REPO}/pull/') + r'([1-9][0-9]*)', target['prUrl']) if isinstance(target['prUrl'], str) else None
        if not match or source_issue(gh(f'repos/{REPO}/pulls/{match[1]}')) != issue:
            raise Stop('Initial payload PR mismatch')
    else:
        raise Stop('Unexpected initial repository options')
    state = {'repo': REPO, 'issue': issue, 'agent_id': agent_identity(issue), 'phase': 'prepared', 'legacy': False}
    comment = gh(f'repos/{REPO}/issues/{issue}/comments', method='POST', data={'body': state_body(state)})
    if not isinstance(comment, dict) or records([comment], issue) != [(comment, state)]:
        raise Stop('Initial reservation was not confirmed; no create attempted')
    comment['body'] = state_body(state)
    try:
        guard(issue_number=issue, launch=True, repository_ownership=True, ignore_comment_id=comment['id'], read=gh, pages=pages)
        fresh = gh(f"repos/{REPO}/issues/comments/{comment['id']}")
        if not isinstance(fresh, dict) or records([fresh], issue) != [(fresh, state)] or fresh.get('id') != comment['id']:
            raise Stop('Initial reservation changed before dispatch')
    except (Stop, LineageStop):
        current = gh(f"repos/{REPO}/issues/comments/{comment['id']}")
        if not isinstance(current, dict) or records([current], issue) != [(current, state)] or current.get('id') != comment['id']:
            raise Stop('Initial preparation changed; explicit reconciliation required')
        update(comment, dict(state, phase='released'))
        raise
    state['phase'] = 'dispatch_reserved'
    update(comment, state)
    # No fallible admission reads remain after this durable reservation.
    # A dispatch reservation can never return to prepared or be replayed.
    response = cursor('', payload=dict(payload, agentId=state['agent_id']))
    if not isinstance(response, dict):
        raise Stop('Initial create response does not establish the reserved worker')
    agent, run = response.get('agent'), response.get('run')
    if (not isinstance(agent, dict) or agent.get('id') != state['agent_id'] or not isinstance(run, dict)
            or run.get('agentId') != state['agent_id'] or not isinstance(run.get('id'), str)
            or not RUN_ID.fullmatch(run['id'])):
        raise Stop('Initial create response does not establish the reserved worker')
    state.update(phase='working', run_id=run['id'])
    update(comment, state)
    return {'comment_id': comment['id'], 'state': state}


def recover_all():
    require_admission()
    failed = False
    for issue in pages(f'repos/{REPO}/issues?state=all'):
        if not isinstance(issue, dict) or type(issue.get('number')) is not int:
            raise Stop('Invalid source issue history')
        if issue.get('pull_request'):
            continue
        number = issue['number']
        try:
            found = records(pages(f'repos/{REPO}/issues/{number}/comments'), number)
        except (Stop, ValueError) as error:
            print(f'Issue #{number}: initial ownership retained: {error}', file=sys.stderr)
            failed = True
            continue
        for comment, state in found:
            if state['phase'] in {'terminal', 'released'}:
                continue
            try:
                recover(number, comment['id'])
            except Stop as error:
                print(f"Issue #{number}: initial receipt {comment['id']} retained: {error}", file=sys.stderr)
                failed = True
    return failed


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['launch', 'recover'])
    parser.add_argument('--issue', type=int, required=True)
    parser.add_argument('--comment', type=int)
    parser.add_argument('--payload')
    parser.add_argument('--out', required=True)
    args = parser.parse_args(argv)
    if args.action == 'launch':
        if not args.payload:
            raise Stop('Initial launch needs a payload file')
        result = launch(args.issue, load_json(Path(args.payload).read_text()))
    else:
        if type(args.comment) is not int or args.comment <= 0:
            raise Stop('Initial recovery needs an existing comment ID')
        result = {'comment_id': args.comment, 'state': recover(args.issue, args.comment)}
    Path(args.out).write_text(json.dumps(result) + '\n')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (Stop, LineageStop, OSError, ValueError) as error:
        print(str(error) if isinstance(error, (Stop, LineageStop)) else 'Initial worker operation failed', file=sys.stderr)
        sys.exit(1)
