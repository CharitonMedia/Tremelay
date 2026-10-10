"""Old worker reservations survive a controller upgrade until verified terminal."""
import copy
import os
import runpy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import automation_protocol as protocol
import checkpoint_supervisor as supervisor
import goal_agent_request as goal
import goal_review_launch as launch

REPO = launch.REPO
PR = 11
COMMENT = 100
HEAD = 'a' * 40
AFTER = 'b' * 40
REVIEW = '41'
AGENT = 'bc-7cce015b-2d8b-441e-892b-25f3b1d0cd77'
URL = 'https://cursor.com/agents/' + AGENT
CLAIM = goal.review_claim_marker(REVIEW, HEAD)
RESERVATION = goal.reservation_body(CLAIM)
OLD_RESERVATION = 'Cursor review launch claimed.\n\n' + CLAIM
ACCEPTED = goal.accepted_launch_body(URL, CLAIM)
URL_ONLY = 'A cloud agent is working through the review findings: ' + URL
STOP = f'<!-- tremelay-cycle-stop head:{HEAD} limit:3 -->'
PR_URL = f'https://github.com/{REPO}/pull/{PR}'
REPO_URL = f'https://github.com/{REPO}'


def comment(body=ACCEPTED):
    return {'id': COMMENT, 'user': {'login': goal.TRUSTED_AUTOMATION_LOGIN},
            'issue_url': f'https://api.github.com/repos/{REPO}/issues/{PR}', 'body': body}


def pending(items):
    return launch.pending_claim(items, REPO, PR, goal.TRUSTED_AUTOMATION_LOGIN)


class Server:
    """Fail unexpected calls; recovery gets no live service or model access."""
    def __init__(self, body=ACCEPTED, status='RUNNING'):
        self.comment = comment(body)
        self.agent = {'id': AGENT, 'latestRunId': 'run-1',
                      'repos': [{'url': REPO_URL, 'prUrl': PR_URL}], 'workOnCurrentBranch': True}
        self.run = {'id': 'run-1', 'agentId': AGENT, 'status': status}
        self.login = goal.TRUSTED_AUTOMATION_LOGIN
        self.reads = []
        self.writes = []
        self.cursor_calls = []
        self.recheck = None
        self.fail_patch = False
        self.apply_failed_patch = False

    def gh(self, path, *, method='GET', data=None, paginate=False):
        assert not paginate
        if method == 'GET':
            self.reads.append(path)
            if path == 'user':
                return {'login': self.login}
            if path == f'repos/{REPO}/issues/comments/{COMMENT}':
                return copy.deepcopy(self.comment)
        if method == 'PATCH' and path == f'repos/{REPO}/issues/comments/{COMMENT}':
            self.writes.append(copy.deepcopy(data))
            launch.parse_legacy_state(data['body'])
            if not self.fail_patch or self.apply_failed_patch:
                self.comment['body'] = data['body']
            if self.fail_patch:
                raise launch.Stop('Ambiguous PATCH')
            return None
        raise AssertionError((path, method, data))

    def cursor(self, path, **kwargs):
        assert kwargs == {}, kwargs  # No POST payload, including payload=None.
        self.cursor_calls.append(path)
        if path == '/' + AGENT:
            result = self.recheck if self.recheck is not None and self.cursor_calls.count(path) > 1 else self.agent
        elif path == '/' + AGENT + '/runs/run-1':
            result = self.run
        else:
            raise AssertionError(path)
        if isinstance(result, Exception):
            raise result
        return copy.deepcopy(result)

    def recover(self):
        with patch.object(launch, 'gh', side_effect=self.gh), \
                patch.object(launch, 'cursor', side_effect=self.cursor), \
                patch.object(supervisor, 'assess') as model:
            result = launch.recover(REPO, PR, COMMENT)
            model.assert_not_called()
            return result


class LegacyOwnershipTests(unittest.TestCase):
    def test_all_historical_forms_block_across_newer_heads_and_reviews(self):
        for body in [RESERVATION, OLD_RESERVATION, ACCEPTED, URL_ONLY]:
            for head, review in [(HEAD, 42), (AFTER, 42)]:
                with self.subTest(body=body, head=head, review=review):
                    item = comment(body)
                    self.assertTrue(pending([item]))
                    pull = {'number': PR, 'state': 'open', 'head': {'sha': head, 'repo': {'full_name': REPO}},
                            'labels': [{'name': 'goal'}]}
                    event = {'review': {'id': review, 'commit_id': head}}
                    decision = goal.review_launch_decision(event, 'pull_request_review', pull=pull,
                        comments=[item], trusted_login=goal.TRUSTED_AUTOMATION_LOGIN)
                    self.assertEqual(decision['status'], 'blocked')
                    self.assertEqual(goal.cycle_budget([item]), (1, 3))

    def test_legacy_claims_block_supervisor_entry_and_final_dispatch_guards(self):
        for body in [RESERVATION, OLD_RESERVATION, ACCEPTED, URL_ONLY]:
            item = comment(body)
            pull = {'number': PR, 'state': 'open', 'draft': False,
                    'user': {'login': supervisor.AUTHOR},
                    'head': {'sha': AFTER, 'repo': {'full_name': REPO}}, 'base': {'ref': 'main'},
                    'labels': [{'name': 'goal'}, {'name': 'human-review-required'}], 'body': 'Goal-Issue: #10'}
            with self.subTest(body=body), patch.object(supervisor, 'pages', return_value=[item]), \
                    patch.object(supervisor, 'assess') as model, patch.object(supervisor, 'cursor') as worker, \
                    patch.object(supervisor, 'gh', return_value=pull), patch.object(supervisor, 'wait_for_goal_idle'):
                supervisor.run_one(pull, 3)
                for activity in [False, True]:
                    with self.assertRaisesRegex(supervisor.Stop, 'ordinary review worker'):
                        supervisor.refresh_guard(PR, AFTER, 42, check_activity=activity)
                model.assert_not_called()
                worker.assert_not_called()

    def test_outsiders_and_metadata_free_nonclaims_are_inert(self):
        outsider = comment(ACCEPTED)
        outsider['user']['login'] = 'outsider'
        for body in ['', None, 'Waiting for independent review.', goal.released_body(),
                     'See this worker: ' + URL, 'Historical review findings discussed above.']:
            self.assertFalse(pending([outsider, comment(body)]))

    def test_old_checkpoint_evidence_never_becomes_worker_ownership(self):
        for header in ['Automation stopped after 3 counted attempts in this segment (limit 3).',
                       'Automation stopped after 3 counted attempts (limit 3).']:
            for payload in [RESERVATION, ACCEPTED, URL_ONLY, '<!-- goal-review-claim bad -->',
                            '<!-- goal-review-launch-v1 not-json -->', '<!-- goal-review-legacy-v1 [] -->']:
                body = (header + '\nA documented independent supervisor assessment is required before more implementation.'
                        + f'\nLatest head: `{HEAD}`.\n\nPrevious attempt:\n' + payload
                        + '\n<!-- tremelay-cycle-stop broken -->\n\n' + STOP)
                with self.subTest(header=header, payload=payload):
                    self.assertFalse(pending([comment(body)]))
                    server = Server(body)
                    with self.assertRaisesRegex(launch.Stop, 'evidence'):
                        server.recover()
                    self.assertEqual(server.cursor_calls, [])
                    self.assertEqual(server.writes, [])

    def test_mutated_checkpoint_history_is_a_controlled_failure_not_free_ownership(self):
        header = ('Automation stopped after 3 counted attempts in this segment (limit 3).\n'
                  'A documented independent supervisor assessment is required before more implementation.\n'
                  f'Latest head: `{HEAD}`.\n\n')
        terminal = {'repo': REPO, 'pr': PR, 'comment_id': COMMENT, 'agent_id': AGENT,
                    'run_id': 'run-1', 'status': 'FINISHED', 'phase': 'terminal'}
        payloads = [RESERVATION, ACCEPTED, URL_ONLY, goal.HUMAN_RESUME_MARKER,
                    '<!-- goal-review-launch-v1 broken -->', launch.legacy_state_body(terminal),
                    supervisor.state_body({'head': HEAD, 'review': 41, 'phase': 'working'}, '')]
        for payload in payloads:
            for tail in ['', '\n' + STOP.replace(HEAD, AFTER), '\n' + STOP + '\ntrailing state']:
                body = header + payload + tail
                with self.subTest(payload=payload, tail=tail):
                    with self.assertRaises(protocol.AmbiguousCheckpoint):
                        protocol.is_checkpoint_evidence(body)
                    with self.assertRaises(launch.Stop):
                        pending([comment(body)])
                    server = Server(body)
                    with self.assertRaises(launch.Stop):
                        server.recover()
                    self.assertEqual(server.cursor_calls, [])
                    self.assertEqual(server.writes, [])

    def test_script_namespace_translates_ambiguous_history_and_continues_later_prs(self):
        body = ('Automation stopped after 3 counted attempts in this segment (limit 3).\n'
                'A documented independent supervisor assessment is required before more implementation.\n'
                f'Latest head: `{HEAD}`.\n\n' + ACCEPTED)
        script = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'scripts/checkpoint_supervisor.py'),
                                run_name='legacy_supervisor_script_under_test')
        with self.assertRaises(script['Stop']):
            script['ordinary_worker_pending'](PR, [comment(body)])
        seen = []
        def pull(number):
            return {'number': number, 'state': 'open', 'draft': False,
                    'user': {'login': supervisor.AUTHOR},
                    'head': {'sha': AFTER, 'repo': {'full_name': REPO}}, 'base': {'ref': 'main'},
                    'labels': [{'name': 'goal'}, {'name': 'human-review-required'}], 'body': 'Goal-Issue: #10'}
        def pages(path):
            seen.append(path)
            if path.endswith('/pulls?state=all'):
                return [pull(PR), pull(13)]
            if f'/issues/{PR}/comments' in path:
                return [comment(body)]
            return []
        def gh(path):
            self.assertEqual(path, 'user')
            return {'login': supervisor.AUTHOR}
        def forbidden(*args, **kwargs):
            self.fail('No model or worker calls are authorized by ambiguous historical evidence')
        env = {'GITHUB_REPOSITORY': REPO, 'GITHUB_REF': 'refs/heads/main', 'GITHUB_WORKFLOW_REF': REPO + '/.github/workflows/checkpoint-supervisor.yml@refs/heads/main', 'GH_TOKEN': 'test-owner',
               'CURSOR_API_KEY': 'test-cursor', 'SUPERVISOR_MAX_CHECKPOINTS': '3',
               'TREMELAY_SUPERVISOR_ACTIVATION': script['ACTIVATION_VALUE']}
        namespace = script['main'].__globals__
        with patch.dict(os.environ, env), patch.object(sys, 'argv', ['checkpoint_supervisor.py']), \
                patch.dict(namespace, {'pages': pages, 'gh': gh, 'assess': forbidden, 'cursor': forbidden}):
            self.assertEqual(script['main'](), 1)
        self.assertTrue(any('/issues/13/comments' in path for path in seen))

    def test_owner_claims_with_missing_or_cross_pr_headers_fail_closed(self):
        for change in [{'id': None}, {'id': True}, {'id': 0}, {'issue_url': None},
                       {'issue_url': f'https://api.github.com/repos/{REPO}/issues/12'},
                       {'issue_url': 'https://api.github.com/repos/other/repo/issues/11'}]:
            for body in [RESERVATION, ACCEPTED, URL_ONLY]:
                with self.subTest(change=change, body=body), self.assertRaises(launch.Stop):
                    pending([dict(comment(body), **change)])

    def test_malformed_or_ambiguous_legacy_claims_fail_closed(self):
        malformed = [RESERVATION + 'tail', 'quote: ' + ACCEPTED, ACCEPTED + CLAIM,
                     '\n' + URL_ONLY, 'Quoted: ' + URL_ONLY,
                     CLAIM, OLD_RESERVATION.replace(REVIEW, '0'), OLD_RESERVATION.replace(HEAD, 'bad'),
                     ACCEPTED.replace(AGENT, 'bc-unknown'), ACCEPTED.replace(AGENT, '../other'),
                     ACCEPTED.replace(URL, URL + '?target=12'), ACCEPTED.replace(URL, URL + '/'),
                     ACCEPTED.replace(URL, 'https://cursor.com.evil.test/agents/' + AGENT),
                     ACCEPTED.replace(URL, 'http://cursor.com/agents/' + AGENT),
                     ACCEPTED.replace(URL, 'https://cursor.com/agents/' + AGENT.upper()),
                     RESERVATION + '\n' + goal.HUMAN_RESUME_MARKER,
                     '<!-- goal-review-launch v2 -->', '<!-- goal-review-legacy broken -->']
        for body in malformed:
            with self.subTest(body=body):
                with self.assertRaises(launch.Stop):
                    pending([comment(RESERVATION), comment(body)])
                server = Server(body)
                with self.assertRaises(launch.Stop):
                    server.recover()
                self.assertEqual(server.cursor_calls, [])
                self.assertEqual(server.writes, [])


class LegacyRecoveryTests(unittest.TestCase):
    def test_reservations_never_become_prepared_or_release_without_identity(self):
        for body in [RESERVATION, OLD_RESERVATION]:
            server = Server(body)
            for _ in range(2):
                with self.assertRaisesRegex(launch.Stop, 'manual reconciliation required'):
                    server.recover()
                self.assertTrue(pending([server.comment]))
                self.assertEqual(server.comment['body'], body)
            self.assertEqual(server.cursor_calls, [])
            self.assertEqual(server.writes, [])
            self.assertEqual(goal.cycle_budget([server.comment]), (1, 3))

    def test_owner_and_pr_binding_are_verified_before_cursor_lookup(self):
        for field, value in [('login', 'outsider'), ('user', {'login': 'outsider'}), ('id', 101),
                             ('issue_url', f'https://api.github.com/repos/{REPO}/issues/12'),
                             ('issue_url', f'https://api.github.com/repos/other/repo/issues/{PR}')]:
            server = Server()
            if field == 'login':
                server.login = value
            else:
                server.comment[field] = value
            with self.subTest(field=field), self.assertRaises(launch.Stop):
                server.recover()
            self.assertEqual(server.cursor_calls, [])
            self.assertEqual(server.writes, [])

    def test_creating_and_running_keep_fixed_random_identity_and_one_cycle(self):
        for body in [ACCEPTED, URL_ONLY]:
            for status in ['CREATING', 'RUNNING']:
                with self.subTest(body=body, status=status):
                    server = Server(body, status)
                    saved = server.recover()
                    self.assertEqual(saved['phase'], 'working')
                    self.assertEqual(saved['status'], status)
                    self.assertEqual(saved['agent_id'], AGENT)
                    self.assertNotEqual(saved['agent_id'], launch.agent_identity(REPO, PR, REVIEW, HEAD))
                    self.assertEqual(saved['run_id'], 'run-1')
                    self.assertEqual('review' in saved, body == ACCEPTED)
                    if body == ACCEPTED:
                        self.assertEqual((saved['review'], saved['head']), (REVIEW, HEAD))
                    self.assertTrue(pending([server.comment]))
                    self.assertEqual(server.recover(), saved)
                    self.assertEqual(len(server.writes), 1)
                    self.assertEqual(goal.cycle_budget([server.comment]), (1, 3))
                    self.assertNotIn(launch.MARKER, server.comment['body'])
                    self.assertNotIn(goal.HUMAN_RESUME_MARKER, server.comment['body'])
                    with self.assertRaises(launch.Stop):
                        launch.validate_state(saved)
                    with self.assertRaises(launch.Stop):
                        launch.transition(saved, 'dispatch_reserved')

    def test_terminal_statuses_are_persisted_once_without_post_or_review(self):
        for body in [ACCEPTED, URL_ONLY]:
            for status in launch.TERMINAL:
                with self.subTest(body=body, status=status):
                    server = Server(body, status)
                    saved = server.recover()
                    self.assertEqual((saved['phase'], saved['status']), ('terminal', status))
                    self.assertFalse(pending([server.comment]))
                    self.assertEqual(goal.cycle_budget([server.comment]), (1, 3))
                    self.assertEqual(server.cursor_calls, ['/' + AGENT, '/' + AGENT + '/runs/run-1', '/' + AGENT])
                    calls = list(server.cursor_calls)
                    self.assertEqual(server.recover(), saved)
                    self.assertEqual(server.cursor_calls, calls)
                    self.assertEqual(len(server.writes), 1)
                    self.assertTrue(all(path in {'user', f'repos/{REPO}/issues/comments/{COMMENT}'} for path in server.reads))
                    self.assertNotIn('@codex', server.comment['body'])

    def test_working_to_terminal_retains_original_review_and_consumed_cycle(self):
        server = Server()
        server.recover()
        server.run['status'] = 'FINISHED'
        saved = server.recover()
        self.assertEqual(saved['phase'], 'terminal')
        self.assertEqual(saved['review'], REVIEW)
        self.assertIn(CLAIM, server.comment['body'])
        self.assertEqual(len(server.writes), 2)
        self.assertFalse(pending([server.comment]))
        self.assertEqual(goal.cycle_budget([server.comment]), (1, 3))

    def test_missing_or_uncertain_agent_does_not_release_or_invent_identity(self):
        for agent in [None, {}, launch.Stop('404'), launch.Stop('503'), {'id': 'bc-other'},
                      {'id': AGENT}, {'id': AGENT, 'latestRunId': '../escape'},
                      {'id': AGENT, 'latestRunId': 'run\nheader'}]:
            server = Server()
            server.agent = agent
            with self.subTest(agent=agent), self.assertRaises(launch.Stop):
                server.recover()
            self.assertEqual(server.comment['body'], ACCEPTED)
            self.assertTrue(pending([server.comment]))
            self.assertEqual(server.writes, [])
            self.assertEqual(len(server.cursor_calls), 1)

    def test_absent_mismatched_or_unknown_run_remains_pending(self):
        variants = [None, {}, launch.Stop('404'), launch.Stop('503'),
                    dict(Server().run, id='other'), dict(Server().run, agentId='bc-other')]
        variants += [dict(Server().run, status=status) for status in [None, [], {}, 'UNKNOWN', 'FINISHED\n', 'IDLE']]
        for run in variants:
            server = Server()
            server.run = run
            with self.subTest(run=run), self.assertRaises(launch.Stop):
                server.recover()
            self.assertEqual(server.comment['body'], ACCEPTED)
            self.assertTrue(pending([server.comment]))
            self.assertEqual(server.writes, [])
            self.assertEqual(len(server.cursor_calls), 2)

    def test_pr_association_can_come_from_verified_run_branch(self):
        for status in ['RUNNING', 'FINISHED']:
            server = Server(status=status)
            del server.agent['repos'][0]['prUrl']
            server.run['git'] = {'branches': [{'repoUrl': f'github.com/{REPO}', 'prUrl': PR_URL}]}
            self.assertEqual(server.recover()['status'], status)
            self.assertEqual(goal.cycle_budget([server.comment]), (1, 3))

    def test_agent_repository_pr_and_branch_options_must_match(self):
        mutations = [lambda agent: agent.pop('repos'), lambda agent: agent.update(repos=[]),
                     lambda agent: agent['repos'].append(copy.deepcopy(agent['repos'][0])),
                     lambda agent: agent['repos'][0].update(url='https://github.com/other/repo'),
                     lambda agent: agent['repos'][0].update(prUrl=f'https://github.com/{REPO}/pull/12'),
                     lambda agent: agent['repos'][0].update(prUrl=PR_URL + '?other=12'),
                     lambda agent: agent['repos'][0].update(prUrl=PR_URL + '/'),
                     lambda agent: agent.pop('workOnCurrentBranch'),
                     lambda agent: agent.update(workOnCurrentBranch=False),
                     lambda agent: agent.update(workOnCurrentBranch=1),
                     lambda agent: agent['repos'][0].pop('prUrl')]
        for mutation in mutations:
            server = Server(status='FINISHED')
            mutation(server.agent)
            with self.subTest(agent=server.agent), self.assertRaises(launch.Stop):
                server.recover()
            self.assertTrue(pending([server.comment]))
            self.assertEqual(server.writes, [])

    def test_invalid_or_conflicting_branch_evidence_cannot_override_agent(self):
        for branches in [None, {}, [None], [], [{'repoUrl': 'github.com/other/repo', 'prUrl': PR_URL}],
                         [{'repoUrl': f'github.com/{REPO}', 'prUrl': f'https://github.com/{REPO}/pull/12'}],
                         [{'repoUrl': f'github.com/{REPO}', 'prUrl': PR_URL + '#discussion'}],
                         [{'prUrl': PR_URL}], [{'repoUrl': f'github.com/{REPO}'}]]:
            for direct in [False, True]:
                if direct and branches in ([], [{'repoUrl': f'github.com/{REPO}'}]):
                    continue  # Direct PR evidence does not require a pushed branch.
                server = Server(status='FINISHED')
                if not direct:
                    del server.agent['repos'][0]['prUrl']
                server.run['git'] = {'branches': branches}
                with self.subTest(branches=branches, direct=direct), self.assertRaises(launch.Stop):
                    server.recover()
                self.assertTrue(pending([server.comment]))
                self.assertEqual(server.writes, [])

    def test_a_newer_run_never_releases_the_persisted_worker(self):
        server = Server()
        server.recover()
        before = server.comment['body']
        server.agent['latestRunId'] = 'run-2'
        server.run['status'] = 'FINISHED'
        with self.assertRaisesRegex(launch.Stop, 'same legacy run'):
            server.recover()
        self.assertEqual(server.comment['body'], before)
        self.assertEqual(len(server.writes), 1)
        self.assertTrue(pending([server.comment]))

    def test_agent_changes_during_terminal_lookup_fail_closed(self):
        for change in [{'id': 'bc-other'}, {'latestRunId': 'run-2'}, {'repos': []},
                       {'workOnCurrentBranch': False}]:
            server = Server(status='FINISHED')
            server.recheck = dict(server.agent, **change)
            with self.subTest(change=change), self.assertRaises(launch.Stop):
                server.recover()
            self.assertTrue(pending([server.comment]))
            self.assertEqual(server.writes, [])

    def test_failed_terminal_write_is_reconciled_without_post_or_lost_cycle(self):
        for applied in [False, True]:
            server = Server(status='FINISHED')
            server.fail_patch = True
            server.apply_failed_patch = applied
            with self.assertRaises(launch.Stop):
                server.recover()
            self.assertEqual(pending([server.comment]), not applied)
            self.assertEqual(goal.cycle_budget([server.comment]), (1, 3))
            server.fail_patch = False
            calls = len(server.cursor_calls)
            self.assertEqual(server.recover()['phase'], 'terminal')
            self.assertEqual(len(server.cursor_calls), calls + (0 if applied else 3))
            self.assertEqual(len(server.writes), 1 if applied else 2)

    def test_resolution_envelope_is_canonical_and_bound_to_original_comment(self):
        server = Server(status='FINISHED')
        saved = server.recover()
        body = server.comment['body']
        variants = [body + 'tail', body + body, body.replace('"pr":11', '"pr":11,"pr":11'),
                    body.replace('"phase":"terminal"', '"phase":"working"'),
                    body.replace('"phase":"terminal"', '"phase":null'),
                    body.replace('"phase":"terminal"', '"phase":[]'),
                    body.replace('"phase":"terminal"', '"phase":"prepared"'),
                    body.replace('"status":"FINISHED"', '"status":"RUNNING"'),
                    body.replace('"status":"FINISHED"', '"status":null'),
                    body.replace('"status":"FINISHED"', '"status":{}'),
                    body.replace('"comment_id":100', '"comment_id":true'),
                    body.replace('"run_id":"run-1"', '"run_id":"../run"'),
                    body.replace('"review":"41"', '"review":"041"'),
                    body.replace('"pr":11', '"pr":11,"extra":true'),
                    body.replace(CLAIM, goal.HUMAN_RESUME_MARKER),
                    body.replace(URL, URL + '?x=1')]
        for bad in variants:
            with self.subTest(bad=bad), self.assertRaises(launch.Stop):
                pending([comment(bad)])
        for update in [{'repo': 'other/repo'}, {'pr': 12}, {'comment_id': 101}]:
            # Another target's self-consistent record is still not this claim.
            if 'repo' in update:
                with self.assertRaises(launch.Stop):
                    launch.legacy_state_body(dict(saved, **update))
                continue
            bad = launch.legacy_state_body(dict(saved, **update))
            with self.assertRaises(launch.Stop):
                pending([comment(bad)])
            other = Server(bad)
            with self.assertRaises(launch.Stop):
                other.recover()
            self.assertEqual(other.cursor_calls, [])
            self.assertEqual(other.writes, [])
        self.assertEqual(launch.parse_legacy_state(body.rstrip('\n')), saved)

    def test_existing_manual_recover_command_uses_same_bound_comment(self):
        server = Server(status='FINISHED')
        with patch.object(launch, 'gh', side_effect=server.gh), \
                patch.object(launch, 'cursor', side_effect=server.cursor):
            self.assertEqual(launch.main(['recover', '--repository', REPO, '--pr', str(PR),
                                          '--comment', str(COMMENT)]), 0)
        self.assertFalse(pending([server.comment]))
        self.assertEqual(goal.cycle_budget([server.comment]), (1, 3))


if __name__ == '__main__':
    unittest.main()
