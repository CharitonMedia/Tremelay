"""Retired supervisor receipts use exact-run status and independent PR lineage."""
import copy
import io
import sys
import unittest
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from unittest.mock import patch

from test_worker_target_diagnostic import fixture, AGENT, RUN, SECRET
from test_shared_worker_ownership import ENV
import checkpoint_supervisor as supervisor
import goal_initial_launch as initial


class Server:
    def __init__(self):
        self.state, self.agent, self.run, self.original, self.comment = fixture()
        self.agent['repos'][0].pop('prUrl')
        self.original.update(merged=True, html_url=f'https://github.com/{supervisor.REPO}/pull/22')
        self.enumerated = copy.deepcopy(self.original)
        self.alias = copy.deepcopy(self.original)
        self.alias.update(number=23, merged=False, merged_at=None, state='open',
                          html_url=f'https://github.com/{supervisor.REPO}/pull/23',
                          labels=[{'name': 'human-review-required'}])
        self.current = None
        self.events = []
        self.writes = []
        self.stderr = io.StringIO()
        self.agent_reads = 0

    def cursor(self, path, **kwargs):
        assert not kwargs, 'Recovery must never create a Cursor worker'
        self.events.append(('cursor', path))
        if path == '/' + AGENT:
            self.agent_reads += 1
            return copy.deepcopy(self.current if self.agent_reads > 1 and self.current is not None else self.agent)
        assert path == f'/{AGENT}/runs/{RUN}', path
        return copy.deepcopy(self.run)

    def github(self, path, *, method='GET', data=None, **kwargs):
        assert not kwargs
        self.events.append((method, path))
        if method == 'PATCH':
            assert path == f'repos/{supervisor.REPO}/issues/comments/100'
            self.comment['body'] = data['body']
            self.writes.append(copy.deepcopy(data))
            return None
        assert method == 'GET', 'Recovery must never create a review or change labels'
        if path == 'user':
            return {'login': supervisor.AUTHOR}
        if path == f'repos/{supervisor.REPO}/pulls/22':
            return copy.deepcopy(self.original)
        assert path == f'repos/{supervisor.REPO}/pulls/23', path
        return copy.deepcopy(self.alias)

    def pages(self, path):
        if path == f'repos/{supervisor.REPO}/pulls?state=all':
            return [copy.deepcopy(self.original), copy.deepcopy(self.alias)]
        if path == f'repos/{supervisor.REPO}/issues/22/comments':
            return [self.comment]
        assert path == f'repos/{supervisor.REPO}/issues/23/comments', path
        return []

    @contextmanager
    def mocked(self):
        with patch.object(supervisor, 'gh', side_effect=self.github), \
                patch.object(supervisor, 'cursor', side_effect=self.cursor), \
                patch.object(supervisor, 'pages', side_effect=self.pages), \
                patch.object(supervisor, 'assess') as assess, \
                patch.object(supervisor, 'finish_review') as review, \
                patch.object(supervisor, 'dispatch_ready') as dispatch, \
                patch.object(supervisor, 'run_one') as launch, \
                redirect_stderr(self.stderr), redirect_stdout(io.StringIO()):
            yield
            for action in [assess, review, dispatch, launch]:
                action.assert_not_called()

    def recover(self, *, reconcile_only=True):
        with self.mocked():
            supervisor.recover_worker(self.enumerated, self.comment, self.state, reconcile_only=reconcile_only)

    def scan(self):
        with self.mocked(), patch.object(initial, 'recover_all', return_value=False), \
                patch.dict(supervisor.os.environ, dict(ENV, TREMELAY_WORKER_ADMISSION='serialized-v1'), clear=True), \
                patch.object(sys, 'argv', ['supervisor']):
            return supervisor.main()


class RetiredWorkerLineage(unittest.TestCase):
    def assert_rejected(self, server, *, reconcile_only=True):
        state, comment = copy.deepcopy(server.state), copy.deepcopy(server.comment)
        with self.assertRaises(supervisor.Stop):
            server.recover(reconcile_only=reconcile_only)
        self.assertEqual(server.state, state)
        self.assertEqual(server.comment, comment)
        self.assertEqual(server.writes, [])
        self.assertTrue(supervisor.supervisor_owns_work(server.state))
        self.assertNotIn(SECRET, server.stderr.getvalue())

    def test_observed_missing_agent_fields_reconcile_only_exact_terminal_run(self):
        server = Server()
        server.recover()
        saved = supervisor.records([server.comment])[0][1]
        self.assertEqual(saved['phase'], 'terminal')
        self.assertEqual(saved['terminal_status'], 'FINISHED')
        self.assertEqual(saved['agent_id'], AGENT)
        self.assertEqual(saved['run_id'], RUN)
        self.assertFalse(supervisor.supervisor_owns_work(saved))
        self.assertEqual(server.events, [
            ('cursor', '/' + AGENT), ('cursor', f'/{AGENT}/runs/{RUN}'),
            ('GET', f'repos/{supervisor.REPO}/pulls/22'), ('GET', f'repos/{supervisor.REPO}/pulls/23'),
            ('cursor', '/' + AGENT), ('GET', f'repos/{supervisor.REPO}/pulls/22'),
            ('PATCH', f'repos/{supervisor.REPO}/issues/comments/100')])
        self.assertIn('agent-wide branch metadata does not prove a reviewed commit or output', server.comment['body'])
        self.assertEqual(server.stderr.getvalue(), '')

    def test_automatic_recovery_is_terminal_only_and_idempotent_with_alias_held(self):
        server = Server()
        alias_before = copy.deepcopy(server.alias)
        self.assertEqual(server.scan(), 0)
        self.assertEqual(len(server.writes), 1)
        self.assertEqual(server.alias, alias_before)
        server.events.clear()
        self.assertEqual(server.scan(), 0)
        self.assertEqual(server.events, [('GET', 'user')])
        self.assertEqual(len(server.writes), 1)

    def test_all_explicit_terminal_statuses_can_retire_ownership(self):
        for status in supervisor.WORKER_TERMINAL_STATUSES:
            with self.subTest(status=status):
                server = Server()
                server.run['status'] = status
                server.recover()
                self.assertEqual(server.state['phase'], 'terminal')
                self.assertEqual(server.state['terminal_status'], status)

    def test_missing_stored_run_never_uses_inferred_latest_run_for_alias(self):
        server = Server()
        server.state.pop('run_id')
        self.assert_rejected(server)
        self.assertEqual(server.agent_reads, 1)
        self.assertFalse(any(method == 'GET' for method, _ in server.events))

    def test_running_or_unknown_status_cannot_use_merged_lineage_as_terminal_proof(self):
        for status in ['CREATING', 'RUNNING', 'UNKNOWN', None, SECRET]:
            with self.subTest(status=status):
                server = Server()
                server.run['status'] = status
                self.assert_rejected(server)
                self.assertFalse(any(method == 'GET' for method, _ in server.events))

    def test_identity_or_latest_run_mismatch_before_and_after_lookup_remains_owned(self):
        for stage, field in [('agent', 'id'), ('agent', 'latestRunId'), ('run', 'id'), ('run', 'agentId'),
                             ('current', 'id'), ('current', 'latestRunId')]:
            with self.subTest(stage=stage, field=field):
                server = Server()
                server.current = copy.deepcopy(server.agent)
                getattr(server, stage)[field] = SECRET
                self.assert_rejected(server)

    def test_live_or_unmerged_original_never_uses_alias_even_in_status_only_mode(self):
        for change in [dict(state='open', merged=False, merged_at=None),
                       dict(state='closed', merged=False, merged_at=None),
                       dict(state='open', merged=True), dict(merged=None), dict(merged_at=None)]:
            with self.subTest(change=change):
                server = Server()
                server.original.update(change)
                self.assert_rejected(server)

    def test_completion_mode_keeps_original_strict_association(self):
        server = Server()
        self.assert_rejected(server, reconcile_only=False)
        self.assertFalse(any(method == 'GET' for method, _ in server.events))
        self.assertEqual(server.agent_reads, 1)

    def test_present_agent_fields_must_agree_with_proven_lineage(self):
        for pr in [22, 23]:
            with self.subTest(pr=pr):
                server = Server()
                server.agent['repos'][0].update(prUrl=f'https://github.com/{supervisor.REPO}/pull/{pr}',
                                                startingRef='goal/issue-21')
                server.recover()
                self.assertEqual(server.state['phase'], 'terminal')
        for key, value in [('prUrl', None), ('prUrl', {}), ('prUrl', f'https://github.com/{supervisor.REPO}/pull/24'),
                           ('startingRef', None), ('startingRef', 'goal/issue-24'), ('startingRef', SECRET)]:
            with self.subTest(key=key, value=value):
                server = Server()
                server.agent['repos'][0][key] = value
                self.assert_rejected(server)

    def test_missing_malformed_or_ambiguous_agent_and_branch_metadata_rejects(self):
        changes = [lambda a, r: a.pop('repos'), lambda a, r: a.update(repos=[]),
                   lambda a, r: a.update(repos=a['repos'] * 2), lambda a, r: a.update(repos=[None]),
                   lambda a, r: a.update(workOnCurrentBranch=1), lambda a, r: a.pop('workOnCurrentBranch'),
                   lambda a, r: r.pop('git'), lambda a, r: r.update(git=None),
                   lambda a, r: r['git'].pop('branches'), lambda a, r: r['git'].update(branches=None),
                   lambda a, r: r['git'].update(branches=[]), lambda a, r: r['git'].update(branches=[None]),
                   lambda a, r: r['git'].update(branches=r['git']['branches'] * 2)]
        for index, change in enumerate(changes):
            with self.subTest(index=index):
                server = Server()
                change(server.agent, server.run)
                self.assert_rejected(server)

    def test_foreign_or_noncanonical_provider_targets_reject(self):
        for field, value in [('repoUrl', 'github.com/other/Tremelay'), ('repoUrl', None),
                             ('prUrl', 'https://github.com/other/Tremelay/pull/23'),
                             ('prUrl', f'https://github.com/{supervisor.REPO}/pull/023'),
                             ('prUrl', f'https://github.com/{supervisor.REPO}/pull/23?token=' + SECRET),
                             ('prUrl', None), ('branch', None), ('branch', 'goal/issue-021'),
                             ('branch', 'goal/issue-24'), ('branch', 'goal/issue-21\n' + SECRET)]:
            with self.subTest(field=field, value=value):
                server = Server()
                server.run['git']['branches'][0][field] = value
                self.assert_rejected(server)
        server = Server()
        server.agent['repos'][0]['url'] = 'https://github.com/other/Tremelay'
        self.assert_rejected(server)

    def test_changed_second_agent_metadata_rejects_after_github_proof(self):
        for key, value in [('workOnCurrentBranch', False), ('repos', []),
                           ('repos', [{'url': f'https://github.com/{supervisor.REPO}', 'startingRef': 'goal/issue-24'}])]:
            with self.subTest(key=key, value=value):
                server = Server()
                server.current = dict(copy.deepcopy(server.agent), **{key: value})
                self.assert_rejected(server)
                self.assertEqual(server.agent_reads, 2)

    def test_both_github_prs_require_exact_repository_owner_branch_and_base(self):
        changes = [lambda p: p.update(user={'login': 'other'}), lambda p: p.update(number=24),
                   lambda p: p.update(html_url=f'https://github.com/other/Tremelay/pull/{p["number"]}'),
                   lambda p: p['head'].update(repo={'full_name': 'fork/Tremelay'}),
                   lambda p: p['base'].update(repo={'full_name': 'other/Tremelay'}),
                   lambda p: p['head'].update(ref='goal/issue-24'), lambda p: p['base'].update(ref='develop')]
        for target in ['original', 'alias']:
            for index, change in enumerate(changes):
                with self.subTest(target=target, index=index):
                    server = Server()
                    change(getattr(server, target))
                    self.assert_rejected(server)

    def test_missing_or_malformed_github_identity_fields_reject_as_controlled_stop(self):
        for target in ['original', 'alias']:
            for field in ['number', 'html_url', 'user', 'head', 'base', 'body', 'state', 'merged', 'merged_at']:
                with self.subTest(target=target, field=field):
                    server = Server()
                    getattr(server, target).pop(field)
                    self.assert_rejected(server)
            for side in ['head', 'base']:
                for field in ['repo', 'ref']:
                    with self.subTest(target=target, side=side, field=field):
                        server = Server()
                        getattr(server, target)[side].pop(field)
                        self.assert_rejected(server)
            for field, value in [('user', []), ('base', []), ('head', []), ('state', {}), ('body', None)]:
                with self.subTest(target=target, field=field, value=value):
                    server = Server()
                    getattr(server, target)[field] = value
                    self.assert_rejected(server)

    def test_cross_issue_duplicate_or_malformed_source_markers_reject(self):
        for target in ['original', 'alias']:
            for body in ['Goal-Issue: #24', 'Goal-Issue: #021', 'Goal-Issue: #21\nGoal-Issue: #24',
                         'Goal-Issue: #21\n  Goal-Issue: #24', 'Goal-Issue: #21\nGoal-Issue: #21',
                         'Goal-Issue: #21\nGoal-Issue: invalid', 'No source issue']:
                with self.subTest(target=target, body=body):
                    server = Server()
                    getattr(server, target)['body'] = body
                    self.assert_rejected(server)

    def test_github_read_failure_keeps_receipt_owned(self):
        server = Server()
        with patch.object(server, 'github', side_effect=supervisor.Stop('GitHub operation failed; no automatic replay')):
            self.assert_rejected(server)


if __name__ == '__main__':
    unittest.main()
