"""Incident regressions: ownership outlives PR/head/goal lifecycle changes."""
import copy
import sys
from pathlib import Path
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import automation_protocol as protocol
import checkpoint_supervisor as s
import goal_agent_request as goal
import goal_review_launch as launch
from test_checkpoint_supervisor import PULL, HEAD, REVIEW, DECISION, worker_lookup
from test_goal_review_recovery import Server

ENV = {'GITHUB_REPOSITORY': s.REPO, 'GITHUB_REF': 'refs/heads/main',
       'GITHUB_WORKFLOW_REF': s.REPO + '/.github/workflows/checkpoint-supervisor.yml@refs/heads/main',
       'GH_TOKEN': 'test-token', 'CURSOR_API_KEY': 'test-cursor',
       'TREMELAY_SUPERVISOR_ACTIVATION': s.ACTIVATION_VALUE, 'SUPERVISOR_MAX_CHECKPOINTS': '3'}


def receipt(phase='working'):
    state = {'phase': phase, 'agent_id': s.worker_payload(11, HEAD, 4, DECISION)['agentId'],
             'run_id': 'run-1', 'time': '2000-01-01T00:00:00+00:00', 'head': HEAD,
             'review': 4, 'timeout_escalated': True, 'decision': DECISION}
    comment = {'id': 100, 'user': {'login': s.AUTHOR},
               'issue_url': f'https://api.github.com/repos/{s.REPO}/issues/11',
               'body': s.state_body(state, 'Recorded assessment\n\n<!-- tremelay-human-resume -->')}
    return state, comment


class SharedOwnership(unittest.TestCase):
    def test_supervisor_owns_newer_normal_review_without_stop_label(self):
        state, comment = receipt()
        pull = copy.deepcopy(PULL)
        pull['labels'] = [{'name': 'goal'}]
        pull['head']['sha'] = 'b' * 40
        review = dict(REVIEW, id=5, commit_id='b' * 40)
        result = goal.review_launch_decision({'review': review}, 'pull_request_review',
                    reviews=[review], comments=[comment], trusted_login=s.AUTHOR, pull=pull)
        self.assertEqual(result['status'], 'blocked')
        self.assertTrue(launch.pending_claim([comment], s.REPO, 11, s.AUTHOR))
        self.assertFalse(launch.pending_claim([comment], s.REPO, 11, s.AUTHOR,
                                             ignore_comment_id=100))

    def test_old_completed_escalated_or_unknown_receipts_do_not_prove_terminal(self):
        for phase in ['completed', 'escalate', 'obsolete', 'unknown', None, []]:
            state, comment = receipt(phase)
            with self.subTest(phase=phase):
                self.assertTrue(protocol.supervisor_owns_work(state))
                self.assertTrue(launch.pending_claim([comment], s.REPO, 11, s.AUTHOR))
        for status in ['RUNNING', '', None, [], 'FINISHED quoted']:
            state, _ = receipt('terminal')
            state['terminal_status'] = status
            self.assertTrue(protocol.supervisor_owns_work(state))

    def test_only_valid_terminal_receipt_releases_supervisor_ownership(self):
        for status in protocol.WORKER_TERMINAL_STATUSES:
            state, comment = receipt('terminal')
            state['terminal_status'] = status
            comment['body'] = s.state_body(state, 'Verified existing run')
            self.assertFalse(launch.pending_claim([comment], s.REPO, 11, s.AUTHOR))
            self.assertEqual(goal.cycle_budget([comment]), (0, 3))
        state['run_id'] = '../bad'
        self.assertTrue(protocol.supervisor_owns_work(state))

    def test_orphan_supervisor_launch_receipt_stays_blocking(self):
        state, comment = receipt()
        dispatch = dict(comment, id=101, body=(
            'Cursor remediation round 1: supervisor worker launch reserved.\n\n'
            f'Agent: `{state["agent_id"]}`. Correction is recorded above. '
            'An ambiguous create is reconciled by this identity, never replayed.'))
        with self.assertRaises(s.Stop):
            launch.pending_claim([dispatch], s.REPO, 11, s.AUTHOR)
        self.assertTrue(launch.pending_claim([dispatch, comment], s.REPO, 11, s.AUTHOR))
        state.update(phase='terminal', terminal_status='FINISHED')
        comment['body'] = s.state_body(state, 'Verified')
        self.assertFalse(launch.pending_claim([dispatch, comment], s.REPO, 11, s.AUTHOR))

    def test_wrong_author_or_evidence_cannot_create_ownership(self):
        _, comment = receipt()
        comment['user']['login'] = 'attacker'
        self.assertFalse(launch.pending_claim([comment], s.REPO, 11, s.AUTHOR))

    def test_two_workers_are_reconciled_without_any_review_or_new_work(self):
        state, comment = receipt()
        second = copy.deepcopy(comment)
        second['id'] = 101
        with patch.dict(s.os.environ, ENV, clear=True), patch.object(sys, 'argv', ['supervisor']), \
                patch.object(s, 'gh', return_value={'login': s.AUTHOR}), \
                patch.object(s, 'pages', side_effect=[[PULL], [comment, second]]), \
                patch.object(s, 'recover_worker') as recover, patch.object(s, 'run_one') as model:
            self.assertEqual(s.main(), 0)
        self.assertEqual(recover.call_count, 2)
        self.assertTrue(all(call.kwargs == {'reconcile_only': True} for call in recover.call_args_list))
        model.assert_not_called()


class ClosedGoalRecovery(unittest.TestCase):
    def run_scan(self, pull, comment, cursor_calls):
        writes = []
        def api(path, method='GET', data=None, **kwargs):
            if method == 'PATCH':
                self.assertEqual(path, f'repos/{s.REPO}/issues/comments/100')
                comment['body'] = data['body']
                writes.append(copy.deepcopy(data))
                return None
            self.assertEqual(method, 'GET')
            if path == 'user':
                return {'login': s.AUTHOR}
            self.assertEqual(path, f'repos/{s.REPO}/pulls/11')
            return pull
        def pages(path):
            if path == f'repos/{s.REPO}/pulls?state=all':
                return [pull]
            self.assertEqual(path, f'repos/{s.REPO}/issues/11/comments')
            return [comment]
        with patch.dict(s.os.environ, ENV, clear=True), patch.object(sys, 'argv', ['supervisor']), \
                patch.object(s, 'gh', side_effect=api), patch.object(s, 'pages', side_effect=pages), \
                patch.object(s, 'cursor', side_effect=cursor_calls) as worker, \
                patch.object(s, 'assess') as assess, patch.object(s, 'finish_review') as review, \
                patch.object(s, 'dispatch_ready') as dispatch:
            outcome = s.main()
        assess.assert_not_called()
        review.assert_not_called()
        dispatch.assert_not_called()
        self.assertTrue(all(not call.kwargs for call in worker.call_args_list))
        return outcome, writes, worker.call_count

    def test_closed_merged_or_goal_removed_worker_is_verified_and_recorded(self):
        for changes in [{'state': 'closed', 'merged_at': '2026-10-10T04:05:00Z'}, {'labels': []}]:
            for phase in ['working', 'dispatch_reserved', 'review_reserved', 'completed', 'escalate']:
                with self.subTest(changes=changes, phase=phase):
                    state, comment = receipt(phase)
                    pull = dict(copy.deepcopy(PULL), **changes)
                    result, writes, calls = self.run_scan(pull, comment, worker_lookup(state, 'FINISHED'))
                    self.assertEqual((result, len(writes), calls), (0, 1, 3))
                    saved = s.records([comment])[0][1]
                    self.assertEqual(saved['phase'], 'terminal')
                    self.assertEqual(saved['terminal_status'], 'FINISHED')
                    self.assertEqual(saved['decision'], DECISION)
                    self.assertIn('<!-- tremelay-human-resume -->', comment['body'])
                    self.assertFalse(protocol.supervisor_owns_work(saved))
                    self.assertEqual(self.run_scan(pull, comment, []), (0, [], 0))

    def test_closed_running_old_worker_is_still_owning_without_repeated_writes(self):
        state, comment = receipt()
        pull = dict(copy.deepcopy(PULL), state='closed', labels=[])
        self.assertEqual(self.run_scan(pull, comment, worker_lookup(state, 'RUNNING')), (0, [], 2))
        self.assertTrue(protocol.supervisor_owns_work(s.records([comment])[0][1]))

    def test_unknown_lookup_or_changed_run_never_releases_or_replays(self):
        state, comment = receipt('dispatch_reserved')
        pull = dict(copy.deepcopy(PULL), state='closed', labels=[])
        agent, run, final = worker_lookup(state, 'FINISHED')
        cases = [[s.Stop('ambiguous or missing worker')],
                 [dict(agent, latestRunId='run-new')],
                 [agent, dict(run, id='run-other')],
                 [agent, dict(run, agentId='bc-other')],
                 [agent, dict(run, status='UNKNOWN')],
                 [agent, run, dict(final, latestRunId='run-new')]]
        for calls in cases:
            with self.subTest(calls=calls):
                original = comment['body']
                result, writes, _ = self.run_scan(pull, comment, calls)
                self.assertEqual((result, writes), (1, []))
                self.assertEqual(comment['body'], original)

    def test_explicit_recovery_uses_only_existing_target_and_never_model(self):
        state, comment = receipt()
        pull = dict(copy.deepcopy(PULL), state='closed', labels=[])
        with patch.object(s, 'gh', side_effect=[pull, comment]), \
                patch.object(s, 'recover_worker') as worker, patch.object(s, 'assess') as model:
            s.recover_comment(11, 100)
            worker.assert_called_once_with(pull, comment, state, reconcile_only=True)
            model.assert_not_called()
        forged = dict(comment, issue_url=f'https://api.github.com/repos/{s.REPO}/issues/12')
        with patch.object(s, 'gh', side_effect=[pull, forged]), patch.object(s, 'cursor') as worker:
            with self.assertRaises(s.Stop):
                s.recover_comment(11, 100)
            worker.assert_not_called()

    def test_automatic_legacy_upgrade_skips_modern_prepared_and_continues_unknowns(self):
        modern = Server('prepared').claim
        old = dict(modern, id=200, body=launch.LEGACY_PREFIX +
                   ' https://cursor.com/agents/bc-7cce015b-2d8b-441e-892b-25f3b1d0cd77')
        next_old = dict(old, id=201)
        with patch.object(launch, 'recover', side_effect=[s.Stop('unknown worker'), {'phase': 'terminal'}]) as recover:
            self.assertTrue(s.recover_retired_ordinary(PULL, [modern, old, next_old, next_old]))
            self.assertEqual([call.args[2] for call in recover.call_args_list], [200, 201])
            self.assertTrue(all(call.kwargs == {'reconcile_only': True, 'legacy_only': True}
                                for call in recover.call_args_list))
        # A fresh type change must never release an in-flight modern claim from
        # the supervisor's different serialization group.
        server = Server('prepared')
        with patch.object(launch, 'gh', side_effect=server.gh), patch.object(launch, 'cursor') as cursor:
            with self.assertRaises(s.Stop):
                launch.recover(s.REPO, 11, 100, reconcile_only=True, legacy_only=True)
            cursor.assert_not_called()
        self.assertEqual(server.writes, [])
        self.assertEqual(server.saved()['phase'], 'prepared')

    def test_targeted_mode_cannot_enter_scan_assessment_or_dispatch(self):
        with patch.dict(s.os.environ, ENV, clear=True), \
                patch.object(sys, 'argv', ['supervisor', '--recover-pr', '11', '--recover-comment', '100']), \
                patch.object(s, 'gh', return_value={'login': s.AUTHOR}), \
                patch.object(s, 'recover_comment') as recover, patch.object(s, 'pages') as scan, \
                patch.object(s, 'assess') as model, patch.object(s, 'cursor') as cursor:
            self.assertEqual(s.main(), 0)
            recover.assert_called_once_with(11, 100)
            scan.assert_not_called()
            model.assert_not_called()
            cursor.assert_not_called()

    def test_ordinary_terminal_worker_on_closed_or_unlabelled_goal_is_retired(self):
        for change in [{'state': 'closed'}, {'labels': []}]:
            for status in launch.TERMINAL:
                server = Server('working', status)
                server.pull.update(change)
                saved = server.recover()
                self.assertEqual(saved['phase'], 'retired')
                self.assertEqual(saved['status'], status)
                self.assertEqual(server.posts(), [])
                self.assertEqual(goal.cycle_budget([server.claim]), (1, 3))
                self.assertFalse(launch.pending_claim([server.claim], launch.REPO, 11, s.AUTHOR))
                self.assertEqual(len(server.cursor_calls), 3)


if __name__ == '__main__':
    unittest.main()
