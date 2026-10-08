import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import checkpoint_supervisor as s

HEAD = 'a' * 40
PULL = {'number': 11, 'state': 'open', 'draft': False,
        'user': {'login': s.AUTHOR}, 'head': {'sha': HEAD, 'repo': {'full_name': s.REPO}},
        'base': {'ref': 'main'}, 'body': 'Goal-Issue: #10',
        'labels': [{'name': 'goal'}, {'name': 'human-review-required'}]}
REVIEW = {'id': 4, 'user': {'login': 'chatgpt-codex-connector[bot]'},
          'commit_id': HEAD, 'state': 'COMMENTED', 'submitted_at': '2026-10-08T04:00:00Z'}
DECISION = {'decision': 'resume', 'head': HEAD, 'assessment': 'Implementation bug consistent with scope.',
            'correction': 'Update the derived index and test rollback.', 'reason_for_user': ''}


class Gates(unittest.TestCase):
    def test_fork_other_author_closed_and_non_goal_are_ineligible(self):
        self.assertTrue(s.eligible(PULL))
        for path, value in [(('head', 'repo', 'full_name'), 'outsider/Tremelay'),
                            (('user', 'login'), 'outsider'), (('state',), 'closed'),
                            (('draft',), True), (('base', 'ref'), 'dev'), (('body',), 'ordinary PR')]:
            pull = copy.deepcopy(PULL)
            target = pull
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            self.assertFalse(s.eligible(pull))

    def test_review_requires_exact_head_and_newest_submitted_codex(self):
        newer = dict(REVIEW, id=5, submitted_at='2026-10-08T05:00:00Z')
        stale = dict(REVIEW, id=6, commit_id='b' * 40, submitted_at='2026-10-08T06:00:00Z')
        pending = dict(newer, id=7, state='PENDING')
        forged = dict(newer, id=8, user={'login': 'attacker'})
        self.assertEqual(s.newest_review([REVIEW, newer, stale, pending, forged], HEAD)['id'], 5)

    def test_untrusted_checkpoint_comment_cannot_claim_or_exhaust_budget(self):
        body = s.state_body({'head': HEAD, 'review': 4, 'phase': 'reserved'}, 'Claim')
        self.assertEqual(s.records([{'user': {'login': 'attacker'}, 'body': body}]), [])
        self.assertEqual(len(s.records([{'user': {'login': s.AUTHOR}, 'body': body}])), 1)

    def test_malformed_trusted_state_fails_closed(self):
        with self.assertRaises(s.Stop):
            s.records([{'user': {'login': s.AUTHOR}, 'body': s.MARKER + 'broken -->'}])

    def test_decision_rejects_stale_head_tools_markers_and_empty_correction(self):
        self.assertEqual(s.validate_decision(DECISION, HEAD), DECISION)
        for update in [{'head': 'b' * 40}, {'decision': 'merge'}, {'tool': 'gh'},
                       {'correction': ''}, {'assessment': '<!-- tremelay-human-resume -->'},
                       {'correction': '@codex review'}, {'reason_for_user': 'approve restart'}]:
            with self.assertRaises(s.Stop):
                s.validate_decision(dict(DECISION, **update), HEAD)

    def test_escalation_must_be_actionable(self):
        with self.assertRaises(s.Stop):
            s.validate_decision(dict(DECISION, decision='escalate'), HEAD)
        self.assertEqual(s.validate_decision(dict(DECISION, decision='escalate', reason_for_user='Choose product scope.'), HEAD)['decision'], 'escalate')

    def test_changed_head_and_active_worker_block_dispatch(self):
        for changed in [dict(PULL, head={'sha': 'b' * 40, 'repo': {'full_name': s.REPO}}), PULL]:
            with patch.object(s, 'gh', return_value=changed), patch.object(s, 'pages', return_value=[REVIEW]), patch.object(s, 'active_goal_work', return_value=True):
                with self.assertRaises(s.Stop):
                    s.refresh_guard(11, HEAD, 4)

    def test_model_input_and_output_are_bounded_without_tools(self):
        with self.assertRaises(s.Stop):
            s.assess({'head': HEAD, 'evidence': 'x' * (s.MAX_BYTES + 1)}, 'test-sentinel-key')
        self.assertNotIn('tools', s.SCHEMA['properties'])
        self.assertEqual(s.MODEL, 'gpt-6.1-sol')

    def test_redirect_is_refused(self):
        with self.assertRaises(s.Stop):
            s.NoRedirect().redirect_request(None, None, 302, '', {}, 'https://attacker.invalid')


class Controller(unittest.TestCase):
    def run_controller(self, *, decision=None, failure=None, previous=None):
        writes = []
        def api(path, method='GET', data=None, paginate=False):
            if method != 'GET':
                writes.append((path, method, data))
                if failure and failure(path, method, data):
                    raise s.Stop('Injected transport failure')
                return {'id': 100} if method == 'POST' and path.endswith('/comments') else None
            raise AssertionError('Unexpected GET: ' + path)
        def paged(path):
            if path.endswith('/reviews'):
                return [REVIEW]
            if path.endswith('/comments') and '/reviews/' in path:
                return [{'body': 'P1 implementation issue'}]
            if path.endswith('/comments'):
                return previous or []
            raise AssertionError(path)
        context = [patch.object(s, 'gh', side_effect=api), patch.object(s, 'pages', side_effect=paged),
                   patch.object(s, 'active_goal_work', return_value=False),
                   patch.object(s, 'evidence_for', return_value={'head': HEAD}),
                   patch.object(s, 'retry_job', return_value=200), patch.object(s, 'refresh_guard'),
                   patch.object(s, 'assess', return_value=(decision or DECISION, {'input_tokens': 100}))]
        with context[0], context[1], context[2], context[3], context[4], context[5], context[6] as model:
            error = None
            try:
                s.run_one(PULL, 'test-sentinel-key', 3)
            except s.Stop as exc:
                error = exc
        return writes, model, error

    def test_reservation_and_assessment_precede_restart(self):
        writes, model, error = self.run_controller()
        self.assertIsNone(error)
        self.assertEqual(model.call_count, 1)
        self.assertIn('"phase":"reserved"', writes[0][2]['body'])
        self.assertIn('<!-- tremelay-human-resume -->', writes[1][2]['body'])
        self.assertIn('"phase":"dispatch_reserved"', writes[2][2]['body'])
        self.assertEqual(writes[3][1], 'DELETE')
        self.assertEqual(writes[4][:2], ('repos/' + s.REPO + '/actions/jobs/200/rerun', 'POST'))

    def test_failed_assessment_patch_does_not_clear_stop_or_launch(self):
        writes, _, error = self.run_controller(failure=lambda p, m, d: m == 'PATCH')
        self.assertIsInstance(error, s.Stop)
        self.assertFalse(any(m == 'DELETE' or p.endswith('/rerun') for p, m, d in writes))

    def test_ambiguous_dispatch_keeps_claim_and_does_not_retry(self):
        writes, _, error = self.run_controller(failure=lambda p, m, d: p.endswith('/rerun'))
        self.assertIsInstance(error, s.Stop)
        self.assertEqual(sum(p.endswith('/rerun') for p, m, d in writes), 1)
        self.assertIn('"phase":"dispatch_reserved"', writes[2][2]['body'])

    def test_escalation_records_decision_without_removing_stop(self):
        writes, _, error = self.run_controller(decision=dict(DECISION, decision='escalate', reason_for_user='Change goal scope?'))
        self.assertIsNone(error)
        self.assertFalse(any(m == 'DELETE' or p.endswith('/rerun') for p, m, d in writes))
        self.assertIn("Patrick's input required", writes[-1][2]['body'])

    def test_existing_ambiguous_reservation_is_not_reassessed_or_dispatched(self):
        prior = {'user': {'login': s.AUTHOR}, 'body': s.state_body({'head': HEAD, 'review': 4, 'phase': 'reserved'}, 'claimed')}
        writes, model, error = self.run_controller(previous=[prior])
        self.assertEqual(writes, [])
        self.assertEqual(model.call_count, 0)

    def test_total_budget_stops_new_heads_and_notifies_once(self):
        prior = [{'user': {'login': s.AUTHOR}, 'body': s.state_body({'head': str(i) * 40, 'review': i, 'phase': 'reserved'}, 'claimed')} for i in range(3)]
        writes, model, error = self.run_controller(previous=prior)
        self.assertEqual(model.call_count, 0)
        self.assertEqual(len(writes), 1)
        prior.append({'user': {'login': s.AUTHOR}, 'body': writes[0][2]['body']})
        writes, model, error = self.run_controller(previous=prior)
        self.assertEqual(writes, [])

    def test_workflow_uses_trusted_main_and_serializes_controller(self):
        text = (Path(__file__).resolve().parents[1] / '.github/workflows/checkpoint-supervisor.yml').read_text()
        self.assertIn('ref: main', text)
        self.assertIn('cancel-in-progress: false', text)
        self.assertNotIn('pull_request_target', text)
        self.assertNotIn('CURSOR_API_KEY', text)


if __name__ == '__main__':
    unittest.main()
