import copy
import json
from pathlib import Path
import sys
import subprocess
import tempfile
import shlex
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import checkpoint_supervisor as s
import codex_cursor_remediation as generic
import goal_agent_request as goal
import checkpoint_stop as stop

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

    def test_newer_approval_or_dismissal_supersedes_old_findings(self):
        for state in ['APPROVED', 'DISMISSED']:
            latest = dict(REVIEW, id=9, state=state, submitted_at='2026-10-08T06:00:00Z')
            self.assertIsNone(s.newest_review([REVIEW, latest], HEAD))
            self.assertIsNone(s.newest_review([dict(REVIEW, state=state)], HEAD))

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
            with patch.object(s, 'gh', return_value=changed), patch.object(s, 'pages', return_value=[REVIEW]), patch.object(s, 'active_goal_work', return_value=True), patch.object(s.time, 'sleep'):
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
                   patch.object(s, 'cursor', return_value={'agent': {'id': s.worker_payload(11, HEAD, 4, DECISION)['agentId']}, 'run': {'id': 'run-1'}}), patch.object(s, 'refresh_guard'),
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
        self.assertIn('Cursor remediation round 1', writes[3][2]['body'])
        self.assertFalse(any(method == 'DELETE' for _, method, _ in writes))
        self.assertIn('"phase":"working"', writes[4][2]['body'])

    def test_idle_timeout_preserves_paid_decision_and_recovers_one_first_create(self):
        state = {'phase': 'dispatch_ready', 'head': HEAD, 'review': 4, 'decision': DECISION}
        comment = {'id': 100, 'body': s.state_body(state, 'Recorded assessment')}
        with patch.object(s, 'active_goal_work', return_value=True), patch.object(s.time, 'sleep'), patch.object(s, 'cursor') as api, patch.object(s, 'update_state') as write:
            with self.assertRaises(s.Stop):
                s.dispatch_ready(PULL, comment, state)
            self.assertEqual(state['phase'], 'dispatch_ready')
            api.assert_not_called()
            write.assert_not_called()
        # Next wake finds real work idle. The reservation's comment creates a
        # queued goal run, but the final freshness guard must not wait on it.
        payload = s.worker_payload(11, HEAD, 4, DECISION)
        with patch.object(s, 'wait_for_goal_idle') as idle, patch.object(s, 'active_goal_work', return_value=False), patch.object(s, 'gh', return_value=PULL), patch.object(s, 'pages', return_value=[REVIEW]), patch.object(s, 'update_state'), patch.object(s, 'assess') as model, patch.object(s, 'cursor', return_value={'agent': {'id': payload['agentId']}, 'run': {'id': 'run-1'}}) as api:
            s.dispatch_ready(PULL, comment, state)
            idle.assert_called_once()
            self.assertEqual(api.call_count, 1)
            self.assertEqual(state['phase'], 'working')
            model.assert_not_called()

    def test_record_assessment_before_dispatch_idle_guard(self):
        with patch.object(s, 'dispatch_ready', side_effect=s.Stop('Queued goal run')):
            writes, model, error = self.run_controller()
        self.assertIsInstance(error, s.Stop)
        self.assertEqual(model.call_count, 1)
        body = writes[-1][2]['body']
        self.assertIn('"phase":"dispatch_ready"', body)
        state = s.records([{'user': {'login': s.AUTHOR}, 'body': body}])[0][1]
        self.assertEqual(state['decision'], DECISION)
        self.assertEqual(len(writes), 2)

    def test_post_reservation_head_change_never_posts_create(self):
        state = {'phase': 'dispatch_ready', 'head': HEAD, 'review': 4, 'decision': DECISION}
        comment = {'id': 100, 'body': s.state_body(state, 'Recorded assessment')}
        with patch.object(s, 'refresh_guard', side_effect=[None, s.Stop('Moved head')]), patch.object(s, 'gh'), patch.object(s, 'update_state'), patch.object(s, 'cursor') as api:
            with self.assertRaises(s.Stop):
                s.dispatch_ready(PULL, comment, state)
            self.assertEqual(state['phase'], 'dispatch_reserved')
            api.assert_not_called()

    def test_actual_checkpoint_stop_command_contains_attempts_findings_and_ci(self):
        comments = [
            {'id': 1, 'user': {'login': s.AUTHOR}, 'body': 'A cloud agent is working through the review findings: old'},
            {'id': 2, 'user': {'login': s.AUTHOR}, 'body': goal.HUMAN_RESUME_MARKER},
        ] + [{'id': i, 'html_url': f'https://example.test/attempt/{i}', 'body': f'Cursor remediation round {i}', 'user': {'login': s.AUTHOR}} for i in [3,4,5]]
        findings = [{'path': 'risk.go', 'body': 'P1 suspension scan must use a derived index', 'html_url': 'https://example.test/review/4'}]
        runs = [{'id': 77, 'name': 'CI', 'status': 'completed', 'conclusion': 'failure', 'html_url': 'https://example.test/ci/77'}]
        with tempfile.TemporaryDirectory() as directory:
            source, output = Path(directory)/'comments.json', Path(directory)/'stop.md'
            source.write_text(json.dumps([comments]))
            with patch.object(sys, 'argv', ['checkpoint_stop.py', '--head', HEAD, '--comments', str(source), '--output', str(output)]), patch.dict(s.os.environ, {'GITHUB_REPOSITORY': s.REPO, 'PR_NUMBER': '11'}), patch.object(stop, 'pages', side_effect=[[REVIEW], findings]), patch.object(stop, 'gh', return_value={'workflow_runs': runs}):
                stop.main()
            body = output.read_text()
            self.assertNotIn('findings: old', body)
            self.assertIn('3 counted attempts', body)
            for token in ['attempt/3', 'attempt/4', 'attempt/5', findings[0]['body'], HEAD, 'failure', 'ci/77', 'independent supervisor assessment', 'claims do not prove']:
                self.assertIn(token, body)

    def test_failed_assessment_patch_does_not_clear_stop_or_launch(self):
        writes, _, error = self.run_controller(failure=lambda p, m, d: m == 'PATCH')
        self.assertIsInstance(error, s.Stop)
        self.assertFalse(any(m == 'DELETE' or p.endswith('/rerun') for p, m, d in writes))

    def test_worker_payload_contains_actual_supervisor_correction(self):
        payload = s.worker_payload(11, HEAD, 4, DECISION)
        self.assertIn(DECISION['correction'], payload['prompt']['text'])
        self.assertIn(DECISION['assessment'], payload['prompt']['text'])
        self.assertEqual(payload['repos'][0]['prUrl'], 'https://github.com/' + s.REPO + '/pull/11')
        self.assertEqual(payload, s.worker_payload(11, HEAD, 4, DECISION))

    def test_recovery_never_reposts_create_after_ambiguous_launch(self):
        state = {'phase': 'dispatch_reserved', 'agent_id': s.worker_payload(11, HEAD, 4, DECISION)['agentId'],
                 'time': s.datetime.now(s.timezone.utc).isoformat(), 'head': HEAD}
        comment = {'id': 100, 'body': s.state_body(state, 'assessment')}
        with patch.object(s, 'cursor', side_effect=[{'id': state['agent_id'], 'latestRunId': 'run-1'}, {'status': 'RUNNING'}]) as api, patch.object(s, 'update_state'):
            s.recover_worker(PULL, comment, state)
            self.assertEqual(state['phase'], 'working')
            self.assertTrue(all(not call.kwargs for call in api.call_args_list))

    def test_already_recorded_running_worker_does_not_create_event_feedback(self):
        state = {'phase': 'working', 'agent_id': s.worker_payload(11, HEAD, 4, DECISION)['agentId'],
                 'run_id': 'run-1', 'time': s.datetime.now(s.timezone.utc).isoformat(), 'head': HEAD}
        with patch.object(s, 'cursor', side_effect=[{'id': state['agent_id']}, {'status': 'RUNNING'}]), patch.object(s, 'update_state') as write:
            s.recover_worker(PULL, {'id': 100}, state)
            write.assert_not_called()

    def test_noop_worker_does_not_clear_stop_or_request_review(self):
        state = {'phase': 'working', 'agent_id': s.worker_payload(11, HEAD, 4, DECISION)['agentId'],
                 'run_id': 'run-1', 'time': s.datetime.now(s.timezone.utc).isoformat(), 'head': HEAD}
        with patch.object(s, 'cursor', side_effect=[{'id': state['agent_id']}, {'status': 'FINISHED'}]), patch.object(s, 'gh', side_effect=[PULL, {'status': 'identical'}]) as api, patch.object(s, 'update_state'):
            s.recover_worker(PULL, {'id': 100}, state)
            self.assertEqual(state['phase'], 'escalate')
            self.assertTrue(all(not call.kwargs for call in api.call_args_list))

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

    def test_unattributed_main_comment_run_blocks_resumption(self):
        runs = {"workflow_runs": [{"status": "in_progress", "head_sha": "b" * 40,
                                  "event": "issue_comment", "pull_requests": []}]}
        with patch.object(s, 'gh', return_value=[runs]):
            self.assertTrue(s.active_goal_work(11, HEAD))
        runs["workflow_runs"][0]["status"] = "completed"
        with patch.object(s, 'gh', return_value=[runs]):
            self.assertFalse(s.active_goal_work(11, HEAD))

    def test_idle_gate_sees_active_worker_beyond_first_hundred_runs(self):
        pages = [{'workflow_runs': [{'status': 'completed'} for _ in range(100)]},
                 {'workflow_runs': [{'status': 'in_progress'}]}]
        with patch.object(s, 'gh', return_value=pages) as api:
            self.assertTrue(s.active_goal_work(11, HEAD))
            self.assertTrue(api.call_args.kwargs['paginate'])

    def test_failed_pr_reconciliation_does_not_starve_later_checkpoints(self):
        state = {'phase': 'dispatch_reserved', 'head': HEAD, 'review': 4}
        claim = {'user': {'login': s.AUTHOR}, 'body': s.state_body(state, 'Claim')}
        next_pull = dict(PULL, number=13)
        with patch.dict(s.os.environ, {'GITHUB_REPOSITORY': s.REPO, 'GH_TOKEN': 'test-token', 'OPENAI_API_KEY': 'test-key', 'CURSOR_API_KEY': 'test-cursor', 'SUPERVISOR_MAX_CHECKPOINTS': '3'}), patch.object(sys, 'argv', ['checkpoint_supervisor.py']), patch.object(s, 'gh', return_value={'login': s.AUTHOR}), patch.object(s, 'pages', side_effect=[[PULL, next_pull], [claim], []]), patch.object(s, 'recover_worker', side_effect=s.Stop('No accepted worker')), patch.object(s, 'run_one') as assess:
            self.assertEqual(s.main(), 1)
            self.assertEqual(assess.call_args.args[0]['number'], 13)

    def test_oversized_checkpoint_keeps_durable_bounded_summary_with_links(self):
        finding = {'path': 'risk.go', 'body': 'P1 derived suspension index required ' + 'x' * 62000, 'html_url': 'https://example.test/finding'}
        body = stop.stop_body(HEAD, [], dict(REVIEW, html_url='https://example.test/review'), [finding], [])
        self.assertLess(len(body), 60000)
        for value in [HEAD, 'independent supervisor assessment', 'P1 derived suspension', 'https://example.test/review', 'https://example.test/finding', 'tremelay-cycle-stop']:
            self.assertIn(value, body)

    def test_final_guard_allows_own_label_removal_but_not_other_changes(self):
        pull = copy.deepcopy(PULL)
        pull['labels'] = [{'name': 'goal'}]
        self.assertFalse(s.eligible(pull))
        self.assertTrue(s.eligible(pull, require_stop=False))
        pull['head']['sha'] = 'b' * 40
        with patch.object(s, 'gh', return_value=pull), patch.object(s, 'wait_for_goal_idle'):
            with self.assertRaises(s.Stop):
                s.refresh_guard(11, HEAD, 4, require_stop=False)

    def test_own_comment_workflows_settle_before_final_guard(self):
        with patch.object(s, 'active_goal_work', side_effect=[True, True, False, False]), patch.object(s.time, 'sleep') as sleep, patch.object(s, 'gh', return_value=PULL), patch.object(s, 'pages', return_value=[REVIEW]):
            s.refresh_guard(11, HEAD, 4)
            self.assertEqual(sleep.call_count, 2)

    def test_persistent_active_work_never_allows_launch(self):
        with patch.object(s, 'active_goal_work', return_value=True), patch.object(s.time, 'sleep'):
            with self.assertRaises(s.Stop):
                s.wait_for_goal_idle(11, HEAD)

    def test_review_recovery_uses_trusted_marker_without_duplicate_request(self):
        state = {'completed_head': HEAD, 'phase': 'review_reserved'}
        marker = f'<!-- tremelay-supervisor-review:{HEAD} -->'
        with patch.object(s, 'gh', return_value=PULL) as api, patch.object(s, 'active_goal_work', return_value=False), patch.object(s, 'pages', return_value=[{'user': {'login': s.AUTHOR}, 'body': marker}]), patch.object(s, 'update_state'):
            s.finish_review(PULL, {'id': 100}, state)
            self.assertFalse(any(c.kwargs.get('method') == 'POST' for c in api.call_args_list))
            self.assertEqual(state['phase'], 'completed')

    def test_forged_review_marker_cannot_suppress_independent_review(self):
        state = {'completed_head': HEAD, 'phase': 'review_reserved'}
        marker = f'<!-- tremelay-supervisor-review:{HEAD} -->'
        with patch.object(s, 'gh', return_value=PULL) as api, patch.object(s, 'active_goal_work', return_value=False), patch.object(s, 'pages', return_value=[{'user': {'login': 'outsider'}, 'body': marker}]), patch.object(s, 'update_state'):
            s.finish_review(PULL, {'id': 100}, state)
            self.assertEqual(sum(c.kwargs.get('method') == 'POST' for c in api.call_args_list), 1)

    def test_invalid_cursor_identity_blocks_reconciliation(self):
        with patch.object(s, 'cursor') as api:
            with self.assertRaises(s.Stop):
                s.recover_worker(PULL, {'id': 100}, {'agent_id': '../other-account'})
            api.assert_not_called()

    def test_goal_review_launch_checks_live_stop_and_exact_head(self):
        event = {'review': REVIEW}
        live = copy.deepcopy(PULL)
        self.assertEqual(goal.review_launch_decision(event, 'pull_request_review', pull=live)['status'], 'blocked')
        live['labels'] = [{'name': 'goal'}]
        self.assertEqual(goal.review_launch_decision(event, 'pull_request_review', pull=live)['status'], 'free')
        live['state'] = 'closed'
        self.assertEqual(goal.review_launch_decision(event, 'pull_request_review', pull=live)['status'], 'blocked')
        live['state'] = 'open'
        live['head']['sha'] = 'b' * 40
        self.assertEqual(goal.review_launch_decision(event, 'pull_request_review', pull=live)['status'], 'blocked')

    def test_actual_workflow_state_builders_execute_in_the_correct_jobs(self):
        root = Path(__file__).resolve().parents[1]
        lines = (root / '.github/workflows/goal.yml').read_text().splitlines()
        commands = {name: next(line.strip() for line in lines if 'python -c' in line and f'open("{name}"' in line)
                    for name in ['review_state.json', 'ownership.json']}
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            (tmp / 'scripts').symlink_to(root / 'scripts', target_is_directory=True)
            (tmp / 'reviews.json').write_text(json.dumps([[REVIEW]]))
            (tmp / 'comments.json').write_text('[]')
            result = subprocess.run(shlex.split(commands['review_state.json']), cwd=tmp, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn('pull', json.loads((tmp / 'review_state.json').read_text()))
            (tmp / 'live_pull.json').write_text(json.dumps(PULL))
            result = subprocess.run(shlex.split(commands['ownership.json']), cwd=tmp, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads((tmp / 'ownership.json').read_text())['pull'], PULL)

    def test_actual_precreate_guard_refuses_closed_stopped_or_moved_pr(self):
        root = Path(__file__).resolve().parents[1]
        line = next(line.strip() for line in (root / '.github/workflows/goal.yml').read_text().splitlines()
                    if line.strip().startswith('if ! python -c') and 'precreate_pull.json' in line)
        command = shlex.split(line[len('if ! '):].removesuffix('; then'))
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            (tmp / 'claim.json').write_text(json.dumps({'head': HEAD}))
            live = copy.deepcopy(PULL)
            live['labels'] = [{'name': 'goal'}]
            for modification, expected in [({}, 0), ({'state': 'closed'}, 1),
                    ({'labels': PULL['labels']}, 1), ({'head': {'sha': 'b' * 40}}, 1)]:
                (tmp / 'precreate_pull.json').write_text(json.dumps(dict(live, **modification)))
                result = subprocess.run(command, cwd=tmp, capture_output=True, text=True)
                self.assertEqual(result.returncode, expected, result.stderr)

    def test_generic_loop_cannot_launch_goal_or_stopped_pr(self):
        event = {'action': 'submitted', 'review': REVIEW}
        for label in ['goal', 'human-review-required']:
            pull = copy.deepcopy(PULL)
            pull['labels'] = [{'name': label}, {'name': 'codex-cursor-loop'}]
            plan = generic.build_plan(event, pull, [], [])
            self.assertEqual(plan['action'], 'skip')

    def test_workflow_uses_trusted_main_and_serializes_controller(self):
        text = (Path(__file__).resolve().parents[1] / '.github/workflows/checkpoint-supervisor.yml').read_text()
        self.assertIn('ref: main', text)
        self.assertIn('cancel-in-progress: false', text)
        self.assertNotIn('pull_request_target', text)
        self.assertIn('CURSOR_API_KEY', text)
        self.assertNotIn('pull_request:', text)
        self.assertFalse((Path(__file__).resolve().parents[1] / '.github/workflows/supervisor-preflight.yml').exists())


if __name__ == '__main__':
    unittest.main()
