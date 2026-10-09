import copy
import base64
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
            s.assess({'head': HEAD, 'evidence': 'x' * (s.MAX_BYTES + 1)})
        self.assertNotIn('tools', s.SCHEMA['properties'])
        self.assertEqual(s.MODEL, 'claude-sonnet-5-5')

    def test_redirect_is_refused(self):
        with self.assertRaises(s.Stop):
            s.NoRedirect().redirect_request(None, None, 302, '', {}, 'https://attacker.invalid')


class Controller(unittest.TestCase):
    def run_controller(self, *, decision=None, failure=None, previous=None, review=None, inline=None):
        writes = []
        def api(path, method='GET', data=None, paginate=False):
            if method != 'GET':
                writes.append((path, method, data))
                if failure and failure(path, method, data):
                    raise s.Stop('Injected transport failure')
                return {'id': 100} if method == 'POST' and path.endswith('/comments') else None
            if path.endswith('/pulls/11'):
                return PULL
            raise AssertionError('Unexpected GET: ' + path)
        def paged(path):
            if path.endswith('/reviews'):
                return [review or REVIEW]
            if path.endswith('/comments') and '/reviews/' in path:
                return inline if inline is not None else [{'body': 'P1 implementation issue'}]
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
                s.run_one(PULL, 3)
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
        with patch.object(s, 'gh', return_value=PULL), patch.object(s, 'pages', return_value=[REVIEW]), patch.object(s, 'active_goal_work', return_value=True), patch.object(s.time, 'sleep'), patch.object(s, 'cursor') as api, patch.object(s, 'update_state') as write:
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
        with patch.object(s, 'retire_stale_assessment', return_value=False), patch.object(s, 'refresh_guard', side_effect=[None, s.Stop('Moved head')]), patch.object(s, 'gh'), patch.object(s, 'update_state'), patch.object(s, 'cursor') as api:
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
        with patch.dict(s.os.environ, {'GITHUB_REPOSITORY': s.REPO, 'GITHUB_REF': 'refs/heads/main', 'GITHUB_WORKFLOW_REF': s.REPO + '/.github/workflows/checkpoint-supervisor.yml@refs/heads/main', 'GH_TOKEN': 'test-token', 'CURSOR_API_KEY': 'test-cursor', 'SUPERVISOR_MAX_CHECKPOINTS': '3', 'TREMELAY_SUPERVISOR_ACTIVATION': s.ACTIVATION_VALUE}), patch.object(sys, 'argv', ['checkpoint_supervisor.py']), patch.object(s, 'gh', return_value={'login': s.AUTHOR}), patch.object(s, 'pages', side_effect=[[PULL, next_pull], [claim], []]), patch.object(s, 'recover_worker', side_effect=s.Stop('No accepted worker')), patch.object(s, 'run_one') as assess:
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

    def test_review_body_only_feedback_receives_assessment(self):
        for state in ['COMMENTED', 'CHANGES_REQUESTED']:
            review = dict(REVIEW, state=state, body='<details><summary>P1 finding</summary>Maintain a derived suspension index and cover rollback.</details>')
            writes, model, error = self.run_controller(review=review, inline=[])
            self.assertIsNone(error)
            model.assert_called_once()
            self.assertIn('"phase":"working"', writes[-1][2]['body'])

    def test_empty_clean_and_wrapper_only_reviews_do_not_consume_budget(self):
        bodies = ['', '  ',
            "Codex Review: Didn't find any major issues.\n\n**Reviewed commit:** `aaaaaaaa`",
            '### 💡 Codex Review\n\nHere are some automated review suggestions for this pull request.\n\n**Reviewed commit:** `aaaaaaaa`\n<details> <summary>ℹ️ About Codex in GitHub</summary>Help and setup instructions.</details>']
        for body in bodies:
            writes, model, error = self.run_controller(review=dict(REVIEW, body=body), inline=[])
            self.assertIsNone(error)
            model.assert_not_called()
            self.assertEqual(writes, [])

    def test_binary_or_invalid_source_fails_closed_without_exposing_bytes(self):
        for content in [base64.b64encode(b'\x89PNG\xff').decode(), 'not-base64!', None]:
            with patch.object(s, 'gh', return_value={'encoding': 'base64', 'content': content}):
                with self.assertRaisesRegex(s.Stop, '^Source evidence is not valid UTF-8 text; manual assessment required$'):
                    s.read_source('image.png', HEAD)
        with patch.object(s, 'gh', return_value={'encoding': 'base64', 'content': 'aGVs\nbG8=\n'}):
            self.assertEqual(s.read_source('text.txt', HEAD), 'hello')

    def test_binary_evidence_does_not_abort_later_prs(self):
        next_pull = dict(PULL, number=13)
        processed = []
        run_one = s.run_one
        def paged(path):
            if path.endswith('/pulls?state=open'):
                return [PULL, next_pull]
            if path.endswith('/reviews'):
                return [REVIEW]
            if '/reviews/' in path and path.endswith('/comments'):
                return [{'body': 'P1 finding'}]
            if path.endswith('/comments'):
                return []
            if path.endswith('/files'):
                return [{'filename': 'image.png', 'status': 'added'}]
            raise AssertionError(path)
        def api(path, **kwargs):
            self.assertEqual(kwargs.get('method', 'GET'), 'GET')
            if path == 'user':
                return {'login': s.AUTHOR}
            if '/git/trees/' in path:
                return {'tree': [], 'truncated': False}
            if '/contents/' in path:
                content = b'\x89PNG\xff' if '/image.png?' in path else b'Required document'
                return {'encoding': 'base64', 'content': base64.b64encode(content).decode()}
            raise AssertionError(path)
        def process(pull, limit):
            if pull['number'] == 11:
                return run_one(pull, limit)
            processed.append(pull['number'])
        with patch.dict(s.os.environ, {'GITHUB_REPOSITORY': s.REPO, 'GITHUB_REF': 'refs/heads/main', 'GITHUB_WORKFLOW_REF': s.REPO + '/.github/workflows/checkpoint-supervisor.yml@refs/heads/main', 'GH_TOKEN': 'test-token', 'CURSOR_API_KEY': 'test-cursor', 'SUPERVISOR_MAX_CHECKPOINTS': '3', 'TREMELAY_SUPERVISOR_ACTIVATION': s.ACTIVATION_VALUE}), patch.object(sys, 'argv', ['checkpoint_supervisor.py']), patch.object(s, 'gh', side_effect=api), patch.object(s, 'pages', side_effect=paged), patch.object(s, 'active_goal_work', return_value=False), patch.object(s, 'run_one', side_effect=process), patch.object(s, 'assess') as model, patch.object(s, 'cursor') as worker:
            self.assertEqual(s.main(), 1)
            self.assertEqual(processed, [13])
            model.assert_not_called()
            worker.assert_not_called()

    def test_stale_unlaunched_assessment_is_retired_for_head_or_review_change(self):
        for change in ['head', 'review', 'approval']:
            state = {'phase': 'dispatch_ready', 'head': HEAD, 'review': 4, 'decision': DECISION}
            claim = {'id': 100, 'user': {'login': s.AUTHOR}, 'body': s.state_body(state, 'Recorded assessment')}
            live = copy.deepcopy(PULL)
            review = dict(REVIEW, id=5, submitted_at='2026-10-08T06:00:00Z')
            if change == 'head':
                live['head']['sha'] = 'b' * 40
                review['commit_id'] = 'b' * 40
            elif change == 'approval':
                review['state'] = 'APPROVED'
            def api(path, method='GET', data=None, **kwargs):
                if method == 'PATCH':
                    self.assertEqual(path, f'repos/{s.REPO}/issues/comments/100')
                    claim['body'] = data['body']
                    return None
                self.assertEqual(method, 'GET')
                return {'login': s.AUTHOR} if path == 'user' else live
            def paged(path):
                if path.endswith('/pulls?state=open'):
                    return [live]
                if path.endswith('/reviews'):
                    return [review]
                if path.endswith('/comments'):
                    return [claim]
                raise AssertionError(path)
            with patch.dict(s.os.environ, {'GITHUB_REPOSITORY': s.REPO, 'GITHUB_REF': 'refs/heads/main', 'GITHUB_WORKFLOW_REF': s.REPO + '/.github/workflows/checkpoint-supervisor.yml@refs/heads/main', 'GH_TOKEN': 'test-token', 'CURSOR_API_KEY': 'test-cursor', 'SUPERVISOR_MAX_CHECKPOINTS': '3', 'TREMELAY_SUPERVISOR_ACTIVATION': s.ACTIVATION_VALUE}), patch.object(sys, 'argv', ['checkpoint_supervisor.py']), patch.object(s, 'gh', side_effect=api), patch.object(s, 'pages', side_effect=paged), patch.object(s, 'run_one') as next_assessment, patch.object(s, 'cursor') as worker:
                self.assertEqual(s.main(), 0)
                next_assessment.assert_not_called()
                retired = s.records([claim])[0][1]
                self.assertEqual(retired['phase'], 'obsolete')
                self.assertEqual(retired['head'], HEAD)
                self.assertEqual(retired['review'], 4)
                self.assertEqual(retired['decision'], DECISION)
                self.assertNotIn('agent_id', retired)
                self.assertEqual(s.main(), 0)
                next_assessment.assert_called_once_with(live, 3)
                worker.assert_not_called()

    def test_retired_assessments_still_consume_total_budget(self):
        prior = [{'user': {'login': s.AUTHOR}, 'body': s.state_body({'head': str(i) * 40, 'review': i, 'phase': 'obsolete'}, 'Retired assessment')} for i in range(3)]
        writes, model, error = self.run_controller(previous=prior)
        self.assertIsNone(error)
        model.assert_not_called()
        self.assertEqual(len(writes), 1)
        self.assertIn('total checkpoint budget', writes[0][2]['body'])

    def test_failed_retirement_does_not_release_or_launch(self):
        state = {'phase': 'dispatch_ready', 'head': HEAD, 'review': 4, 'decision': DECISION}
        claim = {'id': 100, 'body': s.state_body(state, 'Recorded assessment')}
        changed = copy.deepcopy(PULL)
        changed['head']['sha'] = 'b' * 40
        with patch.object(s, 'gh', return_value=changed), patch.object(s, 'pages', return_value=[]), patch.object(s, 'update_state', side_effect=s.Stop('Write failed')), patch.object(s, 'cursor') as worker:
            with self.assertRaises(s.Stop):
                s.dispatch_ready(changed, claim, state)
            self.assertEqual(state['phase'], 'dispatch_ready')
            worker.assert_not_called()

    def test_reserved_or_identified_worker_cannot_be_retired(self):
        for extra in [{'phase': 'dispatch_reserved'}, {'phase': 'working'}, {'agent_id': 'bc-unknown'}, {'run_id': 'run-1'}]:
            state = dict({'phase': 'dispatch_ready', 'head': HEAD, 'review': 4, 'decision': DECISION}, **extra)
            with patch.object(s, 'gh') as api, patch.object(s, 'update_state') as write:
                with self.assertRaises(s.Stop):
                    s.retire_stale_assessment(11, {'id': 100}, state)
                api.assert_not_called()
                write.assert_not_called()


    def test_timed_out_running_worker_keeps_ownership_across_new_reviews_and_heads(self):
        state = {'phase': 'working', 'agent_id': s.worker_payload(11, HEAD, 4, DECISION)['agentId'],
                 'run_id': 'run-1', 'time': '2000-01-01T00:00:00+00:00', 'head': HEAD, 'review': 4}
        claim = {'id': 100, 'user': {'login': s.AUTHOR}, 'body': s.state_body(state, 'Recorded worker')}
        writes = []
        live = copy.deepcopy(PULL)
        newer_review = dict(REVIEW, id=5, submitted_at='2026-10-08T06:00:00Z')
        def api(path, method='GET', data=None, **kwargs):
            if method == 'PATCH':
                claim['body'] = data['body']
                writes.append(data['body'])
                return None
            self.assertEqual(method, 'GET')
            return {'login': s.AUTHOR} if path == 'user' else live
        def paged(path):
            if path.endswith('/pulls?state=open'):
                return [live]
            if path.endswith('/comments'):
                return [claim]
            if path.endswith('/reviews'):
                return [newer_review]
            raise AssertionError(path)
        with patch.dict(s.os.environ, {'GITHUB_REPOSITORY': s.REPO, 'GITHUB_REF': 'refs/heads/main', 'GITHUB_WORKFLOW_REF': s.REPO + '/.github/workflows/checkpoint-supervisor.yml@refs/heads/main', 'GH_TOKEN': 'test-token', 'CURSOR_API_KEY': 'test-cursor', 'SUPERVISOR_MAX_CHECKPOINTS': '3', 'TREMELAY_SUPERVISOR_ACTIVATION': s.ACTIVATION_VALUE}), patch.object(sys, 'argv', ['checkpoint_supervisor.py']), patch.object(s, 'gh', side_effect=api), patch.object(s, 'pages', side_effect=paged), patch.object(s, 'cursor', side_effect=[{'id': state['agent_id']}, {'status': 'RUNNING'}] * 2) as worker, patch.object(s, 'run_one') as assess:
            self.assertEqual(s.main(), 0)
            live['head']['sha'] = 'b' * 40
            newer_review['commit_id'] = 'b' * 40
            self.assertEqual(s.main(), 0)
            self.assertEqual(len(writes), 1)
            saved = s.records([claim])[0][1]
            self.assertEqual(saved['phase'], 'working')
            self.assertTrue(saved['timeout_escalated'])
            self.assertEqual(saved['agent_id'], state['agent_id'])
            assess.assert_not_called()
            self.assertTrue(all(not call.kwargs for call in worker.call_args_list))

    def test_timed_out_worker_can_finish_without_a_replacement(self):
        state = {'phase': 'working', 'timeout_escalated': True,
                 'agent_id': s.worker_payload(11, HEAD, 4, DECISION)['agentId'],
                 'run_id': 'run-1', 'time': '2000-01-01T00:00:00+00:00', 'head': HEAD, 'review': 4}
        advanced = copy.deepcopy(PULL)
        advanced['head']['sha'] = 'b' * 40
        with patch.object(s, 'cursor', side_effect=[{'id': state['agent_id']}, {'status': 'FINISHED'}]) as worker, patch.object(s, 'gh', side_effect=[advanced, {'status': 'ahead'}]), patch.object(s, 'active_goal_work', return_value=False), patch.object(s, 'update_state'), patch.object(s, 'finish_review') as review:
            s.recover_worker(PULL, {'id': 100}, state)
            self.assertEqual(state['phase'], 'review_reserved')
            self.assertEqual(state['completed_head'], 'b' * 40)
            review.assert_called_once()
            self.assertTrue(all(not call.kwargs for call in worker.call_args_list))


    def test_disabled_installation_makes_no_service_calls(self):
        for activation in ['', 'true', 'reviewed-v1-d9cfdd332b6a490e9999f037f632a750', 'cursor-v2-43b97c8db2a048cba47178df2e964a2f']:
            with patch.dict(s.os.environ, {'GITHUB_REPOSITORY': s.REPO, 'TREMELAY_SUPERVISOR_ACTIVATION': activation}, clear=True), patch.object(sys, 'argv', ['checkpoint_supervisor.py']), patch.object(s, 'gh') as github, patch.object(s, 'cursor') as worker, patch.object(s, 'assess') as model:
                self.assertEqual(s.main(), 0)
                github.assert_not_called()
                worker.assert_not_called()
                model.assert_not_called()

    def test_preflight_is_read_only_and_does_not_reveal_values(self):
        from contextlib import redirect_stdout
        import io
        values = {'GITHUB_REPOSITORY': s.REPO, 'GITHUB_REF': 'refs/heads/main', 'GITHUB_WORKFLOW_REF': s.REPO + '/.github/workflows/checkpoint-supervisor.yml@refs/heads/main', 'GH_TOKEN': 'github-private-sentinel', 'CURSOR_API_KEY': 'cursor-private-sentinel'}
        output = io.StringIO()
        with patch.dict(s.os.environ, values, clear=True), patch.object(sys, 'argv', ['checkpoint_supervisor.py', '--preflight']), patch.object(s, 'gh', return_value={'login': s.AUTHOR}) as github, patch.object(s, 'cursor') as worker, patch.object(s, 'assess') as model, patch.object(s, 'authentication_preflight') as authentication, redirect_stdout(output):
            self.assertEqual(s.main(), 0)
            github.assert_called_once_with('user')
            worker.assert_not_called()
            model.assert_not_called()
            authentication.assert_called_once_with()
        self.assertIn('Release activation is disabled.', output.getvalue())
        for name in ['GH_TOKEN', 'CURSOR_API_KEY']:
            self.assertNotIn(values[name], output.getvalue())
        self.assertNotIn(s.ACTIVATION_VALUE, output.getvalue())

    def test_workflow_activation_gate_covers_every_trigger(self):
        workflow = (Path(__file__).resolve().parents[1] / '.github/workflows/checkpoint-supervisor.yml').read_text()
        condition = next(line.strip().removeprefix('if: ${{ ').removesuffix(' }}') for line in workflow.splitlines() if line.strip().startswith('if: ${{ '))
        self.assertIn(s.ACTIVATION_VALUE, condition)
        expression = condition.replace('vars.TREMELAY_SUPERVISOR_ACTIVATION', 'activation').replace('github.event_name', 'event').replace('inputs.preflight_only', 'preflight').replace('inputs.model_smoke_only', 'smoke').replace('github.workflow_ref', 'workflow_ref').replace('github.ref', 'ref').replace('&&', 'and').replace('||', 'or').replace('== true', '== True')
        trusted_workflow = s.REPO + '/.github/workflows/checkpoint-supervisor.yml@refs/heads/main'
        for event in ['schedule', 'workflow_run', 'workflow_dispatch']:
            for activation in ['', 'true', 'old-release', s.ACTIVATION_VALUE]:
                for preflight in [False, True]:
                    for smoke in [False, True]:
                        for ref in ['refs/heads/main', 'refs/heads/feature', 'refs/pull/1/merge']:
                            for workflow_ref in [trusted_workflow, trusted_workflow.replace('@refs/heads/main', '@refs/heads/feature')]:
                                allowed = eval(expression, {'__builtins__': {}}, {'activation': activation, 'event': event, 'preflight': preflight, 'smoke': smoke, 'ref': ref, 'workflow_ref': workflow_ref})
                                self.assertEqual(allowed, ref == 'refs/heads/main' and workflow_ref == trusted_workflow and (activation == s.ACTIVATION_VALUE or (event == 'workflow_dispatch' and (preflight or smoke))))
        self.assertIn('TREMELAY_SUPERVISOR_ACTIVATION: ${{ vars.TREMELAY_SUPERVISOR_ACTIVATION }}', workflow)


if __name__ == '__main__':
    unittest.main()
