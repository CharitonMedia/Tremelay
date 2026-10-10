"""Safe observed metadata never relaxes a failed worker association check."""
import copy
import io
import json
from contextlib import redirect_stderr
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import checkpoint_supervisor as supervisor
import goal_initial_launch as initial
from test_goal_review_recovery import PULL
from test_shared_worker_ownership import ENV

AGENT = 'bc-00000000-0000-0000-0000-000000000001'
RUN = 'run-00000000-0000-0000-0000-000000000002'
PREFIX = 'Worker target mismatch (unverified snapshot): '
SECRET = 'private_credential_a783cc41851b43958e9bc1e019c48af0'


def fixture(other_pr=23):
    state = {'agent_id': AGENT, 'run_id': RUN, 'phase': 'working', 'head': 'a' * 40,
             'review': 4, 'time': '2026-10-10T00:00:00+00:00'}
    agent = {'id': AGENT, 'latestRunId': RUN, 'workOnCurrentBranch': True,
             'repos': [{'url': f'https://github.com/{supervisor.REPO}',
                        'prUrl': f'https://github.com/{supervisor.REPO}/pull/22'}]}
    run = {'id': RUN, 'agentId': AGENT, 'status': 'FINISHED',
           'git': {'branches': [{'repoUrl': f'github.com/{supervisor.REPO}',
                                'branch': 'goal/issue-21',
                                'prUrl': f'https://github.com/{supervisor.REPO}/pull/{other_pr}'}]}}
    pull = copy.deepcopy(PULL)
    pull.update(number=22, state='closed', merged_at='2026-10-10T04:05:00Z', body='Goal-Issue: #21')
    pull['head']['ref'] = 'goal/issue-21'
    comment = {'id': 100, 'user': {'login': supervisor.AUTHOR},
               'issue_url': f'https://api.github.com/repos/{supervisor.REPO}/issues/22',
               'body': supervisor.state_body(state, 'Existing worker receipt')}
    return state, agent, run, pull, comment


class WorkerTargetDiagnostic(unittest.TestCase):
    def parse_output(self, text):
        lines = [line for line in text.splitlines() if line.startswith(PREFIX)]
        self.assertEqual(len(lines), 1)
        return json.loads(lines[0][len(PREFIX):])

    def test_automatic_closed_pr_failure_reports_snapshot_and_keeps_ownership(self):
        state, agent, run, pull, comment = fixture()
        before = copy.deepcopy(comment)
        stderr = io.StringIO()
        def pages(path):
            if path.endswith('/pulls?state=all'): return [pull]
            if path.endswith('/issues/22/comments'): return [comment]
            raise AssertionError(path)
        with patch.dict(supervisor.os.environ, dict(ENV, TREMELAY_WORKER_ADMISSION='serialized-v1'), clear=True), \
                patch.object(sys, 'argv', ['supervisor']), patch.object(initial, 'recover_all', return_value=False), \
                patch.object(supervisor, 'gh', return_value={'login': supervisor.AUTHOR}) as github, \
                patch.object(supervisor, 'pages', pages), patch.object(supervisor, 'cursor', side_effect=[agent, run]) as cursor, \
                patch.object(supervisor, 'update_state') as update, patch.object(supervisor, 'assess') as model, \
                patch.object(supervisor, 'finish_review') as review, redirect_stderr(stderr):
            self.assertEqual(supervisor.main(), 1)
        observed = self.parse_output(stderr.getvalue())
        self.assertEqual(observed['expected_repository'], supervisor.REPO)
        self.assertEqual(observed['expected_pr'], 22)
        self.assertEqual(observed['expected_goal_branch'], 'goal/issue-21')
        self.assertEqual(observed['recorded_agent_id'], AGENT)
        self.assertEqual(observed['recorded_run_id'], RUN)
        self.assertEqual(observed['observed_status'], 'FINISHED')
        self.assertEqual(observed['observed_work_on_current_branch'], 'true')
        self.assertEqual(observed['agent_repositories'][0]['pr']['number'], 22)
        self.assertEqual(observed['pushed_branches'][0], {
            'repository': supervisor.REPO, 'pr': {'repository': supervisor.REPO, 'number': 23},
            'goal_branch': 'goal/issue-21'})
        self.assertIn('Legacy worker branch evidence targets another repository or PR', stderr.getvalue())
        self.assertEqual(comment, before)
        self.assertTrue(supervisor.supervisor_owns_work(supervisor.records([comment])[0][1]))
        self.assertEqual(cursor.call_count, 2)  # Failure precedes the terminal latest-run recheck.
        self.assertTrue(all(not call.kwargs for call in cursor.call_args_list))
        self.assertEqual([call.args[0] for call in github.call_args_list],
                         ['user', f'repos/{supervisor.REPO}/pulls/22'])
        update.assert_not_called(); model.assert_not_called(); review.assert_not_called()

    def test_secret_shaped_provider_fields_never_reach_the_failure_log(self):
        state, agent, run, pull, comment = fixture()
        agent.update(prompt=SECRET, authorization=SECRET, result=SECRET, workOnCurrentBranch=SECRET)
        agent['repos'][0].update(extra=SECRET, startingRef=SECRET)
        run.update(result=SECRET, prompt={'text': SECRET}, token=SECRET)
        run['git']['branches'] = [{'repoUrl': f'github.com/{SECRET}/private-repo',
                                  'prUrl': f'https://github.com/{SECRET}/private-repo/pull/23',
                                  'branch': SECRET, 'credentials': SECRET}]
        stderr = io.StringIO()
        with patch.object(supervisor, 'cursor', side_effect=[agent, run]), \
                patch.object(supervisor, 'update_state') as update, redirect_stderr(stderr), \
                self.assertRaises(supervisor.Stop):
            supervisor.recover_worker(pull, comment, state, reconcile_only=True)
        text = stderr.getvalue()
        self.assertNotIn(SECRET, text)
        self.assertNotIn('private-repo', text)
        self.assertNotIn('https://', text)
        self.assertNotIn('credentials', text)
        branch = self.parse_output(text)['pushed_branches'][0]
        self.assertEqual(branch['repository'], 'foreign_repository')
        self.assertEqual(branch['pr'], {'repository': 'foreign_repository', 'number': 23})
        self.assertEqual(branch['goal_branch'], 'unrecognized_branch')
        self.assertEqual(state['phase'], 'working')
        update.assert_not_called()

    def test_branch_ownership_flag_uses_typed_categories_without_accepting_mismatches(self):
        cases = [({}, 'missing'), ({'workOnCurrentBranch': False}, 'false')]
        cases.extend(({'workOnCurrentBranch': value}, 'unrecognized')
                     for value in [None, 0, 1, 'true', 'false', SECRET, [], {}])
        for fields, category in cases:
            with self.subTest(fields=fields):
                state, agent, run, pull, comment = fixture(other_pr=22)
                before = copy.deepcopy(state)
                agent.pop('workOnCurrentBranch')
                agent.update(fields)
                stderr = io.StringIO()
                with patch.object(supervisor, 'cursor', side_effect=[agent, run]) as cursor, \
                        patch.object(supervisor, 'update_state') as update, redirect_stderr(stderr), \
                        self.assertRaisesRegex(supervisor.Stop, 'repository or branch ownership is unverified'):
                    supervisor.recover_worker(pull, comment, state, reconcile_only=True)
                observed = self.parse_output(stderr.getvalue())
                self.assertEqual(observed['observed_work_on_current_branch'], category)
                self.assertNotIn(SECRET, stderr.getvalue())
                self.assertEqual(state, before)
                self.assertTrue(supervisor.supervisor_owns_work(state))
                self.assertEqual(cursor.call_count, 2)
                update.assert_not_called()

    def test_only_bounded_canonical_pr_urls_and_goal_branches_are_emitted(self):
        state, agent, run, _, _ = fixture()
        urls = [f'https://github.com/{supervisor.REPO}/pull/23?token={SECRET}',
                f'https://github.com/{supervisor.REPO}/pull/23#{SECRET}',
                f'https://{SECRET}@github.com/{supervisor.REPO}/pull/23',
                f'https://github.com.evil.test/{supervisor.REPO}/pull/23',
                f'https://github.com/{supervisor.REPO}/pull/023',
                f'https://github.com/{supervisor.REPO}/pull/' + '1' * 1000]
        for url in urls:
            run['git']['branches'][0].update(prUrl=url, branch='goal/issue-21\n' + SECRET)
            with self.subTest(url=url[:60]):
                data = supervisor.worker_target_diagnostic(22, state, agent, run, 'goal/issue-' + '1' * 1000)
                self.assertEqual(data['pushed_branches'][0]['pr'], 'unrecognized_pr')
                self.assertEqual(data['pushed_branches'][0]['goal_branch'], 'unrecognized_branch')
                self.assertEqual(data['expected_goal_branch'], 'unrecognized_branch')
                self.assertNotIn(SECRET, json.dumps(data))

    def test_unexpected_types_and_non_uuid_ids_use_fixed_categories(self):
        state, agent, run, _, _ = fixture()
        state.update(agent_id=SECRET, run_id='run-' + SECRET)
        agent['repos'] = [None, SECRET, {}, {'url': [SECRET], 'prUrl': {'secret': SECRET}, 'startingRef': True}]
        run.update(status=SECRET, git={'branches': [False, {}, {'repoUrl': SECRET, 'branch': SECRET}]})
        data = supervisor.worker_target_diagnostic(True, state, agent, run, SECRET)
        self.assertEqual(data['expected_pr'], 'unrecognized_pr')
        self.assertEqual(data['recorded_agent_id'], 'unrecognized_uuid')
        self.assertEqual(data['recorded_run_id'], 'unrecognized_uuid')
        self.assertEqual(data['observed_status'], 'unrecognized_status')
        self.assertNotIn(SECRET, json.dumps(data))
        for status in supervisor.WORKER_TERMINAL_STATUSES | {'CREATING', 'RUNNING'}:
            run['status'] = status
            self.assertEqual(supervisor.worker_target_diagnostic(22, {}, {}, run)['observed_status'], status)

    def test_diagnostic_record_count_and_output_size_are_bounded(self):
        state, agent, run, _, _ = fixture()
        agent['repos'] *= 10000
        run['git']['branches'] *= 10000
        data = supervisor.worker_target_diagnostic(22, state, agent, run, 'goal/issue-21')
        for name in ['agent_repositories', 'pushed_branches']:
            self.assertEqual(len(data[name]), 9)
            self.assertEqual(data[name][-1], 'additional_records_omitted')
        self.assertLess(len(json.dumps(data)), 4000)

    def test_success_still_requires_latest_run_recheck_and_has_no_diagnostic(self):
        state, agent, run, _, _ = fixture(other_pr=22)
        stderr = io.StringIO()
        with patch.object(supervisor, 'cursor', side_effect=[agent, run, agent]) as cursor, redirect_stderr(stderr):
            self.assertEqual(supervisor.verified_worker_run(22, state), (RUN, 'FINISHED', None))
        self.assertEqual(stderr.getvalue(), '')
        self.assertEqual(cursor.call_count, 3)

    def test_second_association_failure_reports_the_rechecked_agent(self):
        state, agent, run, _, _ = fixture(other_pr=22)
        current = copy.deepcopy(agent)
        current['repos'][0]['prUrl'] = f'https://github.com/{supervisor.REPO}/pull/23'
        stderr = io.StringIO()
        with patch.object(supervisor, 'cursor', side_effect=[agent, run, current]) as cursor, redirect_stderr(stderr), \
                self.assertRaisesRegex(supervisor.Stop, 'targets another PR'):
            supervisor.verified_worker_run(22, state)
        data = self.parse_output(stderr.getvalue())
        self.assertEqual(data['agent_repositories'][0]['pr']['number'], 23)
        self.assertEqual(data['pushed_branches'][0]['pr']['number'], 22)
        self.assertEqual(cursor.call_count, 3)
        self.assertEqual(state['phase'], 'working')

    def test_identity_failure_never_formats_unverified_provider_identity(self):
        state, agent, run, _, _ = fixture()
        agent['id'] = SECRET
        stderr = io.StringIO()
        with patch.object(supervisor, 'cursor', return_value=agent) as cursor, redirect_stderr(stderr), \
                self.assertRaisesRegex(supervisor.Stop, 'different worker identity'):
            supervisor.verified_worker_run(22, state)
        self.assertEqual(stderr.getvalue(), '')
        self.assertEqual(cursor.call_count, 1)


if __name__ == '__main__':
    unittest.main()
