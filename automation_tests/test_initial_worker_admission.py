"""Durable initial ownership and cross-workflow serialized admission, offline."""
import copy
from contextlib import ExitStack
import json
import os
from pathlib import Path
import sys
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import automation_protocol as protocol
import checkpoint_supervisor as supervisor
import goal_initial_launch as initial
import goal_lineage as lineage
import goal_review_launch as ordinary
import generic_worker as generic
from test_admission_review_regressions import WORKER_ADMISSION_JOBS, workflow_job, assert_workflow_admission
from test_goal_lineage import pull
from test_goal_review_recovery import Server as ReviewServer
from test_shared_worker_ownership import ENV as SUPERVISOR_ENV, receipt as supervisor_receipt
from test_generic_worker import plan as generic_plan, receipt as generic_receipt

ENV = dict(SUPERVISOR_ENV, TREMELAY_WORKER_ADMISSION='serialized-v1')
REPO = initial.REPO


def payload(issue=10):
    return {'name': 'Initial goal', 'prompt': {'text': 'Implement the approved issue.'},
            'repos': [{'url': f'https://github.com/{REPO}', 'startingRef': f'goal/issue-{issue}'}],
            'workOnCurrentBranch': True, 'autoCreatePR': False, 'skipReviewerRequest': True}


class Server:
    def __init__(self):
        self.issues = {10: {'number': 10, 'state': 'open'}, 12: {'number': 12, 'state': 'open'}}
        self.pulls = []
        self.comments = {}
        self.calls = []
        self.status = 'RUNNING'
        self.post_error = False
        self.lookup_error = False
        self.close_on_reserve = False
        self.agent_reads = 0
        self.mutate_agent = None

    def gh(self, path, method='GET', data=None, **kwargs):
        self.calls.append(('gh', method, path, copy.deepcopy(data)))
        if path == 'user':
            return {'login': initial.AUTHOR}
        if '/issues/comments/' in path:
            comment = next(c for rows in self.comments.values() for c in rows
                           if c['id'] == int(path.rsplit('/', 1)[1]))
            if method == 'PATCH':
                comment['body'] = data['body']
            return copy.deepcopy(comment)
        if '/issues?state=all' in path:
            return copy.deepcopy(list(self.issues.values()))
        if '/pulls?state=all' in path:
            return copy.deepcopy(self.pulls)
        if '/pulls/' in path:
            return copy.deepcopy(next(p for p in self.pulls if p['number'] == int(path.rsplit('/', 1)[1])))
        base = path.split('?', 1)[0]
        if base.endswith('/comments'):
            number = int(base.split('/')[-2])
            if method == 'POST':
                comment = {'id': 100 + sum(len(rows) for rows in self.comments.values()),
                           'body': data['body'], 'user': {'login': initial.AUTHOR},
                           'issue_url': f'https://api.github.com/repos/{REPO}/issues/{number}'}
                self.comments.setdefault(number, []).append(comment)
                if self.close_on_reserve:
                    self.issues[number]['state'] = 'closed'
                return copy.deepcopy(comment)
            return copy.deepcopy(self.comments.get(number, []))
        if '/issues/' in base:
            return copy.deepcopy(self.issues[int(base.rsplit('/', 1)[1])])
        raise AssertionError(path)

    def cursor(self, path, *, payload=None):
        self.calls.append(('cursor', 'POST' if payload is not None else 'GET', path, copy.deepcopy(payload)))
        if payload is not None:
            if self.post_error:
                raise initial.Stop('ambiguous create')
            return {'agent': {'id': payload['agentId']}, 'run': {'id': 'run-1', 'agentId': payload['agentId']}}
        if self.lookup_error:
            raise initial.Stop('404 or inaccessible')
        agent_id = path.split('/')[1]
        issue = next(n for n, rows in self.comments.items()
                     if any(initial.parse_body(c['body'], n).get('agent_id') == agent_id for c in rows))
        if '/runs/' in path:
            return {'id': 'run-1', 'agentId': agent_id, 'status': self.status}
        self.agent_reads += 1
        agent = {'id': agent_id, 'latestRunId': 'run-1', 'workOnCurrentBranch': True,
                 'repos': payload_for(issue)['repos']}
        if self.mutate_agent:
            self.mutate_agent(agent, self.agent_reads)
        return agent

    def context(self):
        stack = ExitStack()
        stack.enter_context(patch.dict(os.environ, ENV, clear=True))
        stack.enter_context(patch.object(initial, 'gh', self.gh))
        stack.enter_context(patch.object(initial, 'cursor', self.cursor))
        return stack

    def state(self, issue=10):
        return initial.parse_body(self.comments[issue][0]['body'], issue)

    def posts(self):
        return [c for c in self.calls if c[:2] == ('cursor', 'POST')]


# Avoid shadowing the cursor method's payload argument.
payload_for = payload


class InitialAdmission(unittest.TestCase):
    def test_reservation_precedes_create_and_relabel_cannot_repeat(self):
        server = Server()
        with server.context():
            result = initial.launch(10, payload())
            with self.assertRaises(RuntimeError):
                initial.launch(10, payload())
        self.assertEqual(result['state']['phase'], 'working')
        self.assertEqual(len(server.posts()), 1)
        post = next(i for i, c in enumerate(server.calls) if c[:2] == ('cursor', 'POST'))
        bodies = [c[3]['body'] for c in server.calls[:post] if c[0] == 'gh' and c[1] in {'POST', 'PATCH'}]
        self.assertEqual([initial.parse_body(b, 10)['phase'] for b in bodies], ['prepared', 'dispatch_reserved'])

    def test_two_stale_initial_label_jobs_admit_only_one_worker(self):
        for second_issue in (10, 12):
            with self.subTest(second_issue=second_issue):
                server = Server()
                admission = threading.Lock()
                both_queued = threading.Barrier(2)
                results = []
                def job(issue):
                    # Both events were queued before either obtained the actual
                    # shared Actions admission group. Exercise the real guards
                    # and reservation transition in each serialized job.
                    both_queued.wait(timeout=5)
                    with admission:
                        try:
                            initial.launch(issue, payload(issue))
                            results.append('created')
                        except RuntimeError:
                            results.append('held')
                with server.context():
                    threads = [threading.Thread(target=job, args=(n,)) for n in (10, second_issue)]
                    for thread in threads: thread.start()
                    for thread in threads: thread.join(timeout=5)
                self.assertTrue(all(not thread.is_alive() for thread in threads))
                self.assertCountEqual(results, ['created', 'held'])
                self.assertEqual(len(server.posts()), 1)

    def test_ambiguous_create_cancellation_404_and_closure_never_release_or_replay(self):
        server = Server()
        server.post_error = True
        with server.context():
            with self.assertRaises(initial.Stop): initial.launch(10, payload())
            server.issues[10]['state'] = 'closed'
            server.lookup_error = True
            for _ in range(2):
                with self.assertRaises(initial.Stop): initial.recover(10, 100)
            with self.assertRaises(initial.Stop): initial.launch(12, payload(12))
        self.assertEqual(server.state()['phase'], 'dispatch_reserved')
        self.assertEqual(len(server.posts()), 1)
        self.assertFalse(any(c[1] == 'DELETE' for c in server.calls))

    def test_precreate_failure_can_release_only_a_prepared_claim(self):
        server = Server()
        server.close_on_reserve = True
        with server.context(), self.assertRaises(RuntimeError):
            initial.launch(10, payload())
        self.assertEqual(server.state()['phase'], 'released')
        self.assertEqual(server.posts(), [])
        with server.context(), patch.dict(os.environ, TREMELAY_WORKER_ADMISSION=''):
            with self.assertRaises(initial.Stop): initial.recover(10, 100)

    def test_final_prepared_read_failure_releases_for_one_safe_later_admission(self):
        server = Server()
        original = server.gh
        failed = False
        def gh(path, **kwargs):
            nonlocal failed
            if '/issues/comments/' in path and kwargs.get('method', 'GET') == 'GET' and not failed:
                failed = True
                raise initial.Stop('Final admission read failed')
            return original(path, **kwargs)
        with server.context():
            with patch.object(initial, 'gh', gh), self.assertRaises(initial.Stop):
                initial.launch(10, payload())
            self.assertEqual(server.state()['phase'], 'released')
            self.assertEqual(server.posts(), [])
            result = initial.launch(10, payload())
            self.assertEqual(result['state']['phase'], 'working')
            self.assertEqual(len(server.posts()), 1)

    def test_initial_owner_blocks_normal_supervisor_and_generic_admission(self):
        server = Server()
        server.pulls = [pull()]
        with server.context():
            initial.launch(10, payload())
            with self.assertRaises(RuntimeError):
                lineage.guard(pr_number=11, launch=True, repository_ownership=True,
                              read=server.gh, pages=lambda p: lineage.bounded_pages(p, read=server.gh))
            with patch.object(supervisor, 'gh', server.gh), patch.object(supervisor, 'pages', initial.pages), \
                    patch.object(supervisor, 'eligible', return_value=True), \
                    patch.object(supervisor, 'wait_for_goal_idle'), patch.object(supervisor, 'cursor') as create:
                with self.assertRaises(supervisor.Stop):
                    supervisor.refresh_guard(11, 'a' * 40, 4)
                create.assert_not_called()
            server.pulls[0]['base']['repo'] = {'full_name': REPO}
            server.pulls[0]['labels'] = [{'name': 'codex-cursor-loop'}]
            with patch.object(generic, 'gh', server.gh), patch.object(generic, 'cursor') as create:
                with self.assertRaises(RuntimeError): generic.launch(generic_plan())
                create.assert_not_called()
        self.assertEqual(len(server.posts()), 1)

    def test_each_pr_worker_family_blocks_initial_admission(self):
        claims = [ReviewServer('working').claim, supervisor_receipt()[1],
                  generic_receipt(generic.prepare(generic_plan())[0])]
        for claim in claims:
            server = Server()
            server.pulls = [pull()]
            server.comments[11] = [claim]
            with self.subTest(body=claim['body'][:35]), server.context(), self.assertRaises(RuntimeError):
                initial.launch(12, payload(12))
            self.assertEqual(server.posts(), [])

    def test_terminal_receipt_binds_current_run_and_branch_and_prevents_relabel(self):
        server = Server()
        with server.context():
            initial.launch(10, payload())
            server.status = 'FINISHED'
            saved = initial.recover(10, 100)
            self.assertEqual(saved['phase'], 'terminal')
            calls = len(server.calls)
            self.assertEqual(initial.recover(10, 100), saved)
            self.assertFalse(any(c[0] == 'cursor' for c in server.calls[calls:]))
            with self.assertRaises(initial.Stop): initial.launch(10, payload())
            initial.launch(12, payload(12))
        self.assertEqual(len(server.posts()), 2)

    def test_changed_run_or_foreign_target_never_records_terminal(self):
        mutations = [lambda a, n: a.update(latestRunId='run-new'),
                     lambda a, n: a.update(latestRunId='run-new') if n == 2 else None,
                     lambda a, n: a['repos'][0].update(url='https://github.com/other/repo'),
                     lambda a, n: a['repos'][0].update(startingRef='goal/issue-12'),
                     lambda a, n: a.update(workOnCurrentBranch=False)]
        for mutate in mutations:
            server = Server()
            with server.context():
                initial.launch(10, payload())
                server.status, server.mutate_agent = 'FINISHED', mutate
                with self.assertRaises(initial.Stop): initial.recover(10, 100)
            self.assertEqual(server.state()['phase'], 'working')
            self.assertEqual(len(server.posts()), 1)

    def test_historical_open_issue_with_merged_pr_migrates_get_only(self):
        server = Server()
        server.pulls = [pull(state='closed', merged_at='2026-10-10T00:00:00Z')]
        agent_id = 'bc-00000000-0000-0000-0000-000000000001'
        server.comments[10] = [{'id': 100, 'user': {'login': initial.AUTHOR},
            'issue_url': f'https://api.github.com/repos/{REPO}/issues/10',
            'body': initial.LEGACY_PREFIX + 'https://cursor.com/agents/' + agent_id + initial.LEGACY_SUFFIX}]
        server.status = 'FINISHED'
        with server.context():
            self.assertFalse(initial.recover_all())
            self.assertEqual(server.state()['phase'], 'terminal')
            before = len(server.calls)
            self.assertFalse(initial.recover_all())
        self.assertEqual(server.posts(), [])
        self.assertFalse(any(c[0] == 'cursor' for c in server.calls[before:]))
        self.assertTrue(all(c[1] in {'GET', 'PATCH'} for c in server.calls))

    def test_unknown_receipt_does_not_starve_other_get_only_recovery(self):
        server = Server()
        with server.context():
            initial.launch(10, payload())
        second = copy.deepcopy(server.comments[10][0]); second['id'] = 101
        server.comments[10].append(second)
        with server.context(), patch.object(initial, 'recover', side_effect=[initial.Stop('unknown'), {'phase': 'terminal'}]) as recover:
            self.assertTrue(initial.recover_all())
            self.assertEqual([c.args[1] for c in recover.call_args_list], [100, 101])

    def test_malformed_trusted_receipts_fail_closed_but_evidence_is_inert(self):
        from test_legacy_control_readers import old_checkpoint
        for body in ['<!-- goal-initial-v2 {} -->', '<!-- goal-initial-v1 bad -->',
                     initial.LEGACY_PREFIX + 'https://cursor.com/agents/unknown',
                     '<!-- goal-initial',
                     *[initial.LEGACY_PREFIX.rstrip() + gap + 'https://cursor.com/agents/bc-00000000-0000-0000-0000-000000000001' + initial.LEGACY_SUFFIX
                       for gap in ['', '\t', '\n']]]:
            comment = {'id': 100, 'user': {'login': initial.AUTHOR},
                       'issue_url': f'https://api.github.com/repos/{REPO}/issues/10', 'body': body}
            with self.subTest(body=body), self.assertRaises(RuntimeError): initial.pending_claim([comment], 10)
            self.assertFalse(initial.pending_claim([dict(comment, user={'login': 'other'})], 10))
            self.assertIsNone(initial.parse_body(old_checkpoint(body), 10))
        for marker in ['<!-- goal-initial-v2 {} -->', '<!-- goal-initial', '<!-- codex-cursor-worker-v2 {} -->']:
            damaged = old_checkpoint(marker).rsplit('<!-- tremelay-cycle-stop', 1)[0] + marker
            with self.assertRaises(protocol.AmbiguousCheckpoint): protocol.is_checkpoint_evidence(damaged)


class RetiredSourceRecovery(unittest.TestCase):
    def test_open_goal_pr_with_closed_source_or_merged_lineage_recovers_without_paid_work(self):
        for retirement in ('closed', 'merged'):
            server = ReviewServer('working', 'FINISHED')
            original_gh = server.gh
            def gh(path, **kwargs):
                if path == f'repos/{REPO}/issues/10':
                    return {'number': 10, 'state': 'closed' if retirement == 'closed' else 'open'}
                if '/pulls?state=all' in path:
                    history = [server.pull]
                    if retirement == 'merged': history.append(pull(9, state='closed', merged_at='2026-10-10T00:00:00Z'))
                    return copy.deepcopy(history)
                return original_gh(path, **kwargs)
            def pages(path):
                if '/pulls?state=all' in path: return [server.pull]
                if path.endswith('/comments'): return [copy.deepcopy(server.claim)]
                raise AssertionError(path)
            # The live lineage check uses the same fresh all-state history.
            def live(p, **kwargs):
                try: lineage.ensure_open_lineage(10, read=gh, pages=lambda path: gh(path))
                except lineage.LineageStop as error: raise supervisor.Stop(str(error))
            with self.subTest(retirement=retirement), patch.dict(os.environ, ENV, clear=True), \
                    patch.object(sys, 'argv', ['supervisor']), patch.object(initial, 'recover_all', return_value=False), \
                    patch.object(supervisor, 'gh', gh), patch.object(supervisor, 'pages', pages), \
                    patch.object(supervisor, 'live_lineage', live), patch.object(ordinary, 'gh', gh), \
                    patch.object(ordinary, 'cursor', server.cursor), patch.object(supervisor, 'assess') as assess, \
                    patch.object(supervisor, 'cursor') as create, patch.object(supervisor, 'run_one') as run:
                self.assertEqual(supervisor.main(), 0)
                self.assertEqual(server.saved()['phase'], 'retired')
                assess.assert_not_called(); create.assert_not_called(); run.assert_not_called()
                self.assertEqual(server.posts(), [])
                self.assertEqual(len(server.cursor_calls), 3)

    def run_completion_scan(self, server, gh=None):
        def pages(path):
            if '/pulls?state=all' in path: return [copy.deepcopy(server.pull)]
            if path.endswith('/comments'): return [copy.deepcopy(server.claim)]
            if path.endswith('/reviews'): return []
            raise AssertionError(path)
        with patch.dict(os.environ, ENV, clear=True), patch.object(sys, 'argv', ['supervisor']), \
                patch.object(initial, 'recover_all', return_value=False), \
                patch.object(supervisor, 'gh', gh or server.gh), patch.object(supervisor, 'pages', pages), \
                patch.object(ordinary, 'gh', gh or server.gh), patch.object(ordinary, 'cursor', server.cursor), \
                patch.object(supervisor, 'assess') as model, patch.object(supervisor, 'cursor') as create:
            result = supervisor.main()
            model.assert_not_called(); create.assert_not_called()
            return result

    def test_displaced_completion_job_finishes_once_across_duplicate_wakes(self):
        server = ReviewServer('working', 'FINISHED')
        self.assertEqual(self.run_completion_scan(server), 0)
        self.assertEqual(server.saved()['phase'], 'completed')
        self.assertEqual(len(server.posts()), 1)
        calls = len(server.cursor_calls)
        self.assertEqual(self.run_completion_scan(server), 0)
        self.assertEqual(len(server.posts()), 1)
        self.assertEqual(len(server.cursor_calls), calls)

    def test_ambiguous_review_completion_deduplicates_existing_request(self):
        server = ReviewServer('working', 'FINISHED')
        server.post_error = True
        self.assertEqual(self.run_completion_scan(server), 1)
        self.assertEqual(server.saved()['phase'], 'review_reserved')
        self.assertEqual(len(server.posts()), 1)
        server.post_error = False
        self.assertEqual(self.run_completion_scan(server), 0)
        self.assertEqual(server.saved()['phase'], 'completed')
        self.assertEqual(len(server.posts()), 1)

    def test_changed_head_after_review_reservation_never_requests_stale_review(self):
        server = ReviewServer('working', 'FINISHED')
        server.before_post_head = 'c' * 40
        self.assertEqual(self.run_completion_scan(server), 1)
        self.assertEqual(server.saved()['phase'], 'review_reserved')
        self.assertEqual(server.posts(), [])

    def test_revoked_goal_or_source_during_terminal_lookup_is_status_only(self):
        for change in ('labels', 'source'):
            server = ReviewServer('working', 'FINISHED')
            original_cursor, original_gh = server.cursor, server.gh
            revoked = False
            def cursor(path, **kwargs):
                nonlocal revoked
                result = original_cursor(path, **kwargs)
                if '/runs/' in path:
                    revoked = True
                    if change == 'labels': server.pull['labels'] = [{'name': 'human-review-required'}]
                return result
            def gh(path, **kwargs):
                if change == 'source' and revoked and path == f'repos/{REPO}/issues/10':
                    return {'number': 10, 'state': 'closed'}
                return original_gh(path, **kwargs)
            server.cursor = cursor
            with self.subTest(change=change):
                self.assertEqual(self.run_completion_scan(server, gh), 0)
                self.assertEqual(server.saved()['phase'], 'retired')
                self.assertEqual(server.posts(), [])

    def test_shared_lock_allows_retired_modern_prepared_release(self):
        server = ReviewServer('prepared')
        with patch.dict(os.environ, ENV), patch.object(ordinary, 'gh', server.gh), patch.object(ordinary, 'cursor') as cursor:
            self.assertFalse(supervisor.recover_ordinary_receipts(server.pull, [server.claim]))
            self.assertEqual(server.claim['body'], ordinary.released_body())
            cursor.assert_not_called()

    def test_queued_goals_do_not_deadlock_fixed_admission_but_old_contract_stays_conservative(self):
        with patch.dict(os.environ, ENV, clear=True), patch.object(supervisor, 'gh') as gh:
            self.assertFalse(supervisor.active_goal_work(11, 'a' * 40))
            gh.assert_not_called()
        with patch.dict(os.environ, dict(ENV, TREMELAY_WORKER_ADMISSION='unknown'), clear=True), \
                patch.object(supervisor, 'gh', return_value=[{'workflow_runs': [{'status': 'queued'}]}]):
            self.assertTrue(supervisor.active_goal_work(11, 'a' * 40))
        with patch.dict(os.environ, dict(ENV, GITHUB_WORKFLOW_REF='feature'), clear=True):
            with self.assertRaises(supervisor.Stop): supervisor.active_goal_work(11, 'a' * 40)

    def test_actual_jobs_share_admission_across_every_create_and_recovery_entry(self):
        self.assertEqual(sum(map(len, WORKER_ADMISSION_JOBS.values())), 6)
        for filename in WORKER_ADMISSION_JOBS:
            workflow = (ROOT / '.github/workflows' / filename).read_text()
            with self.subTest(workflow=filename):
                assert_workflow_admission(self, workflow, filename)
        goal = (ROOT / '.github/workflows/goal.yml').read_text()
        implement = goal.split('  implement:', 1)[1].split('  publish:', 1)[0]
        self.assertNotIn('curl ', implement)
        self.assertIn('goal_initial_launch.py launch', implement)
        self.assertLess(implement.index('goal_initial_launch.py recover'), implement.index('apply-sync'))

    def test_each_actual_job_requires_its_own_queue_and_admission_environment(self):
        for filename, jobs in WORKER_ADMISSION_JOBS.items():
            workflow = (ROOT / '.github/workflows' / filename).read_text()
            for name in jobs:
                job = workflow_job(workflow, name)
                indent = 10 if filename == 'checkpoint-supervisor.yml' else 6
                admission = ' ' * indent + 'TREMELAY_WORKER_ADMISSION: serialized-v1'
                self.assertEqual(workflow.count(job), 1)
                self.assertIn(admission, job)
                mutations = [
                    job.replace('      queue: max\n', ''),
                    job.replace('queue: max', 'queue: single'),
                    job.replace(admission, ''),
                    job.replace(admission, admission.replace('serialized-v1', 'unknown')),
                    job.replace(admission, admission + '\n' + admission),
                    job.replace(admission, '  ' + admission),
                    job.replace(admission, admission.replace('serialized-v1', '"serialized-v1"')),
                    job.replace(admission, admission.replace('TREMELAY_WORKER_ADMISSION', '"TREMELAY_WORKER_ADMISSION"')),
                ]
                if filename == 'checkpoint-supervisor.yml':
                    mutations.append('    env:\n      TREMELAY_WORKER_ADMISSION: serialized-v1\n' + job.replace(admission, ''))
                else:
                    mutations.append(job.replace(admission, '') + '\n    steps:\n      - name: Other\n'
                                     '        env:\n          TREMELAY_WORKER_ADMISSION: serialized-v1\n')
                for changed in mutations:
                    with self.subTest(workflow=filename, job=name, mutation=changed), self.assertRaises(AssertionError):
                        assert_workflow_admission(self, workflow.replace(job, changed), filename)

    def test_workflow_lock_cannot_absorb_job_queue_or_change_wake_coalescing(self):
        filename = 'checkpoint-supervisor.yml'
        workflow = (ROOT / '.github/workflows' / filename).read_text()
        top_lock = 'concurrency:\n  group: tremelay-checkpoint-supervisor\n  cancel-in-progress: false\n'
        self.assertIn(top_lock, workflow)
        mutations = [
            '',
            top_lock + '  queue: max\n',
            top_lock.replace('cancel-in-progress: false', 'cancel-in-progress: true'),
            top_lock.replace('tremelay-checkpoint-supervisor', 'tremelay-worker-admission'),
            top_lock.replace('tremelay-checkpoint-supervisor', '"tremelay-worker-admission"'),
            top_lock.replace('tremelay-checkpoint-supervisor', "'tremelay-worker-admission'"),
        ]
        for changed in mutations:
            with self.subTest(lock=changed), self.assertRaises(AssertionError):
                assert_workflow_admission(self, workflow.replace(top_lock, changed), filename)


class RealInitialWorkflow(unittest.TestCase):
    def test_actual_initial_launch_shell_cannot_repeat_ambiguous_create(self):
        workflow = (ROOT / '.github/workflows/goal.yml').read_text()
        job = workflow.split('  implement:', 1)[1].split('  publish:', 1)[0]
        step = job.split('      - name: Launch Cloud Agent\n', 1)[1].split('      - name:', 1)[0]
        script = '\n'.join(line[10:] for line in step.split('        run: |\n', 1)[1].splitlines())
        script = script.replace('${{ github.event.issue.number }}', '10')
        wrapper = r'''#!PYTHON
import json, os, pathlib, sys
sys.path.insert(0, TESTS)
from test_initial_worker_admission import Server, initial, lineage
if sys.argv[1] == '-c':
    os.execv(sys.executable, [sys.executable] + sys.argv[1:])
server = Server()
store = pathlib.Path('mock-server.json')
if store.exists():
    saved = json.loads(store.read_text())
    server.comments = {int(k):v for k,v in saved['comments'].items()}
    server.calls = [tuple(c) for c in saved['calls']]
server.post_error = True
result = 1
try:
    with server.context():
        if sys.argv[1].endswith('goal_initial_launch.py'):
            result = initial.main(sys.argv[2:])
        elif sys.argv[1].endswith('goal_lineage.py'):
            original = lineage.guard
            lineage.guard = lambda **kwargs: original(read=server.gh, pages=initial.pages, **kwargs)
            result = lineage.main(sys.argv[2:])
        else:
            raise AssertionError(sys.argv)
except RuntimeError:
    pass
finally:
    store.write_text(json.dumps({'comments':server.comments,'calls':server.calls}))
raise SystemExit(result)
'''.replace('PYTHON', sys.executable).replace('TESTS', repr(str(ROOT / 'automation_tests')))
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            (temp / 'scripts').symlink_to(ROOT / 'scripts', target_is_directory=True)
            (temp / 'payload.json').write_text(json.dumps(payload()))
            bindir = temp / 'bin'; bindir.mkdir()
            executable = bindir / 'python'; executable.write_text(wrapper); executable.chmod(0o755)
            git = bindir / 'git'
            git.write_text('#!/bin/bash\nif [ "$1" = rev-parse ]; then echo ' + 'a' * 40 + '; fi\n')
            git.chmod(0o755)
            env = dict(ENV, PATH=str(bindir) + os.pathsep + os.defpath, GOAL_GITHUB_TOKEN='offline')
            for _ in range(2):
                result = subprocess.run(['/bin/bash', '-c', script], cwd=temp, env=env,
                                        text=True, capture_output=True, timeout=10)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            saved = json.loads((temp / 'mock-server.json').read_text())
            self.assertEqual(sum(c[:2] == ['cursor', 'POST'] for c in saved['calls']), 1)
            state = initial.parse_body(saved['comments']['10'][0]['body'], 10)
            self.assertEqual(state['phase'], 'dispatch_reserved')


if __name__ == '__main__':
    unittest.main()
