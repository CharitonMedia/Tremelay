"""Review findings reproduced against both the previous and corrected trees."""
import copy
import os
import re
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import checkpoint_supervisor as supervisor

REPO = supervisor.REPO
ENV = {'GITHUB_REPOSITORY': REPO, 'GITHUB_REF': 'refs/heads/main',
       'GITHUB_WORKFLOW_REF': REPO + '/.github/workflows/checkpoint-supervisor.yml@refs/heads/main',
       'GH_TOKEN': 'offline', 'CURSOR_API_KEY': 'offline',
       'TREMELAY_SUPERVISOR_ACTIVATION': supervisor.ACTIVATION_VALUE}

WORKER_ADMISSION_JOBS = {
    'goal.yml': ['implement', 'review-launch', 'recover-review', 'request-codex'],
    'checkpoint-supervisor.yml': ['supervise'],
    'codex-cursor-remediation.yml': ['remediate'],
}


def workflow_block(text, header, indent, *, required=True):
    """Read one canonical indentation-scoped block, not general YAML."""
    lines = text.splitlines()
    matches = [i for i, line in enumerate(lines) if line == ' ' * indent + header]
    if header.endswith(':'):
        key = re.escape(header[:-1])
        intended = [i for i, line in enumerate(lines)
                    if re.match(r' {' + str(indent) + r'}[\"\']?' + key + r'[\"\']?\s*:', line)]
        if intended != matches:
            raise AssertionError('Expected canonical block header, without inline or quoted overrides')
    if not matches and not required:
        return ''
    if len(matches) != 1:
        raise AssertionError(f'Expected one {header!r} block at indent {indent}')
    start = matches[0] + 1
    end = start
    while end < len(lines):
        line = lines[end]
        if line.strip() and not line.lstrip().startswith('#'):
            if len(line) - len(line.lstrip(' ')) <= indent:
                break
        end += 1
    return '\n'.join(lines[start:end])


def workflow_fields(block, indent):
    """Require direct, unique scalar fields in the checked canonical block."""
    fields = {}
    for line in block.splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        match = re.fullmatch(r' {' + str(indent) + r'}([A-Za-z][A-Za-z0-9_-]*): (.+)', line)
        if match is None or match[1] in fields:
            raise AssertionError('Expected unique direct workflow fields')
        fields[match[1]] = match[2]
    return fields


def workflow_job(workflow, name):
    return workflow_block(workflow_block(workflow, 'jobs:', 0), name + ':', 2)


def assert_worker_concurrency(test, job):
    test.assertEqual(workflow_fields(workflow_block(job, 'concurrency:', 4), 6),
                     {'group': 'tremelay-worker-admission', 'cancel-in-progress': 'false', 'queue': 'max'})


def assert_workflow_admission(test, workflow, filename):
    top_lock = workflow_fields(workflow_block(workflow, 'concurrency:', 0, required=False), 2)
    expected_top = ({'group': 'tremelay-checkpoint-supervisor', 'cancel-in-progress': 'false'}
                    if filename == 'checkpoint-supervisor.yml' else {})
    test.assertEqual(top_lock, expected_top)
    for name in WORKER_ADMISSION_JOBS[filename]:
        job = workflow_job(workflow, name)
        assert_worker_concurrency(test, job)
        job_env = workflow_fields(workflow_block(job, 'env:', 4, required=False), 6)
        admission = job_env.get('TREMELAY_WORKER_ADMISSION')
        if filename == 'checkpoint-supervisor.yml':
            step = workflow_block(workflow_block(job, 'steps:', 4), '- name: Assess stopped goal PRs', 6)
            admission = workflow_fields(workflow_block(step, 'env:', 8), 10).get('TREMELAY_WORKER_ADMISSION')
            test.assertNotIn('TREMELAY_WORKER_ADMISSION', job_env)
        test.assertEqual(admission, 'serialized-v1')


class ReviewFindings(unittest.TestCase):
    def test_initial_create_uses_durable_reservation(self):
        text = (ROOT / '.github/workflows/goal.yml').read_text()
        job = text.split('  implement:', 1)[1].split('  publish:', 1)[0]
        self.assertIn('goal_initial_launch.py launch', job)
        self.assertNotIn('curl --fail-with-body', job)

    def test_every_create_entry_uses_same_serialized_job_group(self):
        for path, names in WORKER_ADMISSION_JOBS.items():
            workflow = (ROOT / '.github/workflows' / path).read_text()
            for name in names:
                with self.subTest(workflow=path, job=name):
                    assert_worker_concurrency(self, workflow_job(workflow, name))

    def test_open_goal_with_retired_source_still_reconciles_ordinary_receipt(self):
        pull = {'number': 11, 'state': 'open', 'draft': False, 'merged_at': None,
                'user': {'login': supervisor.AUTHOR},
                'head': {'sha': 'a' * 40, 'ref': 'goal/issue-10', 'repo': {'full_name': REPO}},
                'base': {'ref': 'main'}, 'body': 'Goal-Issue: #10', 'labels': [{'name': 'goal'}]}
        receipt = {'id': 100, 'user': {'login': supervisor.AUTHOR},
                   'issue_url': f'https://api.github.com/repos/{REPO}/issues/11',
                   'body': 'A cloud agent is working through the review findings: '
                           'https://cursor.com/agents/bc-00000000-0000-0000-0000-000000000001'}
        import goal_review_launch as ordinary
        with patch.dict(os.environ, ENV, clear=True), patch.object(sys, 'argv', ['supervisor']), \
                patch.object(supervisor, 'gh', return_value={'login': supervisor.AUTHOR}), \
                patch.object(supervisor, 'pages', side_effect=[[copy.deepcopy(pull)], [receipt]]), \
                patch.object(supervisor, 'live_lineage', side_effect=supervisor.Stop('Source issue closed')), \
                patch.object(ordinary, 'recover') as recover, patch.object(supervisor, 'assess') as model:
            self.assertEqual(supervisor.main(), 0)
            recover.assert_called_once_with(REPO, 11, 100, reconcile_only=True, legacy_only=True)
            model.assert_not_called()


class WorkflowScopes(unittest.TestCase):
    def test_other_job_workflow_or_step_cannot_supply_a_missing_job_lock(self):
        lock = 'concurrency:\n  group: tremelay-worker-admission\n  cancel-in-progress: false\n  queue: max\n'
        for misplaced in [lock, '  other:\n' + '\n'.join('    ' + line for line in lock.splitlines()),
                          '  target:\n    steps:\n      - name: Nested\n' + '\n'.join('        ' + line for line in lock.splitlines())]:
            if misplaced.startswith('concurrency:'):
                workflow = misplaced + 'jobs:\n  target:\n    runs-on: ubuntu-latest\n'
            elif misplaced.startswith('  other:'):
                workflow = 'jobs:\n' + misplaced + '\n  target:\n    runs-on: ubuntu-latest\n'
            else:
                workflow = 'jobs:\n' + misplaced
            with self.subTest(workflow=workflow), self.assertRaises(AssertionError):
                assert_worker_concurrency(self, workflow_job(workflow, 'target'))

    def test_step_admission_cannot_be_supplied_by_another_step(self):
        workflow = ('jobs:\n  supervise:\n    steps:\n'
                    '      - name: Assess stopped goal PRs\n        run: controller\n'
                    '      - name: Other\n        env:\n          TREMELAY_WORKER_ADMISSION: serialized-v1\n')
        job = workflow_job(workflow, 'supervise')
        step = workflow_block(workflow_block(job, 'steps:', 4), '- name: Assess stopped goal PRs', 6)
        with self.assertRaises(AssertionError):
            workflow_block(step, 'env:', 8)

    def test_optional_headers_reject_inline_quoted_or_duplicate_overrides(self):
        for text in ['concurrency: tremelay-worker-admission',
                     '"concurrency":\n  group: tremelay-worker-admission',
                     "'concurrency':\n  group: tremelay-worker-admission",
                     'concurrency:\n  group: other\nconcurrency: tremelay-worker-admission']:
            with self.subTest(text=text), self.assertRaises(AssertionError):
                workflow_block(text, 'concurrency:', 0, required=False)
        self.assertEqual(workflow_block('jobs:\n  test:\n    steps: []', 'env:', 0, required=False), '')

    def test_queue_must_be_on_the_target_job_concurrency(self):
        lock = '    concurrency:\n      group: tremelay-worker-admission\n      cancel-in-progress: false\n'
        target = '  target:\n' + lock
        misplaced = [
            'concurrency:\n  queue: max\njobs:\n' + target,
            'jobs:\n  other:\n' + lock + '      queue: max\n' + target,
            'jobs:\n' + target + '    steps:\n      - name: Nested\n        concurrency:\n          queue: max\n',
            'jobs:\n' + target + '    queue: max\n',
        ]
        for workflow in misplaced:
            with self.subTest(workflow=workflow), self.assertRaises(AssertionError):
                assert_worker_concurrency(self, workflow_job(workflow, 'target'))

    def test_noncanonical_fields_or_single_pending_admission_fail(self):
        lock = ('    concurrency:\n      group: tremelay-worker-admission\n'
                '      cancel-in-progress: false\n      queue: max\n')
        assert_worker_concurrency(self, lock)
        mutations = [
            lock.replace('      queue: max\n', ''),
            lock.replace('queue: max', 'queue: single'),
            lock.replace('group: tremelay-worker-admission', 'group: other'),
            lock.replace('cancel-in-progress: false', 'cancel-in-progress: true'),
            lock.replace('    concurrency:', '    concurrency: {queue: max}'),
            lock + lock,
        ]
        for key, value in [('group', 'tremelay-worker-admission'), ('cancel-in-progress', 'false'), ('queue', 'max')]:
            field = f'      {key}: {value}\n'
            mutations.extend([
                lock.replace(field, field + field),
                lock.replace(field, '  ' + field),
                lock.replace(field, field[2:]),
                lock.replace(field, f'      {key}: {{{value}}}\n'),
            ])
            for quote in ['"', "'"]:
                mutations.extend([
                    lock.replace(field, f'      {quote}{key}{quote}: {value}\n'),
                    lock.replace(field, f'      {key}: {quote}{value}{quote}\n'),
                ])
        for job in mutations:
            with self.subTest(job=job), self.assertRaises(AssertionError):
                assert_worker_concurrency(self, job)


if __name__ == '__main__':
    unittest.main()
