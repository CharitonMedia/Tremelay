"""Exact review regressions for unknown ownership envelopes and branch races."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import automation_protocol as protocol
import checkpoint_supervisor as supervisor
import goal_review_launch as launch
from test_legacy_control_readers import old_checkpoint

HEAD = 'a' * 40


def owner(body):
    return {'id': 100, 'body': body, 'user': {'login': supervisor.AUTHOR},
            'issue_url': f'https://api.github.com/repos/{supervisor.REPO}/issues/11'}


class SupervisorEnvelopeGaps(unittest.TestCase):
    def test_unknown_or_malformed_intended_envelopes_fail_all_ownership_readers(self):
        invalid = ['<!-- tremelay-supervisor-v2 {"phase":"working"} -->',
                   '<!-- tremelay-supervisor-v0 {"phase":"working"} -->',
                   '<!-- tremelay-supervisor-v2', '<!-- tremelay-supervisor-working -->',
                   '<!-- tremelay-supervisor-v1x {} -->',
                   '<!-- tremelay-supervisor-review:not-a-head -->',
                   '<!-- tremelay-supervisor-budget extra -->']
        for body in invalid:
            with self.subTest(body=body):
                with self.assertRaises(ValueError):
                    protocol.supervisor_state(body)
                with self.assertRaises(supervisor.Stop):
                    supervisor.records([owner(body)])
                with self.assertRaises(supervisor.Stop):
                    launch.pending_claim([owner(body)], supervisor.REPO, 11, supervisor.AUTHOR)
                self.assertFalse(protocol.is_resume_authorization(protocol.HUMAN_RESUME_MARKER + '\n' + body))

    def test_unknown_envelope_cannot_hide_next_to_a_valid_v1_record(self):
        valid = supervisor.state_body({'head': HEAD, 'review': 1, 'phase': 'working'}, 'Claim')
        for body in ['<!-- tremelay-supervisor-v2 {} -->\n' + valid,
                     valid + '\n<!-- tremelay-supervisor-v2 {} -->',
                     '<!-- tremelay-supervisor-budget -->\n<!-- tremelay-supervisor-v2 {} -->']:
            with self.subTest(body=body), self.assertRaises(ValueError):
                protocol.supervisor_state(body)

    def test_known_non_envelope_controls_keep_their_existing_meaning(self):
        for marker in ['<!-- tremelay-supervisor-budget -->', f'<!-- tremelay-supervisor-review:{HEAD} -->']:
            body = 'Existing controller result.\n\n' + marker
            with self.subTest(marker=marker):
                self.assertIsNone(protocol.supervisor_state(body))
                self.assertEqual(supervisor.records([owner(body)]), [])
                self.assertFalse(launch.pending_claim([owner(body)], supervisor.REPO, 11, supervisor.AUTHOR))
                self.assertTrue(protocol.has_control_marker(body, marker))
        valid = {'head': HEAD, 'review': 1, 'phase': 'reserved'}
        self.assertEqual(protocol.supervisor_state(supervisor.state_body(valid, 'Claim')), valid)

    def test_unknown_controls_inside_old_checkpoint_evidence_remain_inert(self):
        payload = '<!-- tremelay-supervisor-v2 {"phase":"working"} -->'
        for oversized in [False, True]:
            body = old_checkpoint(payload, oversized=oversized)
            self.assertIsNone(protocol.supervisor_state(body))
            self.assertEqual(supervisor.records([owner(body)]), [])
            self.assertFalse(launch.pending_claim([owner(body)], supervisor.REPO, 11, supervisor.AUTHOR))
            self.assertFalse(protocol.is_resume_authorization(body))
        self.assertEqual(supervisor.records([dict(owner(payload), user={'login': 'attacker'})]), [])


class BranchPublicationRace(unittest.TestCase):
    def run_ensure(self, scenario):
        text = (ROOT / '.github/workflows/goal.yml').read_text()
        step = text.split('      - name: Ensure goal branch\n', 1)[1].split('      - name:', 1)[0]
        script = step.split('        run: |\n', 1)[1]
        script = '\n'.join(line[10:] for line in script.splitlines() if line.startswith('          '))
        script = script.replace('${{ github.event.issue.number }}', '10')
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            (tmp / 'scripts').symlink_to(ROOT / 'scripts', target_is_directory=True)
            (tmp / 'payload.json').write_text(json.dumps({'repos': [{'startingRef': 'goal/issue-10'}]}))
            (tmp / 'state.json').write_text(json.dumps({'stage': 'initial'}))
            bindir = tmp / 'bin'
            bindir.mkdir()
            (bindir / 'python').symlink_to(sys.executable)
            program = r'''#!PYTHON
import json, os, pathlib, sys
args = sys.argv[1:]
tool = pathlib.Path(sys.argv[0]).name
with open('calls.jsonl', 'a') as stream:
    stream.write(json.dumps({'tool': tool, 'args': args}) + '\n')
state = json.loads(pathlib.Path('state.json').read_text())
scenario = os.environ['SCENARIO']
if tool == 'git':
    if args[0] == 'fetch':
        pathlib.Path('state.json').write_text(json.dumps({'stage': 'changed'}))
        sys.exit(0)
    if args[0] == 'ls-remote': sys.exit(2)
    if args[0] == 'push': sys.exit(0)
    raise SystemExit('Unexpected git call')
if tool == 'gh':
    path = args[-1]
    changed = state['stage'] == 'changed'
    if '/issues/10' in path:
        if changed and scenario == 'unavailable': sys.exit(1)
        print(json.dumps({'number': 10, 'state': 'closed' if changed and scenario == 'closed' else 'open'}))
        sys.exit(0)
    if '/pulls?state=all' in path:
        pulls = []
        if changed and scenario == 'merged':
            pulls = [{'number': 9, 'state': 'closed', 'merged_at': '2026-10-10T00:00:00Z',
                      'body': 'Goal-Issue: #10', 'head': {'ref': 'goal/issue-10',
                      'repo': {'full_name': 'CharitonMedia/Tremelay'}}, 'labels': []}]
        print(json.dumps(pulls)); sys.exit(0)
    raise SystemExit('Unexpected gh call')
raise SystemExit('Unexpected mocked tool')
'''.replace('PYTHON', sys.executable)
            for name in ['git', 'gh']:
                target = bindir / name
                target.write_text(program)
                target.chmod(0o755)
            env = {'PATH': str(bindir) + os.pathsep + os.defpath,
                   'SCENARIO': scenario, 'GH_TOKEN': 'offline-test-token',
                   'GITHUB_REPOSITORY': supervisor.REPO}
            # The source was eligible when the request was prepared. The mock
            # changes it during git fetch, immediately before branch creation.
            initial = subprocess.run([sys.executable, 'scripts/goal_lineage.py', '--issue', '10',
                                      '--launch', '--repository-ownership'],
                                     cwd=tmp, env=env, capture_output=True, text=True)
            self.assertEqual(initial.returncode, 0, initial.stderr)
            result = subprocess.run(['/bin/bash', '-c', script], cwd=tmp, env=env,
                                    capture_output=True, text=True)
            calls = [json.loads(line) for line in (tmp / 'calls.jsonl').read_text().splitlines()]
            return result, calls, step

    def test_actual_ensure_step_refuses_retired_or_unreadable_goal_after_build(self):
        for scenario in ['closed', 'merged', 'unavailable']:
            with self.subTest(scenario=scenario):
                result, calls, _ = self.run_ensure(scenario)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(any(c['tool'] == 'git' and c['args'][0] == 'push' for c in calls))

    def test_actual_ensure_step_rechecks_then_pushes_valid_goal(self):
        result, calls, step = self.run_ensure('open')
        self.assertEqual(result.returncode, 0, result.stderr)
        push = next(i for i, c in enumerate(calls) if c['tool'] == 'git' and c['args'][0] == 'push')
        fetch = next(i for i, c in enumerate(calls) if c['tool'] == 'git' and c['args'][0] == 'fetch')
        self.assertTrue(any(c['tool'] == 'gh' and '/issues/10' in c['args'][-1] for c in calls[fetch + 1:push]))
        self.assertIn('GH_TOKEN: ${{ github.token }}', step)


if __name__ == '__main__':
    unittest.main()
