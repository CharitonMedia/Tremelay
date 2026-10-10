"""Review findings reproduced against both the previous and corrected trees."""
import copy
import os
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


class ReviewFindings(unittest.TestCase):
    def test_initial_create_uses_durable_reservation(self):
        text = (ROOT / '.github/workflows/goal.yml').read_text()
        job = text.split('  implement:', 1)[1].split('  publish:', 1)[0]
        self.assertIn('goal_initial_launch.py launch', job)
        self.assertNotIn('curl --fail-with-body', job)

    def test_every_create_entry_uses_same_serialized_job_group(self):
        import yaml
        targets = {'goal.yml': ['implement', 'review-launch'],
                   'checkpoint-supervisor.yml': ['supervise'],
                   'codex-cursor-remediation.yml': ['remediate']}
        for path, names in targets.items():
            workflow = yaml.safe_load((ROOT / '.github/workflows' / path).read_text())
            for name in names:
                with self.subTest(workflow=path, job=name):
                    self.assertEqual(workflow['jobs'][name].get('concurrency'),
                                     {'group': 'tremelay-worker-admission', 'cancel-in-progress': False})

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


if __name__ == '__main__':
    unittest.main()
