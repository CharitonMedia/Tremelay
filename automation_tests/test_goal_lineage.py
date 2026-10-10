"""Closed/merged goals and existing owners cannot restart through late events."""
import argparse
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import goal_agent_request as goal
import goal_lineage as lineage
import goal_review_launch as recovery

REPO = lineage.REPO
HEAD = 'a' * 40


def pull(number=11, **changes):
    result = {'number': number, 'state': 'open', 'merged_at': None, 'user': {'login': lineage.OWNER},
              'body': 'Goal-Issue: #10', 'head': {'ref': 'goal/issue-10', 'sha': HEAD, 'repo': {'full_name': REPO}},
              'base': {'ref': 'main'}, 'labels': [{'name': 'goal'}],
              'html_url': f'https://github.com/{REPO}/pull/{number}'}
    result.update(changes)
    return result


class Sources:
    def __init__(self):
        self.issue = {'number': 10, 'state': 'open'}
        self.pulls = [pull()]
        self.comments = {}
        self.calls = []

    def read(self, path):
        self.calls.append(path)
        if path == f'repos/{REPO}/issues/10':
            return copy.deepcopy(self.issue)
        if path == f'repos/{REPO}/pulls/11':
            return copy.deepcopy(next(p for p in self.pulls if p['number'] == 11))
        raise AssertionError(path)

    def pages(self, path):
        self.calls.append(path)
        if path == f'repos/{REPO}/pulls?state=all':
            return copy.deepcopy(self.pulls)
        if path == f'repos/{REPO}/issues?state=all':
            return [copy.deepcopy(self.issue)]
        prefix = f'repos/{REPO}/issues/'
        if path.startswith(prefix) and path.endswith('/comments'):
            return copy.deepcopy(self.comments.get(int(path[len(prefix):].split('/')[0]), []))
        raise AssertionError(path)

    def guard(self, **kwargs):
        return lineage.guard(read=self.read, pages=self.pages, **kwargs)


class GoalLineageTests(unittest.TestCase):
    def test_open_goal_without_prior_pr_can_launch(self):
        source = Sources()
        source.pulls = []
        self.assertEqual(source.guard(issue_number=10, launch=True), [])

    def test_closed_or_unknown_source_always_stops(self):
        for issue in [{'number': 10, 'state': 'closed'}, {'number': 10}, {}, None,
                      {'number': 10, 'state': 'open', 'pull_request': {'url': 'unexpected'}}]:
            with self.subTest(issue=issue):
                source = Sources()
                source.issue = issue
                with self.assertRaises(lineage.LineageStop):
                    source.guard(issue_number=10)

    def test_merged_prior_pr_blocks_even_after_reopening_issue(self):
        for marker in ['Goal-Issue: #10', '']:
            source = Sources()
            source.pulls.append(pull(9, state='closed', merged_at='2026-10-01T00:00:00Z', body=marker))
            for kwargs in [{'issue_number': 10}, {'pr_number': 11, 'head': HEAD, 'launch': True}]:
                with self.subTest(marker=marker, kwargs=kwargs), self.assertRaisesRegex(lineage.LineageStop, 'merged'):
                    source.guard(**kwargs)

    def test_source_marker_preserves_lineage_on_an_alternate_branch(self):
        source = Sources()
        old = pull(9, state='closed', merged_at='2026-10-01T00:00:00Z')
        old['head']['ref'] = 'old-goal-head'
        source.pulls.append(old)
        with self.assertRaisesRegex(lineage.LineageStop, 'merged'):
            source.guard(issue_number=10)

    def test_manual_hold_is_never_retagged_by_publication(self):
        source = Sources()
        source.pulls[0]['labels'] = [{'name': 'human-review-required'}]
        with self.assertRaisesRegex(lineage.LineageStop, 'manual'):
            source.guard(issue_number=10)
        self.assertIsNone(goal.sync_plan(issue_number=10, title='Goal', base_ref='main', existing=source.pulls[0]))

    def test_missing_lifecycle_evidence_fails_closed(self):
        for field in ['merged_at', 'state', 'labels', 'head', 'body']:
            source = Sources()
            del source.pulls[0][field]
            with self.subTest(field=field), self.assertRaises(lineage.LineageStop):
                source.guard(issue_number=10)

    def test_unknown_read_failure_never_becomes_permission(self):
        source = Sources()
        with patch.object(source, 'pages', side_effect=RuntimeError('offline')):
            with self.assertRaises(RuntimeError):
                source.guard(issue_number=10)

    def test_new_review_head_does_not_clear_closed_pr_owner(self):
        source = Sources()
        source.pulls.append(pull(9, state='closed'))
        old = {'id': 100, 'user': {'login': goal.TRUSTED_AUTOMATION_LOGIN},
               'issue_url': f'https://api.github.com/{REPO}/issues/9', 'body': 'old accepted worker'}
        source.comments[9] = [old]
        with patch.object(recovery, 'pending_claim', side_effect=lambda comments, *args, **kwargs: bool(comments)) as pending:
            with self.assertRaisesRegex(lineage.LineageStop, 'owns'):
                source.guard(pr_number=11, head=HEAD, launch=True, ignore_comment_id=101)
            self.assertEqual([call.args[2] for call in pending.call_args_list], [11, 9])
            self.assertTrue(all(call.kwargs == {'ignore_comment_id': 101} for call in pending.call_args_list))

    def test_new_issue_waits_for_owned_pr_from_another_completed_goal(self):
        source = Sources()
        old = pull(22, state='closed', body='Goal-Issue: #20', merged_at='2026-10-01T00:00:00Z',
                   head={'ref': 'goal/issue-20', 'repo': {'full_name': REPO}})
        source.pulls.append(old)
        source.comments[22] = [{'body': 'existing worker receipt'}]
        with patch.object(recovery, 'pending_claim', side_effect=lambda comments, *args, **kwargs: bool(comments)) as pending:
            with self.assertRaisesRegex(lineage.LineageStop, 'owns'):
                source.guard(issue_number=10, launch=True, repository_ownership=True)
            self.assertIn(22, [call.args[2] for call in pending.call_args_list])
        source.comments[22] = []
        with patch.object(recovery, 'pending_claim', return_value=False):
            self.assertEqual(len(source.guard(issue_number=10, launch=True, repository_ownership=True)), 1)

    def test_foreign_markers_cannot_nominate_publication_or_launch_targets(self):
        candidates = []
        for update in [{'user': {'login': 'attacker'}},
                       {'head': {'ref': 'goal/issue-10', 'repo': {'full_name': 'attacker/fork'}}},
                       {'head': {'ref': 'attacker-branch', 'repo': {'full_name': REPO}}},
                       {'base': {'ref': 'other'}}]:
            candidate = pull(99, **update)
            candidates.append(candidate)
            with self.subTest(update=update), self.assertRaises(lineage.LineageStop):
                lineage.source_issue(candidate)
        self.assertEqual(lineage.open_pr_records(candidates), [])
        self.assertEqual([p['number'] for p in lineage.open_pr_records(candidates + [pull()])], [11])
        with self.assertRaises(lineage.LineageStop):
            lineage.open_pr_records([pull(), pull(12)])

    def test_target_is_fresh_and_bound_to_source(self):
        for mutate in [lambda p: p.update(state='closed'),
                       lambda p: p['head'].update(sha='b' * 40),
                       lambda p: p['head'].update(ref='other-branch'),
                       lambda p: p.update(body='Goal-Issue: #10\nGoal-Issue: #12')]:
            source = Sources()
            mutate(source.pulls[0])
            with self.subTest(mutate=mutate), self.assertRaises(lineage.LineageStop):
                source.guard(pr_number=11, head=HEAD)

    def test_pagination_does_not_truncate_at_100_pull_requests(self):
        source = Sources()
        history = [pull(i + 100, body='', head={'ref': f'other/{i}', 'repo': {'full_name': REPO}}) for i in range(100)]
        history.append(pull(9, state='closed', merged_at='2026-10-01T00:00:00Z'))
        with patch.object(lineage, '_gh_json', side_effect=[history[:100], history[100:]]) as gh:
            with self.assertRaisesRegex(lineage.LineageStop, 'merged'):
                lineage.ensure_open_lineage(10, read=source.read, pages=lineage.gh_pages)
            args = gh.call_args.args[0]
            self.assertEqual(gh.call_count, 2)
            self.assertIn('per_page=100&page=2', args[-1])
            self.assertIn('state=all', args[-1])
        with patch.object(lineage, '_gh_json', return_value={'truncated': True}):
            with self.assertRaises(lineage.LineageStop):
                lineage.gh_pages('path')

    def test_history_bound_fails_closed_instead_of_authorizing_a_prefix(self):
        with patch.object(lineage, 'MAX_HISTORY_PAGES', 2), self.assertRaises(lineage.LineageStop):
            lineage.bounded_pages('path', read=lambda path: [{}] * 100)

    def test_apply_sync_reads_fresh_lineage_before_any_write(self):
        args = argparse.Namespace(issue_number=10, pr_number=None, title='Goal', base_ref='main',
                                  existing='stale-file.json', ahead=True, head_changed=False, head_accepted=False)
        for reason in ['closed source issue', 'merged lineage', 'manual hold']:
            with self.subTest(reason=reason), patch.object(lineage, 'guard', side_effect=lineage.LineageStop(reason)), \
                    patch.object(goal, '_run_gh') as mutation:
                with self.assertRaises(lineage.LineageStop):
                    goal._cmd_apply_sync(args)
                mutation.assert_not_called()
        with patch.object(lineage, 'guard', return_value=[pull()]), patch.object(goal, '_run_gh') as mutation:
            self.assertEqual(goal._cmd_apply_sync(args), 0)
            mutation.assert_not_called()

    def test_workflow_guards_all_launch_and_publication_paths(self):
        text = (Path(__file__).resolve().parents[1] / '.github/workflows/goal.yml').read_text()
        implement = text.split('  implement:', 1)[1].split('  publish:', 1)[0]
        publish = text.split('  publish:', 1)[1].split('  codex-clean-complete:', 1)[0]
        review = text.split('  review-launch:', 1)[1].split('  recover-review:', 1)[0]
        self.assertIn('--launch --repository-ownership --open-prs-out open_prs.json', implement)
        self.assertIn('--pr "$pr_number" --head "$before" --launch', implement)
        self.assertIn('--issue "$issue"', publish)
        self.assertIn('--ignore-comment-id "$claim_id"', review)
        for job in [implement, publish]:
            self.assertIn('ref: main', job)


if __name__ == '__main__':
    unittest.main()
