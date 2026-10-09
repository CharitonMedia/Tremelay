import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import goal_agent_request as g
import goal_review_launch as recovery

HEAD = "a" * 40
REPO = "CharitonMedia/Tremelay"


class LaunchWorkflow(unittest.TestCase):
    def shell(self):
        text = (ROOT / ".github/workflows/goal.yml").read_text()
        job = text[text.index("  review-launch:"):text.index("  recover-review:")]
        step = job[job.index("      - name: Launch Cloud Agent\n"):]
        script = step.split("        run: |\n", 1)[1]
        script = "\n".join(line[10:] if line.startswith("          ") else line for line in script.splitlines())
        return script.replace("${{ github.event.pull_request.number || github.event.issue.number }}", "11")

    def run_launch(self, scenario):
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            (tmp / "scripts").symlink_to(ROOT / "scripts", target_is_directory=True)
            marker = g.review_claim_marker("4", HEAD)
            (tmp / "claim.json").write_text(json.dumps({"status": "free", "owned": False, "marker": marker, "review_id": "4", "head": HEAD}))
            (tmp / "payload.json").write_text(json.dumps({"name": "test", "prompt": {"text": "Fix the reviewed defect."}, "repos": [{"url": f"https://github.com/{REPO}", "prUrl": f"https://github.com/{REPO}/pull/11"}], "workOnCurrentBranch": True, "autoCreatePR": False, "skipReviewerRequest": True}))
            bin_dir = tmp / "bin"
            bin_dir.mkdir()
            program = r'''#!PYTHON
import json, os, pathlib, sys
a=sys.argv[1:]
scenario=os.environ["SCENARIO"]
tool=pathlib.Path(sys.argv[0]).name
with open("calls.jsonl","a") as f: f.write(json.dumps({"tool":tool,"args":a})+"\n")
if tool=="sleep": sys.exit(0)
if tool=="gh":
    if a[:2]==["pr","view"]: print("a"*40);sys.exit(0)
    method=a[a.index("--method")+1] if "--method" in a else ("POST" if "-f" in a else "GET")
    path=next((x for x in a if x.startswith("repos/")),"")
    if method=="DELETE":
        if scenario=="release_delete_failure": print("HTTP/2 500");sys.exit(1)
        print("HTTP/2 204");sys.exit(0)
    if method=="PATCH":
        if "--include" in a: print("HTTP/2 200");sys.exit(0)
        if scenario=="claim_patch_failure": sys.exit(1)
        print("{}");sys.exit(0)
    if method=="POST" and path.endswith("/comments"):print("101");sys.exit(0)
    if "/pulls/11/reviews" in path:
        if scenario=="review_read_failure":sys.exit(1)
        review={"id":5 if scenario=="new_review" else 4,"commit_id":"a"*40,"state":"APPROVED" if scenario=="new_review" else "COMMENTED","submitted_at":"2026-10-08T01:00:00Z","user":{"login":"chatgpt-codex-connector[bot]"}}
        print(json.dumps([[review]]));sys.exit(0)
    if path.endswith("/pulls/11"):
        if "--jq" in a:sys.exit(0)
        if scenario in {"pre_read_failure","release_delete_failure"}:sys.exit(1)
        pull={"state":"closed" if scenario=="closed" else "open", "head":{"sha":"b"*40 if scenario=="moved" else "a"*40}, "labels":[{"name":"human-review-required"}] if scenario=="stopped" else []}
        print(json.dumps(pull));sys.exit(0)
    raise SystemExit("Unexpected GitHub operation")
if tool=="curl":
    payload=json.loads(pathlib.Path("payload.json").read_text())
    assert payload["agentId"].startswith("bc-")
    if scenario=="curl_error":sys.exit(7)
    code={"ambiguous":"500","conflict":"409","rejected":"422"}.get(scenario,"201")
    pathlib.Path("response.json").write_text(json.dumps({"agent":{"id":payload["agentId"],"url":"https://cursor.com/agents/"+payload["agentId"]},"run":{"id":"run-1","agentId":payload["agentId"]}}))
    print(code,end="");sys.exit(0)
raise SystemExit("Unexpected tool")
'''.replace("PYTHON", sys.executable)
            for name in ["gh", "curl", "sleep"]:
                path = bin_dir / name
                path.write_text(program)
                path.chmod(0o755)
            env = dict(os.environ, PATH=str(bin_dir) + os.pathsep + os.environ["PATH"], GITHUB_REPOSITORY=REPO,
                       GITHUB_OUTPUT=str(tmp/"output"), GOAL_GITHUB_TOKEN="test-owner", GH_TOKEN="test-owner",
                       CURSOR_API_KEY="test-cursor", SCENARIO=scenario)
            result = subprocess.run(["bash", "-c", self.shell()], cwd=tmp, env=env, text=True, capture_output=True, timeout=15)
            calls = [json.loads(line) for line in (tmp/"calls.jsonl").read_text().splitlines()]
            state = json.loads((tmp/"launch_state.json").read_text()) if (tmp/"launch_state.json").exists() else None
            output = (tmp/"output").read_text() if (tmp/"output").exists() else ""
            return result, calls, state, output

    def test_real_launch_step_releases_every_definite_precreate_failure(self):
        for scenario in ["pre_read_failure", "closed", "moved", "stopped", "claim_patch_failure", "review_read_failure", "new_review"]:
            with self.subTest(scenario=scenario):
                result, calls, _, _ = self.run_launch(scenario)
                self.assertNotEqual(result.returncode, 0, result.stderr)
                self.assertFalse(any(c["tool"]=="curl" for c in calls))
                self.assertTrue(any("DELETE" in c["args"] for c in calls), result.stderr)

    def test_real_release_falls_back_to_nonowning_comment(self):
        result, calls, _, _ = self.run_launch("release_delete_failure")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(c["tool"]=="curl" for c in calls))
        patches = [c for c in calls if "PATCH" in c["args"] and "--include" in c["args"]]
        self.assertEqual(len(patches), 1)
        body = next(x[5:] for x in patches[0]["args"] if x.startswith("body="))
        self.assertFalse(g.comment_counts_cycle(body))
        self.assertNotIn("<!--", body)

    def test_real_launch_retains_ambiguous_and_conflict_claims(self):
        for scenario in ["curl_error", "ambiguous", "conflict"]:
            with self.subTest(scenario=scenario):
                result, calls, state, _ = self.run_launch(scenario)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(sum(c["tool"]=="curl" for c in calls), 1)
                self.assertFalse(any("DELETE" in c["args"] for c in calls))
                self.assertEqual(state["phase"], "dispatch_reserved")
                self.assertRegex(state["agent_id"], r"^bc-[0-9a-f-]{36}$")

    def test_real_launch_releases_definitive_rejection(self):
        result, calls, _, _ = self.run_launch("rejected")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(sum(c["tool"]=="curl" for c in calls), 1)
        self.assertTrue(any("DELETE" in c["args"] for c in calls))

    def test_real_launch_keeps_accepted_identity_for_recovery(self):
        result, calls, state, output = self.run_launch("accepted")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(sum(c["tool"]=="curl" for c in calls), 1)
        self.assertFalse(any("DELETE" in c["args"] for c in calls))
        self.assertEqual(state["phase"], "working")
        self.assertEqual(state["run_id"], "run-1")
        self.assertIn("claim_id=101", output)
        final_patch = [c for c in calls if c['tool'] == 'gh' and 'PATCH' in c['args']][-1]
        persisted_body = next(x[5:] for x in final_patch['args'] if x.startswith('body='))
        self.assertEqual(recovery.parse_body(persisted_body), state)

    def test_manual_recovery_is_serialized_and_cannot_launch(self):
        text = (ROOT / ".github/workflows/goal.yml").read_text()
        job = text.split("  recover-review:", 1)[1].split("  request-codex:", 1)[0]
        for value in ["ref: main", "goal-review-${{ inputs.recovery_pr }}", "goal_review_launch.py recover"]:
            self.assertIn(value, job)
        self.assertNotIn("curl", job)
        self.assertNotIn(" prepare ", job)
        self.assertNotIn("--phase dispatch_reserved", job)
        monitor = text.split('  request-codex:', 1)[1]
        self.assertIn('group: goal-review-${{ needs.review-launch.outputs.pr_number }}', monitor)
        self.assertIn('cancel-in-progress: false', monitor)

    def test_new_review_cannot_replace_an_unresolved_worker(self):
        marker = g.review_claim_marker('4', HEAD)
        claim = {'status': 'free', 'owned': False, 'marker': marker, 'review_id': '4', 'head': HEAD}
        payload = {'name': 'test', 'prompt': {'text': 'Fix defect'}, 'repos': [{'url': f'https://github.com/{REPO}', 'prUrl': f'https://github.com/{REPO}/pull/11'}], 'workOnCurrentBranch': True, 'autoCreatePR': False, 'skipReviewerRequest': True}
        saved, _ = recovery.prepare(REPO, 11, claim, payload)
        saved = recovery.transition(saved, 'dispatch_reserved')
        comment = {'id': 101, 'user': {'login': g.TRUSTED_AUTOMATION_LOGIN}, 'issue_url': f'https://api.github.com/repos/{REPO}/issues/11', 'body': recovery.state_body(saved)}
        newer = 'b' * 40
        live = {'number': 11, 'state': 'open', 'head': {'sha': newer, 'repo': {'full_name': REPO}}, 'labels': [{'name': 'goal'}]}
        event = {'review': {'id': 5, 'commit_id': newer}}
        result = g.review_launch_decision(event, 'pull_request_review', pull=live, comments=[comment], trusted_login=g.TRUSTED_AUTOMATION_LOGIN)
        self.assertEqual(result['status'], 'blocked')

    def test_delayed_review_event_cannot_override_newer_approval(self):
        older = {'id': 4, 'commit_id': HEAD, 'state': 'COMMENTED', 'submitted_at': '2026-10-08T01:00:00Z', 'user': {'login': 'chatgpt-codex-connector[bot]'}}
        newer = dict(older, id=5, state='APPROVED', submitted_at='2026-10-08T02:00:00Z')
        event = {'review': older}
        result = g.review_launch_decision(event, 'pull_request_review', reviews=[older, newer])
        self.assertEqual(result['status'], 'blocked')
        inline = {'comment': {'pull_request_review_id': 4, 'commit_id': HEAD}}
        self.assertEqual(g.review_launch_decision(inline, 'pull_request_review_comment', reviews=[older, newer])['status'], 'blocked')
        self.assertEqual(g.review_launch_decision(event, 'pull_request_review', reviews=[older])['status'], 'free')

    def test_supervisor_cannot_replace_an_ordinary_claim(self):
        import checkpoint_supervisor as supervisor
        from unittest.mock import patch
        state = {'repo': REPO, 'pr': 11, 'review': '4', 'head': HEAD,
                 'agent_id': recovery.agent_identity(REPO, 11, '4', HEAD), 'phase': 'dispatch_reserved'}
        comment = {'id': 101, 'user': {'login': g.TRUSTED_AUTOMATION_LOGIN}, 'issue_url': f'https://api.github.com/repos/{REPO}/issues/11', 'body': recovery.state_body(state)}
        pull = {'number': 11, 'head': {'sha': HEAD}}
        with patch.object(supervisor, 'pages', return_value=[comment]), patch.object(supervisor, 'assess') as model, patch.object(supervisor, 'cursor') as worker:
            supervisor.run_one(pull, 3)
            model.assert_not_called()
            worker.assert_not_called()
        fresh = {'number': 11, 'state': 'open', 'draft': False, 'user': {'login': supervisor.AUTHOR},
                 'head': {'sha': HEAD, 'repo': {'full_name': REPO}}, 'base': {'ref': 'main'},
                 'labels': [{'name': 'goal'}, {'name': 'human-review-required'}], 'body': 'Goal-Issue: #10'}
        for activity in [False, True]:
            with patch.object(supervisor, 'gh', return_value=fresh), patch.object(supervisor, 'pages', return_value=[comment]), patch.object(supervisor, 'wait_for_goal_idle'), patch.object(supervisor, 'cursor') as worker:
                with self.assertRaisesRegex(supervisor.Stop, 'ordinary review worker'):
                    supervisor.refresh_guard(11, HEAD, 4, check_activity=activity)
                worker.assert_not_called()

    def test_script_namespace_bad_claim_does_not_starve_later_prs(self):
        import runpy
        from unittest.mock import patch
        script = runpy.run_path(str(ROOT / 'scripts/checkpoint_supervisor.py'), run_name='supervisor_script_under_test')
        namespace = script['main'].__globals__
        seen = []
        def pull(number):
            return {'number': number, 'state': 'open', 'draft': False, 'user': {'login': 'pattalkslaw-del'},
                    'head': {'sha': HEAD, 'repo': {'full_name': REPO}}, 'base': {'ref': 'main'},
                    'labels': [{'name': 'goal'}, {'name': 'human-review-required'}], 'body': 'Goal-Issue: #10'}
        def pages(path):
            seen.append(path)
            if path.endswith('/pulls?state=open'):
                return [pull(11), pull(13)]
            if '/issues/11/comments' in path:
                return [{'id': 101, 'user': {'login': 'pattalkslaw-del'}, 'issue_url': f'https://api.github.com/repos/{REPO}/issues/11', 'body': '<!-- goal-review-launch-v1 broken -->'}]
            return []
        env = {'GITHUB_REPOSITORY': REPO, 'GITHUB_REF': 'refs/heads/main', 'GITHUB_WORKFLOW_REF': REPO + '/.github/workflows/checkpoint-supervisor.yml@refs/heads/main', 'GH_TOKEN': 'test-owner', 'CURSOR_API_KEY': 'test-cursor', 'SUPERVISOR_MAX_CHECKPOINTS': '3', 'TREMELAY_SUPERVISOR_ACTIVATION': script['ACTIVATION_VALUE']}
        with patch.dict(os.environ, env), patch.object(sys, 'argv', ['checkpoint_supervisor.py']), patch.dict(namespace, {'pages': pages, 'gh': lambda path: {'login': 'pattalkslaw-del'}}):
            self.assertEqual(script['main'](), 1)
        self.assertTrue(any('/issues/13/comments' in path for path in seen))

    def test_attempt_stage_and_id_conflict_semantics(self):
        self.assertFalse(g.claim_survives_cancel(accepted=False, create_settled=False, create_attempted=False))
        self.assertTrue(g.claim_survives_cancel(accepted=False, create_settled=False, create_attempted=True))
        self.assertTrue(g.claim_survives_cancel(accepted=True, create_settled=False, create_attempted=False))
        self.assertEqual(g.create_outcome("409"), "ambiguous")


if __name__ == "__main__":
    unittest.main()
