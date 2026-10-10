import copy
from contextlib import ExitStack
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import codex_cursor_remediation as planner
import generic_worker as worker
import goal_review_launch as ordinary

HEAD = "a" * 40
PR = 11
ENV = {"GITHUB_REPOSITORY": worker.REPO, "TREMELAY_WORKER_ADMISSION": "serialized-v1"}


def plan(review=4, round_number=1):
    result = planner.build_plan(
        {"action": "submitted", "review": {"id": review, "commit_id": HEAD, "user": {"login": "codex"}}},
        {"number": PR, "url": f"https://github.com/{worker.REPO}/pull/{PR}", "headRefOid": HEAD,
         "labels": [{"name": planner.LOOP_LABEL}]},
        [{"id": 5, "body": "Fix the reviewed defect.", "user": {"login": "codex"}}], [])
    result["round"] = round_number
    return result


def receipt(state, comment_id=101, pr=PR):
    return {"id": comment_id, "body": worker.state_body(state), "user": {"login": worker.OWNER},
            "issue_url": f"https://api.github.com/repos/{worker.REPO}/issues/{pr}"}


class Server:
    def __init__(self):
        self.comments = []
        self.calls = []
        self.post_error = None
        self.lookup_error = None
        self.patch_error = False
        self.patch_error_phase = None
        self.reserve_error = False
        self.mutate_agent = None
        self.agent_reads = 0
        self.latest = "run-1"
        self.run_status = "RUNNING"
        self.pull = {"number": PR, "state": "open", "head": {"sha": HEAD, "repo": {"full_name": worker.REPO}},
                     "base": {"repo": {"full_name": worker.REPO}}, "labels": [{"name": planner.LOOP_LABEL}]}

    def gh(self, path, *, method="GET", data=None):
        self.calls.append(("gh", method, path, copy.deepcopy(data)))
        if path == "user":
            return {"login": worker.OWNER}
        if path.startswith(f"repos/{worker.REPO}/pulls?state=all"):
            return [copy.deepcopy(self.pull)]
        if path.startswith(f"repos/{worker.REPO}/issues?state=all"):
            return []
        if path == f"repos/{worker.REPO}/pulls/{PR}":
            return copy.deepcopy(self.pull)
        if path.startswith(f"repos/{worker.REPO}/issues/{PR}/comments"):
            if method == "POST":
                if self.reserve_error:
                    raise worker.Stop("reservation failure")
                comment = {"id": 101 + len(self.comments), "body": data["body"],
                           "user": {"login": worker.OWNER},
                           "issue_url": f"https://api.github.com/repos/{worker.REPO}/issues/{PR}"}
                self.comments.append(comment)
                return copy.deepcopy(comment)
            return copy.deepcopy(self.comments)
        if path.startswith(f"repos/{worker.REPO}/issues/comments/"):
            found = next(c for c in self.comments if c["id"] == int(path.rsplit("/", 1)[1]))
            if method == "PATCH":
                if self.patch_error or worker.parse_body(data['body'])['phase'] == self.patch_error_phase:
                    raise worker.Stop("patch failure")
                found["body"] = data["body"]
            return copy.deepcopy(found)
        raise AssertionError((path, method, data))

    def cursor(self, path, *, payload=None):
        self.calls.append(("cursor", "POST" if payload is not None else "GET", path, copy.deepcopy(payload)))
        agent_id = plan()["payload"]["agentId"]
        if payload is not None:
            if self.post_error:
                raise worker.Stop(self.post_error)
            return {"agent": {"id": payload["agentId"]}, "run": {"id": "run-1", "agentId": payload["agentId"]}}
        if self.lookup_error:
            raise worker.Stop(self.lookup_error)
        if "/runs/" in path:
            return {"id": "run-1", "agentId": agent_id, "status": self.run_status}
        self.agent_reads += 1
        result = {"id": agent_id, "latestRunId": self.latest, "workOnCurrentBranch": True,
                  "repos": [{"url": f"https://github.com/{worker.REPO}",
                             "prUrl": f"https://github.com/{worker.REPO}/pull/{PR}"}]}
        if self.mutate_agent:
            self.mutate_agent(result, self.agent_reads)
        return result

    def context(self):
        stack = ExitStack()
        stack.enter_context(patch.dict(os.environ, ENV))
        stack.enter_context(patch.object(worker, "gh", self.gh))
        stack.enter_context(patch.object(worker, "cursor", self.cursor))
        return stack

    def state(self):
        return worker.parse_body(self.comments[0]["body"])

    def posts(self):
        return [c for c in self.calls if c[:2] == ("cursor", "POST")]


class GenericOwnership(unittest.TestCase):
    def test_reservation_precedes_single_create_and_preserves_round(self):
        server = Server()
        with server.context():
            state, comment_id = worker.launch(plan())
        self.assertEqual((state["phase"], comment_id), ("working", 101))
        self.assertEqual(server.state(), state)
        self.assertEqual(len(server.posts()), 1)
        post_index = next(i for i, c in enumerate(server.calls) if c[:2] == ("cursor", "POST"))
        prior = server.calls[:post_index]
        self.assertTrue(any(c[:2] == ("gh", "POST") and worker.MARKER in c[3]["body"] for c in prior))
        self.assertTrue(any(c[:2] == ("gh", "GET") and c[2].endswith("/issues/comments/101") for c in prior))
        self.assertEqual(planner._round_markers(server.comments, trusted_login=worker.OWNER), [plan()["marker"]])

    def test_ambiguous_create_and_later_404_never_replay_or_delete(self):
        server = Server()
        server.post_error = "ambiguous create"
        with server.context(), self.assertRaises(worker.Stop):
            worker.launch(plan())
        self.assertEqual(server.state()["phase"], "dispatch_reserved")
        server.lookup_error = "404"
        for operation in (lambda: worker.launch(plan()), lambda: worker.reconcile(PR)):
            with server.context(), self.assertRaises(worker.Stop):
                operation()
        self.assertEqual(len(server.posts()), 1)
        self.assertFalse(any(c[1] == "DELETE" for c in server.calls))
        self.assertTrue(worker.pending_generic_claim(server.comments, PR))

    def test_working_receipt_survives_patch_failure_and_job_loss(self):
        server = Server()
        server.patch_error_phase = "working"
        with server.context(), self.assertRaises(worker.Stop):
            worker.launch(plan())
        self.assertEqual(server.state()["phase"], "dispatch_reserved")
        server.patch_error_phase = None
        with server.context():
            state, _ = worker.launch(plan())
        self.assertEqual(state["phase"], "working")
        self.assertEqual(len(server.posts()), 1)

    def test_definite_post_claim_failure_releases_and_allows_same_head_retry(self):
        for failure in ('read', 'label'):
            server = Server()
            live_target = worker.live_target
            calls = 0
            def live(pr, head):
                nonlocal calls
                calls += 1
                if calls == 2:
                    if failure == 'label': server.pull['labels'] = []
                    else: raise worker.Stop('GitHub unavailable before create')
                return live_target(pr, head)
            with self.subTest(failure=failure), server.context():
                with patch.object(worker, 'live_target', live), self.assertRaises(worker.Stop):
                    worker.launch(plan())
                self.assertEqual(server.state()['phase'], 'released')
                self.assertEqual(server.posts(), [])
                self.assertFalse(worker.pending_generic_claim(server.comments, PR))
                self.assertEqual(planner._round_markers(server.comments, trusted_login=worker.OWNER), [])
                server.pull['labels'] = [{'name': planner.LOOP_LABEL}]
                state, comment_id = worker.launch(plan())
                self.assertEqual((state['phase'], state['round'], comment_id), ('working', 1, 102))
                self.assertEqual(len(server.posts()), 1)

    def test_cancelled_prepared_claim_recovers_without_cursor_or_counted_cycle(self):
        server = Server()
        server.comments = [receipt(worker.prepare(plan())[0])]
        with server.context():
            states = worker.reconcile(PR)
            self.assertEqual(states[0]['phase'], 'released')
            self.assertEqual(server.posts(), [])
            self.assertFalse(any(c[0] == 'cursor' for c in server.calls))
            self.assertEqual(planner._round_markers(server.comments, trusted_login=worker.OWNER), [])
            state, _ = worker.launch(plan())
            self.assertEqual(state['phase'], 'working')
            self.assertEqual(len(server.posts()), 1)

    def test_failed_release_persistence_keeps_prepared_until_serialized_recovery(self):
        server = Server()
        server.patch_error_phase = 'released'
        live_target = worker.live_target
        calls = 0
        def live(pr, head):
            nonlocal calls
            calls += 1
            if calls == 2: raise worker.Stop('read failed before create')
            return live_target(pr, head)
        with server.context():
            with patch.object(worker, 'live_target', live), self.assertRaises(worker.Stop):
                worker.launch(plan())
            self.assertEqual(server.state()['phase'], 'prepared')
            self.assertTrue(worker.pending_generic_claim(server.comments, PR))
            self.assertEqual(server.posts(), [])
            server.patch_error_phase = None
            self.assertEqual(worker.reconcile(PR)[0]['phase'], 'released')
            self.assertFalse(any(c[0] == 'cursor' for c in server.calls))

    def test_cancellation_after_reserved_persistence_never_releases_or_reposts(self):
        server = Server()
        original_gh = server.gh
        def gh(path, **kwargs):
            result = original_gh(path, **kwargs)
            if kwargs.get('method') == 'PATCH' and worker.parse_body(kwargs['data']['body'])['phase'] == 'dispatch_reserved':
                raise KeyboardInterrupt('job cancelled before POST')
            return result
        with server.context(), patch.object(worker, 'gh', gh), self.assertRaises(KeyboardInterrupt):
            worker.launch(plan())
        self.assertEqual(server.state()['phase'], 'dispatch_reserved')
        self.assertEqual(server.posts(), [])
        server.lookup_error = '404 or unknown create'
        for operation in (lambda: worker.reconcile(PR), lambda: worker.launch(plan())):
            with server.context(), self.assertRaises(worker.Stop): operation()
        self.assertEqual(server.state()['phase'], 'dispatch_reserved')
        self.assertEqual(server.posts(), [])
        self.assertTrue(worker.pending_generic_claim(server.comments, PR))

    def test_terminal_recovery_is_get_only_even_for_closed_unlabelled_pr(self):
        server = Server()
        server.comments = [receipt(dict(worker.prepare(plan())[0], phase="dispatch_reserved"))]
        server.pull.update(state="closed", labels=[])
        server.run_status = "FINISHED"
        with server.context():
            states = worker.reconcile(PR)
            again = worker.reconcile(PR)
        self.assertEqual(states, again)
        self.assertEqual(server.state()["phase"], "terminal")
        self.assertEqual(server.agent_reads, 2)
        self.assertEqual(server.posts(), [])
        self.assertFalse(worker.pending_generic_claim(server.comments, PR))
        self.assertEqual(planner._round_markers(server.comments, trusted_login=worker.OWNER), [plan()["marker"]])
        self.assertFalse(any(c[0] == "gh" and c[2].endswith(f"/pulls/{PR}") for c in server.calls))

    def test_incomplete_or_changed_service_evidence_keeps_ownership(self):
        cases = [
            lambda s: setattr(s, "lookup_error", "missing agent"),
            lambda s: setattr(s, "run_status", "UNKNOWN"),
            lambda s: setattr(s, "mutate_agent", lambda a, n: a.update(id="wrong")),
            lambda s: setattr(s, "mutate_agent", lambda a, n: a.update(repos=[])),
            lambda s: setattr(s, "mutate_agent", lambda a, n: a["repos"][0].update(prUrl="https://github.com/other/repo/pull/11")),
            lambda s: setattr(s, "mutate_agent", lambda a, n: a.update(latestRunId="run-2") if n == 2 else None),
        ]
        for case in cases:
            server = Server()
            server.comments = [receipt(dict(worker.prepare(plan())[0], phase="dispatch_reserved"))]
            server.run_status = "FINISHED"
            case(server)
            with self.subTest(case=case), server.context(), self.assertRaises(worker.Stop):
                worker.reconcile(PR)
            self.assertTrue(worker.pending_generic_claim(server.comments, PR))
            self.assertEqual(server.posts(), [])

    def test_receipts_are_strict_bound_and_trusted(self):
        comment = receipt(worker.prepare(plan())[0])
        self.assertTrue(worker.pending_generic_claim([comment], PR))
        self.assertFalse(worker.pending_generic_claim([comment], PR, ignore_comment_id=101))
        for change in [lambda c: c.update(body=c["body"].replace("worker-v1", "worker-v2")),
                       lambda c: c.update(body=c["body"] + "quoted suffix"),
                       lambda c: c.update(issue_url=c["issue_url"] + "2"),
                       lambda c: c.update(id=True),
                       lambda c: c.update(body="<!-- codex-cursor-claim review:4 head:" + HEAD + " -->"),
                       lambda c: c.update(body=plan()["marker"]),
                       lambda c: c.update(body=c["body"].replace('"round":1', '"round":4'))]:
            malformed = copy.deepcopy(comment)
            change(malformed)
            with self.subTest(change=change), self.assertRaises(worker.Stop):
                worker.pending_generic_claim([malformed], PR)
            malformed["user"]["login"] = "outsider"
            self.assertFalse(worker.pending_generic_claim([malformed], PR))

    def test_plain_round_prose_from_other_worker_families_is_not_generic_state(self):
        comment = receipt(worker.prepare(plan())[0])
        comment["body"] = "Cursor remediation round 1\n\n<!-- goal-review-claim review:4 head:" + HEAD + " -->"
        self.assertFalse(worker.pending_generic_claim([comment], PR))

    def test_ordinary_owner_and_stale_eligibility_prevent_create(self):
        for scenario in ["ordinary", "closed", "head", "goal", "hold", "fork", "reservation"]:
            server = Server()
            if scenario == "ordinary":
                state = {"repo": worker.REPO, "pr": PR, "review": "9", "head": HEAD,
                         "agent_id": ordinary.agent_identity(worker.REPO, PR, "9", HEAD), "phase": "dispatch_reserved"}
                server.comments = [dict(receipt(worker.prepare(plan())[0]), body=ordinary.state_body(state))]
            elif scenario == "closed":
                server.pull["state"] = "closed"
            elif scenario == "head":
                server.pull["head"]["sha"] = "b" * 40
            elif scenario in {"goal", "hold"}:
                server.pull["labels"].append({"name": "goal" if scenario == "goal" else "human-review-required"})
            elif scenario == "fork":
                server.pull["head"]["repo"]["full_name"] = "other/repo"
            else:
                server.reserve_error = True
            with self.subTest(scenario=scenario), server.context(), self.assertRaises(RuntimeError):
                worker.launch(plan())
            self.assertEqual(server.posts(), [])

    def test_three_round_budget_and_environment_are_not_bypassed(self):
        server = Server()
        for review in (1, 2, 3):
            state = worker.prepare(plan(review, review))[0]
            state.update(phase="terminal", run_id=f"run-{review}", status="FINISHED")
            server.comments.append(receipt(state, review))
        with server.context(), self.assertRaises(worker.Stop):
            worker.launch(plan(4, 3))
        self.assertEqual(server.posts(), [])
        with server.context(), patch.dict(os.environ, TREMELAY_WORKER_ADMISSION=""), self.assertRaises(worker.Stop):
            worker.launch(plan())


class RealGenericWorkflow(unittest.TestCase):
    def shell(self, step_name):
        workflow = (ROOT / ".github/workflows/codex-cursor-remediation.yml").read_text()
        step = workflow.split(f"      - name: {step_name}\n", 1)[1].split("\n      - name:", 1)[0]
        return "\n".join(line[10:] for line in step.split("        run: |\n", 1)[1].splitlines())

    def test_real_workflow_uses_shared_lock_and_reconciliation_around_launch(self):
        workflow = (ROOT / ".github/workflows/codex-cursor-remediation.yml").read_text()
        self.assertIn("group: tremelay-worker-admission\n      cancel-in-progress: false", workflow)
        self.assertIn("TREMELAY_WORKER_ADMISSION: serialized-v1", workflow)
        self.assertNotIn("curl ", workflow)
        self.assertNotIn("cleanup_claim", workflow)
        self.assertLess(workflow.index("Reconcile existing generic worker receipts"), workflow.index("Build exact-head remediation plan"))
        self.assertGreater(workflow.index("Verify and persist generic worker terminal ownership"), workflow.index("Wait for Cursor remediation"))
        self.assertIn("if: always()", workflow.split("Verify and persist generic worker terminal ownership", 1)[1])
        self.assertIn("max_rounds=3", workflow)

    def test_actual_launch_and_reconcile_shell_run_helper_with_no_replay(self):
        # A Python executable shim patches only service boundaries, then executes
        # the actual workflow command and real helper entry point in subprocesses.
        wrapper = '''#!PYTHON
import json, os, pathlib, sys
sys.path.insert(0, TESTS)
from test_generic_worker import Server, worker
server = Server()
store = pathlib.Path("mock-server.json")
if store.exists():
    saved = json.loads(store.read_text())
    server.comments, server.calls = saved["comments"], [tuple(c) for c in saved["calls"]]
server.post_error = "ambiguous create"
server.lookup_error = "404"
try:
    with server.context():
        result = worker.main(sys.argv[2:])
finally:
    store.write_text(json.dumps({"comments":server.comments,"calls":server.calls}))
raise SystemExit(result)
'''.replace("PYTHON", sys.executable).replace("TESTS", repr(str(ROOT / "automation_tests")))
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            (temp / "plan.json").write_text(json.dumps(plan()))
            bindir = temp / "bin"
            bindir.mkdir()
            executable = bindir / "python"
            executable.write_text(wrapper)
            executable.chmod(0o755)
            env = dict(os.environ, **ENV, PATH=str(bindir) + os.pathsep + os.environ["PATH"],
                       PR_NUMBER=str(PR), GITHUB_OUTPUT=str(temp / "output"))
            for name in ["Claim review and launch Cursor Cloud Agent", "Claim review and launch Cursor Cloud Agent",
                         "Verify and persist generic worker terminal ownership"]:
                result = subprocess.run(["bash", "-c", self.shell(name)], cwd=temp, env=env,
                                        text=True, capture_output=True, timeout=10)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            saved = json.loads((temp / "mock-server.json").read_text())
            self.assertEqual(sum(c[:2] == ["cursor", "POST"] for c in saved["calls"]), 1)
            self.assertEqual(worker.parse_body(saved["comments"][0]["body"])["phase"], "dispatch_reserved")
            self.assertFalse(any(c[1] == "DELETE" for c in saved["calls"]))


if __name__ == "__main__":
    unittest.main()
