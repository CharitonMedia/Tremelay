import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import goal_agent_request as goal
import goal_review_launch as launch

HEAD = "a" * 40
AFTER = "b" * 40
PR = 11
REVIEW = "41"
CLAIM = {"status": "free", "owned": False, "marker": goal.review_claim_marker(REVIEW, HEAD),
         "review_id": REVIEW, "head": HEAD}
PAYLOAD = {"name": "Goal review on PR #11", "prompt": {"text": "Repair the legitimate review findings."},
           "repos": [{"url": f"https://github.com/{launch.REPO}",
                      "prUrl": f"https://github.com/{launch.REPO}/pull/{PR}"}],
           "workOnCurrentBranch": True, "autoCreatePR": False, "skipReviewerRequest": True}
PULL = {"number": PR, "state": "open", "draft": False, "merged_at": None,
        "user": {"login": goal.TRUSTED_AUTOMATION_LOGIN},
        "head": {"sha": AFTER, "ref": "goal/issue-10", "repo": {"full_name": launch.REPO}},
        "base": {"ref": "main", "repo": {"full_name": launch.REPO}},
        "body": "Goal-Issue: #10", "labels": [{"name": "goal"}, {"name": "human-review-required"}]}


def state(phase="dispatch_reserved"):
    value, _ = launch.prepare(launch.REPO, PR, CLAIM, PAYLOAD)
    if phase != "prepared":
        value = launch.transition(value, "dispatch_reserved")
    if phase in {"working", "terminal", "review_reserved", "completed"}:
        value = launch.transition(value, "working", {"agent": {"id": value["agent_id"]}, "run": {"id": "run-1"}})
    if phase in {"review_reserved", "completed"}:
        value.update(phase=phase, completed_head=AFTER)
    elif phase == "terminal":
        value.update(phase=phase, status="ERROR")
    return value


class Server:
    """In-memory fixture: network calls are fully mocked and Cursor has no writes."""
    def __init__(self, phase="dispatch_reserved", status="RUNNING"):
        self.state = state(phase)
        self.claim = {"id": 100, "user": {"login": goal.TRUSTED_AUTOMATION_LOGIN},
                      "issue_url": f"https://api.github.com/repos/{launch.REPO}/issues/{PR}",
                      "body": launch.state_body(self.state)}
        self.pull = copy.deepcopy(PULL)
        self.comments = []
        self.writes = []
        self.reads = []
        self.cursor_calls = []
        status = "FINISHED" if phase == "review_reserved" else status
        self.status = status
        self.agent = {"id": self.state["agent_id"], "latestRunId": "run-1", "workOnCurrentBranch": True,
                      "repos": [{"url": f"https://github.com/{launch.REPO}",
                                 "prUrl": f"https://github.com/{launch.REPO}/pull/{PR}"}]}
        self.run = {"id": "run-1", "agentId": self.state["agent_id"], "status": status}
        self.compare = {"status": "ahead"}
        self.login = goal.TRUSTED_AUTOMATION_LOGIN
        self.post_error = False
        self.patch_error_phase = None
        self.apply_failed_patch = False
        self.before_post_head = None

    def gh(self, path, *, method="GET", data=None, paginate=False):
        if method == "GET":
            self.reads.append(path)
            if path == "user":
                return {"login": self.login}
            if path == f"repos/{launch.REPO}/issues/comments/100":
                return copy.deepcopy(self.claim)
            if path == f"repos/{launch.REPO}/issues/10":
                return {"number": 10, "state": "open"}
            if path == f"repos/{launch.REPO}/pulls?state=all&per_page=100&page=1":
                return [copy.deepcopy(self.pull)]
            if path == f"repos/{launch.REPO}/pulls/{PR}":
                return copy.deepcopy(self.pull)
            if path == f"repos/{launch.REPO}/compare/{HEAD}...{AFTER}":
                return self.compare
            if path == f"repos/{launch.REPO}/issues/{PR}/comments?per_page=100":
                assert paginate
                if self.before_post_head:
                    self.pull["head"]["sha"] = self.before_post_head
                return [copy.deepcopy(self.comments)]
            raise AssertionError(path)
        assert not paginate
        self.writes.append((path, method, copy.deepcopy(data)))
        if method == "PATCH":
            assert path == f"repos/{launch.REPO}/issues/comments/100"
            target_phase = "released" if data["body"] == goal.released_body() else launch.parse_body(data["body"])["phase"]
            failed = self.patch_error_phase == target_phase
            if not failed or self.apply_failed_patch:
                self.claim["body"] = data["body"]
            if failed:
                raise launch.Stop("Ambiguous GitHub PATCH")
            return None
        if method == "POST":
            assert path == f"repos/{launch.REPO}/issues/{PR}/comments"
            self.comments.append({"id": len(self.comments) + 200,
                                  "user": {"login": goal.TRUSTED_AUTOMATION_LOGIN}, "body": data["body"]})
            if self.post_error:
                raise launch.Stop("Ambiguous GitHub POST")
            return self.comments[-1]
        raise AssertionError(method)

    def cursor(self, path, **kwargs):
        # Passing payload=None is also unnecessary; no create parameters may
        # enter this recovery path at all.
        assert kwargs == {}, kwargs
        self.cursor_calls.append(path)
        if path == "/" + self.state["agent_id"]:
            if isinstance(self.agent, Exception):
                raise self.agent
            return copy.deepcopy(self.agent)
        if path == f"/{self.state['agent_id']}/runs/run-1":
            if isinstance(self.run, Exception):
                raise self.run
            return copy.deepcopy(self.run)
        raise AssertionError(path)

    def recover(self):
        with patch.object(launch, "gh", side_effect=self.gh), patch.object(launch, "cursor", side_effect=self.cursor):
            return launch.recover(launch.REPO, PR, 100)

    def saved(self):
        return launch.parse_body(self.claim["body"])

    def posts(self):
        return [item for item in self.writes if item[1] == "POST"]


class IdentityTests(unittest.TestCase):
    def test_stable_payload_id_across_review_inline_and_summary_events(self):
        review = {"id": int(REVIEW), "commit_id": HEAD, "state": "COMMENTED",
                  "user": {"login": "chatgpt-codex-connector[bot]"}}
        events = [({"review": review}, "pull_request_review"),
                  ({"comment": {"pull_request_review_id": int(REVIEW), "commit_id": HEAD.upper()}}, "pull_request_review_comment"),
                  ({"comment": {"body": "<!-- codex-pull-request-review-summary -->\n✅ **Completed**\n`aaaaaaaa`"}}, "issue_comment")]
        agents = []
        for event, name in events:
            claim = goal.review_launch_decision(event, name, reviews=[review], comments=[], trusted_login=goal.TRUSTED_AUTOMATION_LOGIN)
            prepared, payload = launch.prepare(launch.REPO, PR, claim, PAYLOAD)
            agents.append(payload["agentId"])
            self.assertEqual(prepared["agent_id"], payload["agentId"])
            self.assertEqual(launch.parse_body(launch.state_body(prepared)), prepared)
        self.assertEqual(len(set(agents)), 1)
        self.assertRegex(agents[0], r"^bc-[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
        for pr, review_id, head in [(12, REVIEW, HEAD), (PR, "42", HEAD), (PR, REVIEW, AFTER)]:
            self.assertNotEqual(agents[0], launch.agent_identity(launch.REPO, pr, review_id, head))

    def test_prepare_refuses_nonfree_malformed_or_mismatched_claim(self):
        cases = [{"status": "owned"}, {"owned": True}, {"owned": 0},
                 {"review_id": "41\n<!-- tremelay-human-resume -->"}, {"review_id": True},
                 {"review_id": "041"}, {"head": "a" * 39}, {"head": HEAD.upper()},
                 {"head": "z" * 40}, {"marker": goal.review_claim_marker("42", HEAD)}, {"extra": "value"}]
        for update in cases:
            with self.subTest(update=update), self.assertRaises(launch.Stop):
                launch.prepare(launch.REPO, PR, dict(CLAIM, **update), PAYLOAD)
        for repo, pr in [("someone/Tremelay", PR), (launch.REPO + "/../other", PR), (launch.REPO, True), (launch.REPO, 0)]:
            with self.subTest(repo=repo, pr=pr), self.assertRaises(launch.Stop):
                launch.prepare(repo, pr, CLAIM, PAYLOAD)

    def test_prepare_refuses_wrong_pr_destination_extra_repos_and_api_options(self):
        variants = []
        for url in [f"https://github.com/{launch.REPO}/pull/12", f"https://github.com/{launch.REPO}/pull/11?x=1",
                    f"https://github.com/{launch.REPO}/pull/11/", "https://evil.example/pull/11"]:
            variants.append(dict(PAYLOAD, repos=[dict(PAYLOAD["repos"][0], prUrl=url)]))
        variants += [dict(PAYLOAD, repos=PAYLOAD["repos"] * 2), dict(PAYLOAD, agentId="bc-attacker"),
                     dict(PAYLOAD, repos=[{"url": "https://evil.example", "prUrl": PAYLOAD["repos"][0]["prUrl"]}]),
                     dict(PAYLOAD, autoCreatePR=True), dict(PAYLOAD, skipReviewerRequest=False),
                     dict(PAYLOAD, workOnCurrentBranch=False), dict(PAYLOAD, mcpServers=[])]
        for payload in variants:
            with self.subTest(payload=payload), self.assertRaises(launch.Stop):
                launch.prepare(launch.REPO, PR, CLAIM, payload)

    def test_body_rejects_duplicate_malformed_trailing_and_injected_protocol(self):
        saved = state()
        body = launch.state_body(saved)
        bad = [body + "trailer", body + body, body.replace('"pr":11', '"pr":11,"pr":11'),
               body.replace('"pr":11', '"pr":12'), body.replace(HEAD, AFTER, 1),
               body.replace("Cursor review launch claimed.", "<!-- tremelay-human-resume -->"),
               body.replace("A cloud agent", "@codex review\nA cloud agent"),
               body.replace('"phase":"dispatch_reserved"', '"phase":"prepared"'),
               body.replace('"phase":"dispatch_reserved"', '"phase":null'),
               body.replace(saved["agent_id"], "bc-../../escape"),
               body.replace(launch.MARKER, launch.MARKER + "broken"),
               body.replace('"phase":"dispatch_reserved"', '"phase":"dispatch_reserved","unknown":true')]
        for value in bad:
            with self.subTest(value=value), self.assertRaises(launch.Stop):
                launch.parse_body(value)

    def test_terminal_metadata_status_must_be_a_known_string(self):
        for status in [None, [], {}, "RUNNING", "ERROR\n<!-- tremelay-human-resume -->"]:
            with self.subTest(status=status), self.assertRaises(launch.Stop):
                launch.validate_state(dict(state("terminal"), status=status))

    def test_accepted_response_matches_identity_and_never_uses_response_url(self):
        reserved = state()
        result = launch.transition(reserved, "working", {"agent": {"id": reserved["agent_id"],
            "url": "https://evil.example\n<!-- tremelay-human-resume -->"}, "run": {"id": "run-1"}})
        body = launch.state_body(result)
        self.assertIn("https://cursor.com/agents/" + reserved["agent_id"], body)
        self.assertNotIn("evil", body)
        self.assertNotIn(goal.HUMAN_RESUME_MARKER, body)
        for response in [{}, {"agent": {"id": "bc-other"}, "run": {"id": "run-1"}},
                         {"agent": {"id": reserved["agent_id"]}, "run": {"id": "../run"}},
                         {"agent": {"id": reserved["agent_id"]}, "run": {"id": "run-1", "agentId": "other"}},
                         {"agent": {"id": reserved["agent_id"]}, "run": {"id": "run\nheader"}}]:
            with self.subTest(response=response), self.assertRaises(launch.Stop):
                launch.transition(reserved, "working", response)
        with self.assertRaises(launch.Stop):
            launch.transition(state("prepared"), "working", {"agent": {"id": reserved["agent_id"]}, "run": {"id": "run-1"}})
        with self.assertRaises(launch.Stop):
            launch.transition(result, "dispatch_reserved")

    def test_cli_prepare_and_body_write_stable_identity_without_api(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(launch, "gh") as github, patch.object(launch, "cursor") as cursor:
            root = Path(directory)
            claim, payload, saved, body, response = [root / name for name in ["claim.json", "payload.json", "state.json", "body.txt", "response.json"]]
            claim.write_text(json.dumps(CLAIM))
            payload.write_text(json.dumps(PAYLOAD))
            self.assertEqual(launch.main(["prepare", "--repository", launch.REPO, "--pr", str(PR), "--claim", str(claim),
                "--payload", str(payload), "--state", str(saved), "--body", str(body)]), 0)
            original = json.loads(saved.read_text())
            self.assertEqual(original["agent_id"], json.loads(payload.read_text())["agentId"])
            self.assertEqual(launch.parse_body(body.read_text()), original)
            self.assertEqual(launch.main(["body", "--state", str(saved), "--phase", "dispatch_reserved", "--body", str(body)]), 0)
            response.write_text(json.dumps({"agent": {"id": original["agent_id"]}, "run": {"id": "run-1"}}))
            self.assertEqual(launch.main(["body", "--state", str(saved), "--phase", "working", "--body", str(body), "--response", str(response)]), 0)
            self.assertEqual(json.loads(saved.read_text())["run_id"], "run-1")
            github.assert_not_called()
            cursor.assert_not_called()


class PendingClaimTests(unittest.TestCase):
    def test_newer_review_cannot_compete_with_any_pending_phase(self):
        for phase in ["prepared", "dispatch_reserved", "working", "review_reserved"]:
            server = Server(phase)
            self.assertTrue(launch.pending_claim([server.claim], launch.REPO, PR, goal.TRUSTED_AUTOMATION_LOGIN))
        for phase in ["terminal", "completed"]:
            server = Server(phase)
            self.assertFalse(launch.pending_claim([server.claim], launch.REPO, PR, goal.TRUSTED_AUTOMATION_LOGIN))

    def test_untrusted_claims_and_metadata_free_nonclaims_do_not_block_new_review(self):
        server = Server()
        server.claim["user"]["login"] = "outsider"
        nonclaim = {"user": {"login": goal.TRUSTED_AUTOMATION_LOGIN}, "body": "Waiting for independent review."}
        self.assertFalse(launch.pending_claim([server.claim, nonclaim], launch.REPO, PR, goal.TRUSTED_AUTOMATION_LOGIN))

    def test_malformed_trusted_record_fails_closed_even_after_valid_pending_record(self):
        server = Server()
        for body in [server.claim["body"] + "untrusted tail", "<!-- goal-review-launch-v1 -->", "<!-- goal-review-launch-v1 broken -->"]:
            bad = dict(server.claim, body=body, id=101)
            with self.subTest(body=body), self.assertRaises(launch.Stop):
                launch.pending_claim([server.claim, bad], launch.REPO, PR, goal.TRUSTED_AUTOMATION_LOGIN)

    def test_pending_claim_checks_owner_and_target_headers(self):
        for change in [{"issue_url": f"https://api.github.com/repos/{launch.REPO}/issues/12"}, {"id": True}]:
            server = Server()
            server.claim.update(change)
            with self.assertRaises(launch.Stop):
                launch.pending_claim([server.claim], launch.REPO, PR, goal.TRUSTED_AUTOMATION_LOGIN)
        server = Server()
        with self.assertRaises(launch.Stop):
            launch.pending_claim([server.claim], launch.REPO, PR, "outsider")
        with self.assertRaises(launch.Stop):
            launch.pending_claim([server.claim], launch.REPO, 12, goal.TRUSTED_AUTOMATION_LOGIN)


class RecoveryTests(unittest.TestCase):
    def test_prepared_release_is_idempotent_and_never_reads_cursor(self):
        server = Server("prepared")
        self.assertEqual(server.recover(), {"phase": "released"})
        self.assertEqual(server.claim["body"], goal.released_body())
        self.assertEqual(server.cursor_calls, [])
        self.assertFalse(goal.comment_counts_cycle(server.claim["body"]))
        self.assertEqual(server.recover(), {"phase": "released"})
        self.assertEqual(len(server.writes), 1)

    def test_workflow_shell_strips_newlines_without_invalidating_claim_or_causing_poll_writes(self):
        for phase in ["prepared", "dispatch_reserved", "working"]:
            server = Server(phase)
            server.claim["body"] = server.claim["body"].rstrip("\n")
            self.assertEqual(launch.parse_body(server.claim["body"]), server.state)
            result = server.recover()
            self.assertEqual(result["phase"], "released" if phase == "prepared" else "working")
            self.assertEqual(len(server.writes), 0 if phase == "working" else 1)
        server = Server("working")
        server.claim["body"] = server.claim["body"].rstrip("\n")
        server.recover()
        server.recover()
        self.assertEqual(server.writes, [])

    def test_repository_number_owner_and_comment_pr_are_checked_before_writes(self):
        for name, value in [("login", "outsider"), ("claim_user", "outsider"), ("claim_id", 101),
                            ("issue_url", f"https://api.github.com/repos/{launch.REPO}/issues/12"),
                            ("issue_url", f"https://api.github.com/repos/outsider/Tremelay/issues/{PR}")]:
            server = Server()
            if name == "claim_user":
                server.claim["user"]["login"] = value
            elif name == "claim_id":
                server.claim["id"] = value
            elif name == "issue_url":
                server.claim["issue_url"] = value
            else:
                setattr(server, name, value)
            with self.subTest(name=name, value=value), self.assertRaises(launch.Stop):
                server.recover()
            self.assertEqual(server.writes, [])
            self.assertEqual(server.cursor_calls, [])
        with patch.object(launch, "gh") as github, patch.object(launch, "cursor") as cursor:
            for repo, pr, comment in [("other/repo", PR, 100), (launch.REPO, True, 100), (launch.REPO, PR, -1)]:
                with self.assertRaises(launch.Stop):
                    launch.recover(repo, pr, comment)
            github.assert_not_called()
            cursor.assert_not_called()

    def test_comment_author_must_be_a_structured_verified_identity(self):
        for user in [None, [], "pattalkslaw-del", {}]:
            server = Server()
            server.claim["user"] = user
            with self.subTest(user=user), self.assertRaises(launch.Stop):
                server.recover()
            self.assertEqual(server.writes, [])
            self.assertEqual(server.cursor_calls, [])

    def test_metadata_pr_mismatch_is_not_authority_for_another_pr(self):
        server = Server()
        other = dict(server.state, pr=12, agent_id=launch.agent_identity(launch.REPO, 12, REVIEW, HEAD))
        server.claim["body"] = launch.state_body(other)
        with self.assertRaises(launch.Stop):
            server.recover()
        self.assertEqual(server.cursor_calls, [])
        self.assertEqual(server.writes, [])

    def test_ambiguous_missing_or_404_worker_lookup_retains_reserved_claim(self):
        for result in [launch.Stop("404 not found"), launch.Stop("503 response ambiguous"), {}, None,
                       {"id": "different"}, {"id": state()["agent_id"], "latestRunId": "../escape"}]:
            server = Server()
            original = server.claim["body"]
            server.agent = result
            with self.subTest(result=result), self.assertRaises(launch.Stop):
                server.recover()
            self.assertEqual(server.claim["body"], original)
            self.assertEqual(server.writes, [])
            self.assertEqual(len(server.cursor_calls), 1)

    def test_accepted_lost_response_is_found_by_get_and_unchanged_polls_do_not_write(self):
        server = Server()
        saved = server.recover()
        self.assertEqual(saved["phase"], "working")
        self.assertEqual(saved["run_id"], "run-1")
        self.assertEqual(len(server.writes), 1)
        self.assertEqual(server.posts(), [])
        self.assertEqual(server.recover(), saved)
        self.assertEqual(len(server.writes), 1)
        self.assertEqual(server.cursor_calls, ["/" + saved["agent_id"], f"/{saved['agent_id']}/runs/run-1"] * 2)
        self.assertEqual(goal.cycle_budget([server.claim]), (1, 3))

    def test_run_lookup_failure_retains_recovered_identity_and_cycle(self):
        for result in [launch.Stop("404"), {"id": "different", "agentId": state()["agent_id"], "status": "FINISHED"},
                       {"id": "run-1", "agentId": "different", "status": "FINISHED"},
                       {"status": "FINISHED"}, {"id": "run-1", "agentId": state()["agent_id"], "status": "UNKNOWN"}]:
            server = Server()
            server.run = result
            with self.subTest(result=result), self.assertRaises(launch.Stop):
                server.recover()
            self.assertEqual(server.saved()["phase"], "working")
            self.assertEqual(server.saved()["run_id"], "run-1")
            self.assertEqual(server.posts(), [])
            self.assertEqual(goal.cycle_budget([server.claim]), (1, 3))

    def test_persisted_run_is_not_replaced_by_latest_run(self):
        server = Server("working")
        server.agent["latestRunId"] = "run-unrelated"
        with self.assertRaises(launch.Stop):
            server.recover()
        self.assertEqual(server.cursor_calls, ["/" + server.state["agent_id"]])
        self.assertEqual(server.writes, [])

    def test_terminal_errors_are_recorded_once_and_never_replaced(self):
        for status in ["ERROR", "CANCELLED", "EXPIRED"]:
            server = Server("working", status)
            result = server.recover()
            self.assertEqual(result["phase"], "terminal")
            self.assertEqual(result["status"], status)
            self.assertEqual(len(server.writes), 1)
            reads = list(server.cursor_calls)
            self.assertEqual(server.recover(), result)
            self.assertEqual(server.cursor_calls, reads)
            self.assertEqual(len(server.writes), 1)
            self.assertEqual(goal.cycle_budget([server.claim]), (1, 3))

    def test_finished_no_new_commit_is_terminal_and_counted_without_review(self):
        server = Server("working", "FINISHED")
        server.pull["head"]["sha"] = HEAD
        self.assertEqual(server.recover()["phase"], "terminal")
        self.assertEqual(server.saved()["status"], "FINISHED")
        self.assertEqual(server.posts(), [])
        self.assertEqual(goal.cycle_budget([server.claim]), (1, 3))
        server.recover()
        self.assertEqual(len(server.writes), 1)

    def test_finished_advancing_head_reserves_then_posts_once_and_keeps_stop_label(self):
        server = Server("working", "FINISHED")
        result = server.recover()
        self.assertEqual(result["phase"], "completed")
        self.assertEqual(result["completed_head"], AFTER)
        self.assertEqual([method for _, method, _ in server.writes], ["PATCH", "POST", "PATCH"])
        self.assertEqual(launch.parse_body(server.writes[0][2]["body"])["phase"], "review_reserved")
        self.assertIn(f"Review exact commit `{AFTER}`", server.posts()[0][2]["body"])
        self.assertIn({"name": "human-review-required"}, server.pull["labels"])
        self.assertFalse(any("labels" in path for path, _, _ in server.writes))
        self.assertEqual(goal.cycle_budget([server.claim]), (1, 3))
        self.assertNotIn(goal.HUMAN_RESUME_MARKER, server.claim["body"])
        cursor_calls = list(server.cursor_calls)
        server.recover()
        self.assertEqual(len(server.posts()), 1)
        self.assertEqual(server.cursor_calls, cursor_calls)
        self.assertEqual(len(server.writes), 3)

    def test_finished_rejects_closed_foreign_non_goal_or_moved_author(self):
        cases = [("draft", True), ("user", {"login": "other"}),
                 ("head", {"sha": AFTER, "repo": {"full_name": "other/repo"}}),
                 ("base", {"ref": "main", "repo": {"full_name": "other/repo"}}),
                 ("base", {"ref": "dev", "repo": {"full_name": launch.REPO}}),
                 ("body", "ordinary PR"), ("number", 12)]
        for key, value in cases:
            server = Server("working", "FINISHED")
            server.pull[key] = value
            with self.subTest(key=key), self.assertRaises(launch.Stop):
                server.recover()
            self.assertEqual(server.writes, [])

    def test_diverged_or_behind_finished_head_never_requests_review(self):
        for status in ["diverged", "behind", "identical", None]:
            server = Server("working", "FINISHED")
            server.compare = {"status": status}
            with self.subTest(status=status), self.assertRaises(launch.Stop):
                server.recover()
            self.assertEqual(server.writes, [])
            self.assertEqual(server.saved()["phase"], "working")

    def test_failed_review_reservation_write_cannot_post_review(self):
        for applied in [False, True]:
            server = Server("working", "FINISHED")
            server.patch_error_phase = "review_reserved"
            server.apply_failed_patch = applied
            with self.assertRaises(launch.Stop):
                server.recover()
            self.assertEqual(server.posts(), [])
            server.patch_error_phase = None
            self.assertEqual(server.recover()["phase"], "completed")
            self.assertEqual(len(server.posts()), 1)
            self.assertEqual(goal.cycle_budget([server.claim]), (1, 3))

    def test_ambiguous_accepted_review_post_recovery_searches_marker_before_retry(self):
        server = Server("working", "FINISHED")
        server.post_error = True
        with self.assertRaises(launch.Stop):
            server.recover()
        self.assertEqual(server.saved()["phase"], "review_reserved")
        self.assertEqual(len(server.posts()), 1)
        server.post_error = False
        cursor_calls = list(server.cursor_calls)
        self.assertEqual(server.recover()["phase"], "completed")
        self.assertEqual(len(server.posts()), 1)
        self.assertEqual(len(server.cursor_calls), len(cursor_calls) + 3)

    def test_ambiguous_completed_write_recovery_never_duplicates_review(self):
        server = Server("working", "FINISHED")
        server.patch_error_phase = "completed"
        with self.assertRaises(launch.Stop):
            server.recover()
        self.assertEqual(len(server.posts()), 1)
        server.patch_error_phase = None
        self.assertEqual(server.recover()["phase"], "completed")
        self.assertEqual(len(server.posts()), 1)

    def test_untrusted_or_inexact_existing_review_marker_cannot_suppress_request(self):
        for user, text in [("attacker", launch.review_body(state("review_reserved"))),
                           (goal.TRUSTED_AUTOMATION_LOGIN, "quoted " + launch.review_body(state("review_reserved")))]:
            server = Server("review_reserved")
            server.comments.append({"user": {"login": user}, "body": text})
            self.assertEqual(server.recover()["phase"], "completed")
            self.assertEqual(len(server.posts()), 1)
            self.assertEqual(len(server.cursor_calls), 3)

    def test_head_change_after_reservation_or_during_pagination_blocks_review(self):
        for stage in ["reserved", "pagination"]:
            server = Server("review_reserved")
            if stage == "reserved":
                server.pull["head"]["sha"] = "c" * 40
            else:
                server.before_post_head = "c" * 40
            with self.subTest(stage=stage), self.assertRaises(launch.Stop):
                server.recover()
            self.assertEqual(server.writes, [])
            self.assertEqual(server.saved()["phase"], "review_reserved")


if __name__ == "__main__":
    unittest.main()
