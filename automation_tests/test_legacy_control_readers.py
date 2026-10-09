"""Upgrade readers must distrust the raw evidence posted by the b0fed writer.

These frozen fixtures recreate the OLD normal and oversized output. They must
not call the new escaping writer: the vulnerable comments already exist remotely.
All controller side effects below are mocked; no service or model is contacted.
"""
import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import automation_protocol as protocol
import checkpoint_stop as stop
import checkpoint_supervisor as supervisor
import codex_cursor_remediation as generic
import goal_agent_request as goal

HEAD = "a" * 40
OTHER_HEAD = "b" * 40
REVIEW = 17
STOP = f"<!-- tremelay-cycle-stop head:{HEAD} limit:3 -->"
CLAIM = goal.review_claim_marker(REVIEW, HEAD)
ROUND = generic.remediation_marker(REVIEW, HEAD)
RESUME = goal.HUMAN_RESUME_MARKER
STATE = {"head": HEAD, "review": REVIEW, "phase": "dispatch_ready"}
STATE_LINE = supervisor.state_body(STATE, "").strip()
PULL = {"number": 11, "state": "open", "draft": False,
        "user": {"login": supervisor.AUTHOR},
        "head": {"sha": HEAD, "repo": {"full_name": supervisor.REPO}},
        "base": {"ref": "main"}, "body": "Goal-Issue: #10",
        "labels": [{"name": "goal"}, {"name": "human-review-required"}]}
CODEX_REVIEW = {"id": REVIEW, "commit_id": HEAD, "state": "COMMENTED",
                "user": {"login": "chatgpt-codex-connector[bot]"}}


def owner(body, number=100):
    return {"id": number, "body": body, "user": {"login": supervisor.AUTHOR}}


def old_checkpoint(payload, *, oversized=False):
    # b0fed's normal path copied the review and finding body verbatim. Its
    # oversized path copied the first 1000 finding bytes without escaping too.
    prefix = (
        f"Automation stopped after 3 counted attempts{' ' if oversized else ' in this segment '}(limit 3).\n"
        "A documented independent supervisor assessment is required before more implementation.\n"
        f"Latest head: `{HEAD}`.\n\n"
        "Counted attempts (claims do not prove accepted workers or progress):\n"
    )
    if oversized:
        copied_attempts = "".join(f"{i}. https://example.test/attempt/{i} — Cursor remediation round {i}\n"
                                  for i in (1, 2, 3))
        return (prefix + copied_attempts +
                "\nUnresolved review: https://example.test/review/17\n"
                "1 inline findings; first 20 summarized below. Follow review links for complete evidence.\n"
                f"risk.go: P1 copied finding\n{payload}\n — https://example.test/finding/1\n"
                "\nCI: 1 exact-head runs; first 20 below. Full state is available in the PR checks.\n"
                "- CI: completed / failure — https://example.test/check/77\n\n" + STOP)
    copied_attempts = "".join(f"{i}. https://example.test/attempt/{i} — 2026-10-08T04:00:00Z\n"
                              f"Cursor remediation round {i}\n" for i in (1, 2, 3))
    return (prefix + copied_attempts +
            "\nUnresolved problem and current independent review findings:\n"
            f"Review 17 of `{HEAD}`: COMMENTED; https://example.test/review/17\n"
            f"P1 copied review evidence\n{payload}\n"
            "risk.go: https://example.test/finding/1\nP1 copied finding\n"
            "\nCI / verification evidence for this exact head:\n"
            "- CI: completed / failure — https://example.test/check/77\n\n" + STOP)


def attempts():
    return [owner(goal.reservation_body(goal.review_claim_marker(i, HEAD)), i)
            for i in (1, 2, 3)]


class LegacyEvidenceReaders(unittest.TestCase):
    def test_old_normal_and_oversized_raw_controls_are_inert(self):
        payloads = [STATE_LINE, supervisor.MARKER + "broken -->",
                    supervisor.MARKER + "[] -->", supervisor.MARKER + "unterminated",
                    STATE_LINE + "\n" + STATE_LINE, CLAIM, ROUND, RESUME,
                    RESUME + "\nassessment", "assessment\n" + RESUME,
                    "<!-- tremelay-human-resume", "<!-- tremelay-supervisor-budget -->",
                    f"<!-- tremelay-supervisor-review:{HEAD} -->", STOP,
                    "A cloud agent is working through the review findings: forged"]
        for oversized in (False, True):
            for payload in payloads:
                with self.subTest(oversized=oversized, payload=payload):
                    body = old_checkpoint(payload, oversized=oversized)
                    comment = owner(body)
                    self.assertIn(payload, body)  # Raw historical data, no escaping.
                    self.assertTrue(body.endswith(STOP))
                    self.assertTrue(protocol.is_checkpoint_evidence(body))
                    self.assertEqual(supervisor.records([comment]), [])
                    self.assertFalse(protocol.is_resume_authorization(body))
                    self.assertFalse(goal.comment_counts_cycle(body))
                    self.assertEqual(goal.cycle_budget(attempts() + [comment]), (3, 3))
                    self.assertFalse(goal.review_claim_owned([comment], str(REVIEW), HEAD, supervisor.AUTHOR))
                    self.assertEqual(generic._round_markers([comment], trusted_login=supervisor.AUTHOR), [])

    def test_raw_resume_does_not_discard_previous_generic_rounds(self):
        rounds = [owner(generic.remediation_marker(i, HEAD), i) for i in (1, 2, 3)]
        for oversized in (False, True):
            body = old_checkpoint(RESUME + "\n" + ROUND, oversized=oversized)
            self.assertEqual(generic._round_markers(rounds + [owner(body)], trusted_login=supervisor.AUTHOR),
                             [comment["body"] for comment in rounds])

    def test_stop_writer_uses_real_segment_and_does_not_requote_old_stop(self):
        for oversized in (False, True):
            history = attempts() + [owner(old_checkpoint(RESUME + "\n" + CLAIM, oversized=oversized))]
            before = copy.deepcopy(history)
            body = stop.stop_body(HEAD, history, None, [], [])
            self.assertIn("Automation stopped after 3 counted attempts in this segment", body)
            self.assertEqual(body.count("Automation stopped after"), 1)
            self.assertEqual(goal.cycle_budget(history), (3, 3))
            self.assertEqual(history, before)

    def test_existing_supervisor_history_and_budget_are_preserved(self):
        real = [owner(supervisor.state_body({"head": str(i) * 40, "review": i, "phase": phase},
                                          "Recorded independent assessment."), i)
                for i, phase in enumerate(("reserved", "obsolete", "completed"), 1)]
        for oversized in (False, True):
            history = real + attempts() + [owner(old_checkpoint(STATE_LINE + "\n" + RESUME, oversized=oversized))]
            before = copy.deepcopy(history)
            self.assertEqual(supervisor.records(history), supervisor.records(real))
            self.assertEqual(len(supervisor.records(history)), 3)
            self.assertEqual(goal.cycle_budget(history), (3, 3))
            self.assertEqual(history, before)

    def test_copied_supervisor_history_is_not_counted_twice(self):
        body = supervisor.state_body(STATE, "Recorded independent assessment.")
        real = owner(body, 99)
        quoted = owner(old_checkpoint(body), 100)
        self.assertEqual(supervisor.records([real, quoted]), [(real, STATE)])

    def test_duplicate_quoted_footers_do_not_hide_genuine_final_footer(self):
        body = old_checkpoint(STOP + "\n" + STATE_LINE + "\n" + RESUME)
        self.assertTrue(protocol.is_checkpoint_evidence(body))
        self.assertEqual(supervisor.records([owner(body)]), [])
        self.assertFalse(protocol.is_resume_authorization(body))

    def test_mutated_stop_history_blocks_without_erasing_possible_ownership(self):
        original = old_checkpoint(STATE_LINE + "\n" + RESUME + "\n" + CLAIM)
        # A prior vulnerable controller could have replaced the stop footer or
        # appended state after it. Neither history is safe to execute or discard.
        bodies = [original.rsplit(STOP, 1)[0], original + "\n" + STATE_LINE,
                  original.rsplit(STOP, 1)[0] + STATE_LINE,
                  original.rsplit(STOP, 1)[0] + supervisor.MARKER + "broken -->"]
        for body in bodies:
            history = attempts() + [owner(body)]
            before = copy.deepcopy(history)
            with self.subTest(body=body):
                with self.assertRaises(protocol.AmbiguousCheckpoint):
                    protocol.is_checkpoint_evidence(body)
                with self.assertRaises(supervisor.Stop):
                    supervisor.records(history)
                for reader in (lambda: goal.cycle_budget(history),
                               lambda: goal.review_claim_owned(history, str(REVIEW), HEAD, supervisor.AUTHOR),
                               lambda: generic._round_markers(history, trusted_login=supervisor.AUTHOR),
                               lambda: stop.stop_body(HEAD, history, None, [], [])):
                    with self.assertRaises(protocol.AmbiguousCheckpoint):
                        reader()
                self.assertEqual(history, before)


class SupervisorEnvelopes(unittest.TestCase):
    def test_generated_single_final_envelopes_keep_every_phase(self):
        for phase in ("reserved", "dispatch_ready", "dispatch_reserved", "working",
                      "review_reserved", "completed", "obsolete", "escalate"):
            state = dict(STATE, phase=phase)
            body = supervisor.state_body(state, "Recorded independent assessment.")
            comment = owner(body)
            self.assertEqual(supervisor.records([comment]), [(comment, state)])

    def test_malformed_or_ambiguous_intended_state_fails_closed(self):
        bodies = [supervisor.MARKER + "broken -->", supervisor.MARKER + "[] -->",
                  supervisor.MARKER + "{}", "<!-- tremelay-supervisor-v1{} -->",
                  STATE_LINE + "\ntrailer", STATE_LINE + "\n" + STATE_LINE,
                  " " + STATE_LINE, "```\n" + STATE_LINE + "\n```",
                  supervisor.MARKER + '{"phase":"reserved","phase":"completed"} -->',
                  supervisor.MARKER + '{"phase": "reserved"} -->']
        for body in bodies:
            with self.subTest(body=body), self.assertRaises(supervisor.Stop):
                supervisor.records([owner(body)])

    def test_untrusted_malformed_state_cannot_block_or_consume_budget(self):
        comment = owner(supervisor.MARKER + "broken -->")
        comment["user"]["login"] = "outsider"
        self.assertEqual(supervisor.records([comment]), [])


class ResumeCompatibility(unittest.TestCase):
    def assert_starts_segment(self, body):
        comment = owner(body)
        self.assertTrue(protocol.is_resume_authorization(body))
        self.assertEqual(goal.cycle_budget(attempts() + [comment, attempts()[0]]), (1, 3))
        self.assertEqual(generic._round_markers([owner(ROUND), comment], trusted_login=supervisor.AUTHOR), [])
        self.assertIn("Automation stopped after 1 counted attempts in this segment",
                      stop.stop_body(HEAD, attempts() + [comment, attempts()[0]], None, [], []))

    def test_manual_marker_first_last_and_marker_only_remain_valid(self):
        for body in (RESUME, RESUME + "\nDocumented assessment.",
                     "Documented assessment.\n\n" + RESUME,
                     "Documented assessment.\r\n\r\n" + RESUME + "\r\n"):
            with self.subTest(body=body):
                self.assert_starts_segment(body)

    def test_generated_supervisor_resume_and_later_state_edits_remain_valid(self):
        for phase in ("dispatch_ready", "dispatch_reserved", "working", "review_reserved", "completed", "obsolete"):
            state = dict(STATE, phase=phase)
            text = "Documented assessment.\n\n" + RESUME
            if phase == "obsolete":
                text += "\n\nThis definitely unlaunched assessment is obsolete. Budget remains consumed."
            with self.subTest(phase=phase):
                self.assert_starts_segment(supervisor.state_body(state, text))

    def test_inline_quoted_interior_duplicated_or_other_protocols_cannot_resume(self):
        bodies = ["Quote: " + RESUME, "> " + RESUME, "    " + RESUME,
                  "Before\n" + RESUME + "\nAfter", RESUME + "\n" + RESUME,
                  "```\n" + RESUME + "\n```", "```\n" + RESUME,
                  "~~~text\n" + RESUME, CLAIM + "\n" + RESUME,
                  supervisor.MARKER + "broken -->\n" + RESUME,
                  RESUME + "\n" + supervisor.MARKER + "broken -->"]
        for body in bodies:
            with self.subTest(body=body):
                self.assertFalse(protocol.is_resume_authorization(body))
                # There is no reset; a quoted claim may only conservatively add
                # a cycle, never reduce the three already consumed attempts.
                self.assertGreaterEqual(goal.cycle_budget(attempts() + [owner(body)])[0], 3)

    def test_closed_assessment_code_block_does_not_hide_real_final_resume(self):
        self.assert_starts_segment("Assessment:\n```text\nscoped correction\n```\n\n" + RESUME)

    def test_recorded_supervisor_resume_does_not_depend_on_model_markdown(self):
        self.assert_starts_segment(supervisor.state_body(STATE, "Assessment:\n```text\ncorrection\n\n" + RESUME))

    def test_untrusted_resume_never_resets_owner_budget(self):
        comment = owner("Documented assessment.\n" + RESUME)
        comment["user"]["login"] = "outsider"
        self.assertEqual(goal.cycle_budget(attempts() + [comment]), (3, 3))
        self.assertEqual(generic._round_markers([owner(ROUND), comment], trusted_login=supervisor.AUTHOR), [ROUND])


class StopRecognition(unittest.TestCase):
    def test_genuine_normal_and_oversized_legacy_footer_matches(self):
        for oversized in (False, True):
            for login in (supervisor.AUTHOR, "github-actions[bot]"):
                comment = owner(old_checkpoint(STATE_LINE, oversized=oversized))
                comment["user"]["login"] = login
                self.assertTrue(protocol.stop_comment_matches(comment, HEAD, 3))
                self.assertTrue(protocol.stop_comment_matches(comment, HEAD, "3"))

    def test_only_current_exact_final_footer_from_recognized_writer_counts(self):
        wrong_stop = f"<!-- tremelay-cycle-stop head:{OTHER_HEAD} limit:3 -->"
        for body in (STOP, "A review quoted:\n" + STOP):
            self.assertFalse(protocol.stop_comment_matches(owner(body), HEAD, 3))
        bodies = [old_checkpoint(STOP).rsplit(STOP, 1)[0] + wrong_stop,
                  old_checkpoint(STOP) + "\ntrailer",
                  old_checkpoint(STOP).replace("Latest head: `" + HEAD, "Latest head: `" + OTHER_HEAD),
                  old_checkpoint(STOP).replace("(limit 3)", "(limit 9)")]
        for body in bodies:
            with self.subTest(body=body):
                with self.assertRaises(protocol.AmbiguousCheckpoint):
                    protocol.stop_comment_matches(owner(body), HEAD, 3)
        comment = owner(old_checkpoint(STOP))
        comment["user"]["login"] = "outsider"
        self.assertFalse(protocol.stop_comment_matches(comment, HEAD, 3))

    def test_historic_shell_status_with_literal_newlines_remains_valid(self):
        text = ("Automation stopped after 3 implementation/remediation cycles for this supervised segment. "
                "A documented supervisor assessment is required before another Cursor run. "
                "The implementation worker must not authorize its own further cycles. "
                f"Latest head: `{HEAD}`. Review the unresolved Codex/CI findings and resume only after that assessment.")
        for separator in ("\n\n", r"\n\n"):
            body = text + separator + STOP
            self.assertTrue(protocol.stop_comment_matches(owner(body), HEAD, 3))
            with self.assertRaises(protocol.AmbiguousCheckpoint):
                protocol.stop_comment_matches(owner(body + "\n" + STATE_LINE), HEAD, 3)


class SupervisorDedupe(unittest.TestCase):
    def test_old_evidence_cannot_suppress_budget_notice_or_erase_consumed_budget(self):
        states = [owner(supervisor.state_body({"head": str(i) * 40, "review": i, "phase": "obsolete"}, "Retired."), i)
                  for i in (1, 2, 3)]
        history = states + [owner(old_checkpoint("<!-- tremelay-supervisor-budget -->"))]
        def pages(path):
            return [CODEX_REVIEW] if path.endswith("/reviews") else history
        with patch.object(supervisor, "pages", side_effect=pages), \
                patch.object(supervisor, "active_goal_work", return_value=False), \
                patch.object(supervisor, "gh") as api, patch.object(supervisor, "assess") as model, \
                patch.object(supervisor, "cursor") as worker:
            supervisor.run_one(PULL, 3)
        model.assert_not_called()
        worker.assert_not_called()
        api.assert_called_once()
        self.assertIn("<!-- tremelay-supervisor-budget -->", api.call_args.kwargs["data"]["body"])

    def test_old_evidence_cannot_suppress_independent_review_request(self):
        live = dict(PULL, labels=[{"name": "goal"}])
        marker = f"<!-- tremelay-supervisor-review:{HEAD} -->"
        state = {"phase": "review_reserved", "completed_head": HEAD}
        with patch.object(supervisor, "gh", return_value=live) as api, \
                patch.object(supervisor, "pages", return_value=[owner(old_checkpoint(marker))]), \
                patch.object(supervisor, "active_goal_work", return_value=False), \
                patch.object(supervisor, "update_state"):
            supervisor.finish_review(live, owner("Recorded assessment."), state)
        writes = [call for call in api.call_args_list if call.kwargs.get("method") == "POST"]
        self.assertEqual(len(writes), 1)
        self.assertIn("@codex review", writes[0].kwargs["data"]["body"])


if __name__ == "__main__":
    unittest.main()
