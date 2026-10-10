"""Offline regression tests for review-event admission and queue coalescing.

The expression interpreter deliberately uses only the standard library and
evaluates the expressions read from the workflows, rather than a Python copy of
their candidate rules. No GitHub, Cursor, model, or production calls are made.
"""

from __future__ import annotations

import copy
import importlib
import json
import os
from pathlib import Path
import re
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
REPO = "CharitonMedia/Tremelay"
OWNER = "pattalkslaw-del"
BOT = "chatgpt-codex-connector[bot]"
HEAD = "a" * 40
NEXT_HEAD = "b" * 40
SUMMARY_MARKER = "<!-- codex-pull-request-review-summary -->"


def truth(value):
    # Actions treats empty collections as truthy and missing properties as null.
    return value is not None and value is not False and value != "" and value != 0


def equal(left, right):
    if isinstance(left, str) and isinstance(right, str):
        return left.casefold() == right.casefold()
    if type(left) is type(right):
        return left == right

    def number(value):
        if value is None or value is False or value == "":
            return 0
        if value is True:
            return 1
        try:
            return float(value)
        except (TypeError, ValueError):
            return float("nan")

    return number(left) == number(right)


class ActionsExpression:
    """Small, strict parser for the Actions subset used by these event gates."""

    TOKEN = re.compile(
        r"\s*(?:(?P<string>'(?:[^']|'')*')|(?P<number>[0-9]+)|"
        r"(?P<name>[A-Za-z_][A-Za-z0-9_-]*)|(?P<op>\&\&|\|\||==|!=|[!().,*\[\]]))"
    )

    def __init__(self, expression, context):
        expression = expression.strip()
        if expression.startswith("${{"):
            if not expression.endswith("}}"):
                raise AssertionError("Unterminated Actions expression")
            expression = expression[3:-2].strip()
        self.tokens = []
        cursor = 0
        while cursor < len(expression):
            found = self.TOKEN.match(expression, cursor)
            if found is None:
                raise AssertionError(f"Unsupported Actions expression near {expression[cursor:]!r}")
            self.tokens.append((found.lastgroup, found.group(found.lastgroup)))
            cursor = found.end()
        self.cursor = 0
        self.context = context

    def take(self, token=None):
        if self.cursor >= len(self.tokens):
            return None
        kind, value = self.tokens[self.cursor]
        if token is not None and value != token:
            return None
        self.cursor += 1
        return kind, value

    def require(self, token):
        if self.take(token) is None:
            raise AssertionError(f"Expected {token!r} at token {self.cursor}")

    def parse(self):
        value = self.or_expression()
        if self.cursor != len(self.tokens):
            raise AssertionError(f"Unexpected trailing tokens: {self.tokens[self.cursor:]!r}")
        return value

    def or_expression(self):
        value = self.and_expression()
        while self.take("||"):
            right = self.and_expression()
            value = value if truth(value) else right
        return value

    def and_expression(self):
        value = self.comparison()
        while self.take("&&"):
            right = self.comparison()
            value = right if truth(value) else value
        return value

    def comparison(self):
        value = self.unary()
        while self.cursor < len(self.tokens) and self.tokens[self.cursor][1] in {"==", "!="}:
            operator = self.take()[1]
            right = self.unary()
            value = equal(value, right) if operator == "==" else not equal(value, right)
        return value

    def unary(self):
        if self.take("!"):
            return not truth(self.unary())
        return self.primary()

    def primary(self):
        token = self.take()
        if token is None:
            raise AssertionError("Unexpected end of Actions expression")
        kind, value = token
        if value == "(":
            result = self.or_expression()
            self.require(")")
            return result
        if kind == "string":
            return value[1:-1].replace("''", "'")
        if kind == "number":
            return int(value)
        if kind != "name":
            raise AssertionError(f"Unexpected token: {token!r}")
        if value in {"true", "false", "null"}:
            return {"true": True, "false": False, "null": None}[value]
        if self.take("("):
            arguments = []
            if not self.take(")"):
                while True:
                    arguments.append(self.or_expression())
                    if self.take(")"):
                        break
                    self.require(",")
            return self.call(value, arguments)
        result = self.context.get(value)
        while self.take("."):
            property_token = self.take()
            if property_token is None or property_token[0] != "name" and property_token[1] != "*":
                raise AssertionError("Expected property or wildcard")
            key = property_token[1]
            if key == "*":
                result = list(result.values()) if isinstance(result, dict) else result if isinstance(result, list) else []
            elif isinstance(result, list):
                result = [item.get(key) for item in result if isinstance(item, dict) and key in item]
            else:
                result = result.get(key) if isinstance(result, dict) else None
        return result

    @staticmethod
    def call(name, arguments):
        def string(value):
            if value is None:
                return ""
            if isinstance(value, bool):
                return str(value).lower()
            return str(value)

        if name == "contains" and len(arguments) == 2:
            haystack, needle = arguments
            if isinstance(haystack, list):
                return any(equal(item, needle) for item in haystack)
            return string(needle).casefold() in string(haystack).casefold()
        if name == "format" and arguments:
            return arguments[0].format(*(string(value) for value in arguments[1:]))
        if name == "startsWith" and len(arguments) == 2:
            return string(arguments[0]).casefold().startswith(string(arguments[1]).casefold())
        if name == "always" and not arguments:
            return True
        raise AssertionError(f"Unsupported Actions function {name!r}")


def evaluate(expression, event, event_name, *, run_id=500, needs=None, steps=None):
    return ActionsExpression(expression, {
        "github": {"event": event, "event_name": event_name, "repository": REPO,
                   "run_id": run_id, "run_attempt": 1, "workflow": "test-workflow",
                   "ref": "refs/heads/main", "actor": "untrusted-dispatcher"},
        "needs": needs or {},
        "steps": steps or {},
    }).parse()


def block(text, header, indent):
    lines = text.splitlines()
    starts = [index for index, line in enumerate(lines) if line == " " * indent + header + ":"]
    if len(starts) != 1:
        raise AssertionError(f"Expected one {header!r} block at indent {indent}")
    begin = starts[0] + 1
    end = begin
    while end < len(lines):
        line = lines[end]
        if line.strip() and not line.lstrip().startswith("#") and len(line) - len(line.lstrip()) <= indent:
            break
        end += 1
    return "\n".join(lines[begin:end])


def scalar(text, key, indent):
    lines = text.splitlines()
    prefix = " " * indent + key + ":"
    indices = [index for index, line in enumerate(lines) if line.startswith(prefix)]
    if len(indices) != 1:
        raise AssertionError(f"Expected one scalar {key!r} at indent {indent}")
    index = indices[0]
    value = lines[index][len(prefix):].strip()
    if value in {">", ">-", "|", "|-"}:
        parts = []
        for line in lines[index + 1:]:
            if line.strip() and len(line) - len(line.lstrip()) <= indent:
                break
            if line.strip() and not line.lstrip().startswith("#"):
                parts.append(line.strip())
        value = " ".join(parts)
    elif value.startswith('"'):
        value = json.loads(value)
    elif value.startswith("'") and value.endswith("'"):
        value = value[1:-1].replace("''", "'")
    return value


def pull(mode="goal"):
    return {
        "number": 29, "state": "open", "draft": False, "merged_at": None,
        "user": {"login": OWNER}, "html_url": f"https://github.com/{REPO}/pull/29",
        "url": f"https://api.github.com/repos/{REPO}/pulls/29",
        "body": "Goal-Issue: #28" if mode == "goal" else "Opted-in ordinary fix",
        "labels": [{"name": "goal" if mode == "goal" else "codex-cursor-loop"}],
        "head": {"sha": HEAD, "ref": "goal/issue-28" if mode == "goal" else "fix/admission",
                 "repo": {"full_name": REPO, "fork": False}},
        "base": {"ref": "main", "repo": {"full_name": REPO}},
    }


def review(review_id=101, *, state="COMMENTED", head=HEAD, body="", login=BOT):
    return {"id": review_id, "state": state, "commit_id": head,
            "submitted_at": f"2026-10-10T07:{review_id % 60:02d}:00Z",
            "user": {"login": login}, "body": body,
            "html_url": f"https://github.com/{REPO}/pull/29#pullrequestreview-{review_id}"}


def finding(comment_id=201, *, review_id=101, head=HEAD, login=BOT):
    return {"id": comment_id, "pull_request_review_id": review_id,
            "commit_id": head, "original_commit_id": head, "user": {"login": login},
            "body": "[P1] Recheck the current head before admitting a review.",
            "path": "scripts/example.py", "line": 17,
            "pull_request_url": f"https://api.github.com/repos/{REPO}/pulls/29"}


def summary_body(*, clean=False, completed=True, head=HEAD):
    body = "Codex Review: Didn't find any major issues." if clean else "[P1] Recheck the current head."
    return "\n".join([SUMMARY_MARKER, "✅ **Completed**" if completed else "Review in progress",
                      body, f"**Reviewed commit:** `{head}`"])


def event(kind="review", mode="goal", *, review_id=101, state="COMMENTED"):
    pr = pull(mode)
    result = {"repository": {"full_name": REPO}, "sender": {"login": "ordinary-user"}}
    if kind == "summary":
        issue = {key: copy.deepcopy(pr[key]) for key in ("number", "state", "body", "labels", "html_url", "user")}
        issue["pull_request"] = {"url": pr["url"]}
        result.update(action="edited", issue=issue,
                      comment={"id": 301, "user": {"login": BOT}, "body": summary_body(),
                               "issue_url": f"https://api.github.com/repos/{REPO}/issues/29"})
        return result, "issue_comment"
    result["pull_request"] = pr
    if kind == "inline":
        result.update(action="created", comment=finding(review_id=review_id))
        return result, "pull_request_review_comment"
    result.update(action="submitted", review=review(review_id, state=state))
    return result, "pull_request_review"


class ExpressionInterpreterTests(unittest.TestCase):
    def test_operator_precedence_missing_values_projection_and_escaping(self):
        payload, name = event()
        cases = {
            "false || true && !false": True,
            "(false || true) && false": False,
            "github.event.missing.child == null": True,
            "contains(github.event.pull_request.labels.*.name, 'GOAL')": True,
            "contains('Didn''t find issues', 'didn''t')": True,
            "format('review-{0}-{1}', github.event.review.id, github.event.review.commit_id)": "review-101-" + HEAD,
            "github.event.review.id || github.run_id": 101,
            "!github.event.issue.pull_request": True,
        }
        for expression, expected in cases.items():
            with self.subTest(expression=expression):
                self.assertEqual(evaluate(expression, payload, name), expected)

    def test_unsupported_syntax_is_rejected_instead_of_silently_accepted(self):
        for expression in ["false broken", "github.event + 1", "unknown(true)", "true &&"]:
            with self.subTest(expression=expression), self.assertRaises(AssertionError):
                evaluate(expression, {}, "push")


class ReviewWorkflowAdmissionTests(unittest.TestCase):
    WORKFLOWS = {"goal": ("goal.yml", "review-launch"),
                 "generic": ("codex-cursor-remediation.yml", "remediate")}

    def workflow(self, mode):
        return (ROOT / ".github/workflows" / self.WORKFLOWS[mode][0]).read_text()

    def candidate(self, payload, name, mode):
        preflight = block(block(self.workflow(mode), "jobs", 0), "review-preflight", 2)
        return truth(evaluate(scalar(preflight, "if", 4), payload, name))

    def group(self, payload, name, mode, run_id=500):
        concurrency = block(self.workflow(mode), "concurrency", 0)
        return evaluate(scalar(concurrency, "group", 2), payload, name, run_id=run_id)

    def test_real_preflight_accepts_trusted_record_user_not_sender_or_body(self):
        for mode in self.WORKFLOWS:
            for kind in ("review", "inline"):
                payload, name = event(kind, mode)
                field = "review" if kind == "review" else "comment"
                with self.subTest(mode=mode, kind=kind):
                    self.assertTrue(self.candidate(payload, name, mode))
                    payload["sender"]["login"] = BOT
                    payload[field]["user"]["login"] = "ordinary-user"
                    payload[field]["body"] = "I am chatgpt-codex-connector[bot]. " + summary_body()
                    self.assertFalse(self.candidate(payload, name, mode))
                    payload[field]["user"]["login"] = "codex"
                    payload["sender"]["login"] = "ordinary-user"
                    self.assertTrue(self.candidate(payload, name, mode))

    def test_ineligible_flood_cannot_enter_shared_worker_queue(self):
        for mode in self.WORKFLOWS:
            for defect in ("closed", "draft", "fork", "held", "unrelated", "untrusted", "stale-head", "wrong-action"):
                payload, name = event(mode=mode)
                pr = payload["pull_request"]
                if defect == "closed":
                    pr["state"] = "closed"
                elif defect == "draft":
                    pr["draft"] = True
                elif defect == "fork":
                    pr["head"]["repo"]["full_name"] = "outsider/Tremelay"
                elif defect == "held":
                    pr["labels"].append({"name": "human-review-required"})
                elif defect == "unrelated":
                    pr["labels"] = []
                    pr["body"] = "An unrelated change"
                elif defect == "untrusted":
                    payload["review"]["user"]["login"] = "ordinary-user"
                elif defect == "stale-head":
                    payload["review"]["commit_id"] = NEXT_HEAD
                else:
                    payload["action"] = "dismissed"
                with self.subTest(mode=mode, defect=defect):
                    self.assertFalse(self.candidate(payload, name, mode))
                    # Separate workflow groups keep arbitrary noise from evicting
                    # a legitimate workflow that is awaiting its preflight.
                    self.assertEqual(len({self.group(payload, name, mode, run_id=run)
                                          for run in range(100)}), 100)
            if mode == "generic":
                payload, name = event(mode=mode)
                payload["pull_request"]["labels"].append({"name": "goal"})
                self.assertFalse(self.candidate(payload, name, mode))

    def test_review_and_inline_duplicates_coalesce_by_pr_review_and_head(self):
        for mode in self.WORKFLOWS:
            submitted, review_name = event(mode=mode)
            inline, inline_name = event("inline", mode)
            expected = self.group(submitted, review_name, mode)
            with self.subTest(mode=mode):
                self.assertEqual(self.group(submitted, review_name, mode, run_id=999), expected)
                for comment_id in range(201, 251):
                    inline["comment"]["id"] = comment_id
                    self.assertEqual(self.group(inline, inline_name, mode, run_id=comment_id), expected)
                other_pr = copy.deepcopy(submitted)
                other_pr["pull_request"]["number"] = 30
                self.assertNotEqual(self.group(other_pr, review_name, mode), expected)
                other_head = copy.deepcopy(submitted)
                other_head["review"]["commit_id"] = NEXT_HEAD
                other_head["pull_request"]["head"]["sha"] = NEXT_HEAD
                self.assertNotEqual(self.group(other_head, review_name, mode), expected)

    def test_late_r1_inline_cannot_displace_r2_on_same_head(self):
        for mode in self.WORKFLOWS:
            r2, review_name = event(mode=mode, review_id=102)
            r1_inline, inline_name = event("inline", mode, review_id=101)
            with self.subTest(mode=mode):
                self.assertNotEqual(self.group(r2, review_name, mode),
                                    self.group(r1_inline, inline_name, mode))

    def test_approval_completion_has_own_namespace_and_no_generic_admission(self):
        approved, name = event(state="APPROVED")
        inline, inline_name = event("inline")
        self.assertTrue(self.candidate(approved, name, "goal"))
        self.assertNotEqual(self.group(approved, name, "goal"),
                            self.group(inline, inline_name, "goal"))
        generic, name = event(mode="generic", state="APPROVED")
        self.assertFalse(self.candidate(generic, name, "generic"))

    def test_summary_is_completed_trusted_and_keyed_by_comment_identity(self):
        payload, name = event("summary")
        self.assertTrue(self.candidate(payload, name, "goal"))
        expected = self.group(payload, name, "goal")
        payload["action"] = "created"
        self.assertEqual(self.group(payload, name, "goal", run_id=501), expected)
        payload["comment"]["id"] += 1
        self.assertNotEqual(self.group(payload, name, "goal"), expected)
        for body in ("Working on the review", summary_body(completed=False), summary_body(clean=True)):
            with self.subTest(body=body):
                payload["comment"]["body"] = body
                self.assertFalse(self.candidate(payload, name, "goal"))
        payload["comment"]["body"] = summary_body()
        payload["comment"]["user"]["login"] = "ordinary-user"
        payload["sender"]["login"] = BOT
        self.assertFalse(self.candidate(payload, name, "goal"))

    def test_clean_summary_still_reaches_existing_completion_job(self):
        payload, name = event("summary")
        payload["comment"]["body"] = summary_body(clean=True)
        completion = block(block(self.workflow("goal"), "jobs", 0), "codex-clean-complete", 2)
        self.assertTrue(truth(evaluate(scalar(completion, "if", 4), payload, name)))
        self.assertFalse(self.candidate(payload, name, "goal"))
        self.assertNotEqual(self.group(payload, name, "goal", 1), self.group(payload, name, "goal", 2))
        self.assertNotIn("tremelay-worker-admission", completion)
        self.assertIn("complete_codex_clean_review.py", completion)

    def test_main_push_manual_and_initial_issue_events_keep_unique_workflow_groups(self):
        for mode in self.WORKFLOWS:
            for name in ("push", "workflow_dispatch", "issues", "schedule"):
                payload = {"repository": {"full_name": REPO}, "action": "labeled",
                           "issue": {"number": 28}, "label": {"name": "goal"},
                           "inputs": {"recovery_pr": 29, "recovery_comment": 800}}
                with self.subTest(mode=mode, event=name):
                    self.assertFalse(self.candidate(payload, name, mode))
                    self.assertNotEqual(self.group(payload, name, mode, 1), self.group(payload, name, mode, 2))

    def test_workflow_coalescer_is_single_and_preflight_does_not_own_worker_lock(self):
        for mode, (_, downstream_name) in self.WORKFLOWS.items():
            workflow = self.workflow(mode)
            concurrency = block(workflow, "concurrency", 0)
            jobs = block(workflow, "jobs", 0)
            preflight = block(jobs, "review-preflight", 2)
            admitted = block(jobs, downstream_name, 2)
            with self.subTest(mode=mode):
                self.assertEqual(scalar(concurrency, "cancel-in-progress", 2), "false")
                self.assertEqual(scalar(concurrency, "queue", 2), "single")
                self.assertNotIn("tremelay-worker-admission", preflight)
                self.assertNotIn("secrets.", preflight)
                permissions = block(preflight, "permissions", 4)
                self.assertEqual({line.split(":", 1)[1].strip() for line in permissions.splitlines()}, {"read"})
                self.assertIn("ref: main", preflight)
                self.assertIn("--settle", preflight)
                self.assertEqual(scalar(admitted, "needs", 4), "review-preflight")
                guard = scalar(admitted, "if", 4)
                payload, name = event(mode=mode)
                for output in ("false", "", None):
                    self.assertFalse(truth(evaluate(guard, payload, name,
                        needs={"review-preflight": {"outputs": {"allowed": output}, "result": "success"}})))
                self.assertTrue(truth(evaluate(guard, payload, name,
                    needs={"review-preflight": {"outputs": {"allowed": "true"}, "result": "success"}})))
                locked = block(admitted, "concurrency", 4)
                self.assertEqual(scalar(locked, "group", 6), "tremelay-worker-admission")
                self.assertEqual(scalar(locked, "cancel-in-progress", 6), "false")
                self.assertEqual(scalar(locked, "queue", 6), "max")
                recheck = admitted.split("      - name: Recheck review admission before writes", 1)[1].split("      - ", 1)[0]
                self.assertIn("scripts/review_admission.py", recheck)
                self.assertNotIn("--settle", recheck)
                self.assertNotIn("secrets.", recheck)
                self.assertNotIn("sleep ", recheck)
                self.assertLess(admitted.index("Recheck review admission before writes"), admitted.index("secrets."))

    def test_rejected_locked_recheck_skips_every_later_step(self):
        for mode, (_, downstream_name) in self.WORKFLOWS.items():
            admitted = block(block(self.workflow(mode), "jobs", 0), downstream_name, 2)
            later = admitted.split("      - name: Recheck review admission before writes", 1)[1]
            later = later.split("      - ", 1)[1]
            steps = re.split(r"(?m)^      - ", "      - " + later)[1:]
            payload, name = event(mode=mode)
            for step in steps:
                with self.subTest(mode=mode, step=step.splitlines()[0]):
                    condition = scalar(step, "if", 8)
                    self.assertFalse(truth(evaluate(condition, payload, name,
                        steps={"admission": {"outputs": {"allowed": "false"}, "outcome": "success"}})))


class ReadFixtures:
    """Strict in-memory GitHub GET responses, with independently mutable state."""

    def __init__(self, mode="goal"):
        self.pull = pull(mode)
        self.source = {"number": 28, "state": "open"}
        self.reviews = [review()]
        self.inline = finding()
        self.comments = [copy.deepcopy(self.inline)]
        self.summary = event("summary")[0]["comment"]
        self.history = None
        self.calls = []
        self.sleeps = []
        self.on_sleep = None

    def read(self, path):
        self.calls.append(("read", path))
        if path == f"repos/{REPO}/pulls/29":
            value = self.pull
        elif path == f"repos/{REPO}/issues/28":
            value = self.source
        elif path == f"repos/{REPO}/pulls/comments/201":
            value = self.inline
        elif path == f"repos/{REPO}/issues/comments/301":
            value = self.summary
        elif re.fullmatch(f"repos/{REPO}/pulls/29/reviews/[0-9]+", path):
            number = int(path.rsplit("/", 1)[1])
            value = next((row for row in self.reviews if row["id"] == number), None)
        else:
            raise AssertionError(f"Unexpected read: {path}")
        return copy.deepcopy(value)

    def pages(self, path):
        self.calls.append(("pages", path))
        if path == f"repos/{REPO}/pulls?state=all":
            value = [self.pull] if self.history is None else self.history
        elif path == f"repos/{REPO}/pulls/29/reviews":
            value = self.reviews
        elif re.fullmatch(f"repos/{REPO}/pulls/29/reviews/[0-9]+/comments", path):
            number = int(path.split("/")[-2])
            value = [row for row in self.comments if row["pull_request_review_id"] == number]
        else:
            raise AssertionError(f"Unexpected paginated read: {path}")
        return copy.deepcopy(value)

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.calls.append(("sleep", seconds))
        if self.on_sleep:
            self.on_sleep(seconds)


class LiveReviewAdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.admission = importlib.import_module("review_admission")

    def prepare(self, payload, name, mode, fixture, *, settle=False):
        with patch("subprocess.run", side_effect=AssertionError("A fixture attempted an external command")):
            return self.admission.prepare_event(payload, name, mode, read=fixture.read,
                pages=fixture.pages, settle=settle, sleep=fixture.sleep)

    def assert_rejected(self, payload, name, mode, fixture, *, settle=False):
        try:
            result = self.prepare(payload, name, mode, fixture, settle=settle)
        except self.admission.lineage.LineageStop:
            return
        self.assertIsNone(result)

    def test_all_supported_event_shapes_recheck_without_mutating_input(self):
        for mode in ("goal", "generic"):
            for kind in ("review", "inline", "summary") if mode == "goal" else ("review", "inline"):
                payload, name = event(kind, mode)
                original = copy.deepcopy(payload)
                fixture = ReadFixtures(mode)
                with self.subTest(mode=mode, kind=kind):
                    result = self.prepare(payload, name, mode, fixture)
                    self.assertIsNotNone(result)
                    self.assertEqual(result["pull_request"], fixture.pull)
                    self.assertEqual(payload, original)
                    self.assertEqual(fixture.sleeps, [])

    def test_ineligible_snapshot_never_reads_or_sleeps(self):
        for mode in ("goal", "generic"):
            for kind in ("review", "inline"):
                for defect in ("untrusted", "closed", "draft", "fork", "held", "unrelated"):
                    payload, name = event(kind, mode)
                    fixture = ReadFixtures(mode)
                    pr = payload["pull_request"]
                    if defect == "untrusted":
                        payload["review" if kind == "review" else "comment"]["user"]["login"] = "outsider"
                        payload["sender"]["login"] = BOT
                    elif defect == "closed":
                        pr["state"] = "closed"
                    elif defect == "draft":
                        pr["draft"] = True
                    elif defect == "fork":
                        pr["head"]["repo"]["full_name"] = "outsider/Tremelay"
                    elif defect == "held":
                        pr["labels"].append({"name": "human-review-required"})
                    else:
                        pr["labels"] = []
                        pr["body"] = "Unrelated work"
                    with self.subTest(mode=mode, kind=kind, defect=defect):
                        self.assertFalse(self.admission.snapshot_candidate(payload, name, mode))
                        self.assertIsNone(self.prepare(payload, name, mode, fixture, settle=True))
                        self.assertEqual(fixture.calls, [])

    def test_live_head_or_eligibility_change_is_rejected_after_preflight(self):
        for mode in ("goal", "generic"):
            for defect in ("head", "closed", "draft", "fork", "held", "opt-out"):
                payload, name = event(mode=mode)
                fixture = ReadFixtures(mode)
                self.assertIsNotNone(self.prepare(payload, name, mode, fixture))
                if defect == "head":
                    fixture.pull["head"]["sha"] = NEXT_HEAD
                elif defect == "closed":
                    fixture.pull["state"] = "closed"
                elif defect == "draft":
                    fixture.pull["draft"] = True
                elif defect == "fork":
                    fixture.pull["head"]["repo"]["full_name"] = "outsider/Tremelay"
                elif defect == "held":
                    fixture.pull["labels"].append({"name": "human-review-required"})
                else:
                    fixture.pull["labels"] = []
                    fixture.pull["body"] = "No longer opted in"
                with self.subTest(mode=mode, defect=defect):
                    self.assert_rejected(payload, name, mode, fixture)
                    self.assertEqual(fixture.sleeps, [])

    def test_goal_source_closure_or_retired_lineage_is_rechecked(self):
        payload, name = event()
        for defect in ("closed-source", "merged-pr", "wrong-branch", "wrong-source"):
            fixture = ReadFixtures()
            self.assertIsNotNone(self.prepare(payload, name, "goal", fixture))
            if defect == "closed-source":
                fixture.source["state"] = "closed"
            elif defect == "merged-pr":
                older = copy.deepcopy(fixture.pull)
                older.update(number=27, state="closed", merged_at="2026-10-09T00:00:00Z")
                fixture.history = [older, fixture.pull]
            elif defect == "wrong-branch":
                fixture.pull["head"]["ref"] = "goal/issue-26"
            else:
                fixture.source["number"] = 26
            with self.subTest(defect=defect):
                self.assert_rejected(payload, name, "goal", fixture)

    def test_unmerged_closed_history_does_not_add_ownership_blocking(self):
        payload, name = event()
        fixture = ReadFixtures()
        older = copy.deepcopy(fixture.pull)
        older.update(number=27, state="closed")
        fixture.history = [older, fixture.pull]
        self.assertIsNotNone(self.prepare(payload, name, "goal", fixture))
        self.assertFalse(any("/issues/27/comments" in str(path) for _, path in fixture.calls))

    def test_settle_precedes_fresh_full_review_read_and_sees_late_finding(self):
        for mode in ("goal", "generic"):
            payload, name = event(mode=mode)
            fixture = ReadFixtures(mode)
            fixture.comments = []
            fixture.on_sleep = lambda seconds: fixture.comments.append(finding(comment_id=202))
            with self.subTest(mode=mode):
                self.assertIsNotNone(self.prepare(payload, name, mode, fixture, settle=True))
                self.assertEqual(fixture.sleeps, [20])
                self.assertEqual(fixture.calls[0], ("sleep", 20))
                self.assertIn(("pages", f"repos/{REPO}/pulls/29/reviews/101/comments"), fixture.calls)
                fixture.comments = []
                self.assert_rejected(payload, name, mode, fixture)
                self.assertEqual(fixture.sleeps, [20])

    def test_pending_review_waits_only_before_lock_and_rereads_final_state(self):
        payload, name = event("inline")
        fixture = ReadFixtures()
        fixture.reviews[0]["state"] = "PENDING"

        def publish_review(seconds):
            if seconds == 5:
                fixture.reviews[0]["state"] = "COMMENTED"

        fixture.on_sleep = publish_review
        self.assertIsNotNone(self.prepare(payload, name, "goal", fixture, settle=True))
        self.assertEqual(fixture.sleeps, [20, 5])
        fixture = ReadFixtures()
        fixture.reviews[0]["state"] = "PENDING"
        self.assert_rejected(payload, name, "goal", fixture)
        self.assertEqual(fixture.sleeps, [])

    def test_late_r1_cannot_override_newer_same_head_review_or_approval(self):
        for mode in ("goal", "generic"):
            for state in ("COMMENTED", "APPROVED"):
                for kind in ("review", "inline"):
                    payload, name = event(kind, mode)
                    fixture = ReadFixtures(mode)
                    fixture.reviews.append(review(102, state=state))
                    with self.subTest(mode=mode, state=state, kind=kind):
                        self.assert_rejected(payload, name, mode, fixture)

    def test_approval_is_independent_of_inline_findings_and_does_not_sleep(self):
        payload, name = event(state="APPROVED")
        fixture = ReadFixtures()
        fixture.reviews = [review(state="APPROVED")]
        fixture.comments = []
        admitted = self.prepare(payload, name, "goal", fixture, settle=True)
        self.assertIsNotNone(admitted)
        self.assertIsNone(self.admission.goal.build_payload(admitted, name))
        self.assertIsNotNone(self.admission.goal.terminal_plan(admitted, name, head_sha=HEAD))
        self.assertEqual(fixture.sleeps, [])
        self.assertFalse(any(path.endswith("/comments") for method, path in fixture.calls if method == "pages"))
        fixture.reviews[0]["state"] = "COMMENTED"
        self.assert_rejected(payload, name, "goal", fixture)

    def test_summary_uses_current_body_and_validates_live_comment_identity(self):
        payload, name = event("summary")
        fixture = ReadFixtures()
        fixture.summary["body"] = summary_body() + "\nCurrent amended summary."
        result = self.prepare(payload, name, "goal", fixture)
        self.assertEqual(result["comment"]["body"], fixture.summary["body"])
        self.assertNotEqual(result["comment"]["body"], payload["comment"]["body"])
        for defect in ("different-id", "foreign-pr", "untrusted", "clean", "incomplete", "stale-head", "deleted"):
            fixture = ReadFixtures()
            if defect == "different-id":
                fixture.summary["id"] = 999
            elif defect == "foreign-pr":
                fixture.summary["issue_url"] = f"https://api.github.com/repos/{REPO}/issues/30"
            elif defect == "untrusted":
                fixture.summary["user"]["login"] = "outsider"
            elif defect == "clean":
                fixture.summary["body"] = summary_body(clean=True)
            elif defect == "incomplete":
                fixture.summary["body"] = summary_body(completed=False)
            elif defect == "stale-head":
                fixture.summary["body"] = summary_body(head=NEXT_HEAD)
            else:
                fixture.summary = None
            with self.subTest(defect=defect):
                self.assert_rejected(payload, name, "goal", fixture)

    def test_inline_refresh_binds_user_review_head_comment_and_pr(self):
        for mode in ("goal", "generic"):
            for defect in ("untrusted", "review", "head", "comment", "pr", "empty"):
                payload, name = event("inline", mode)
                fixture = ReadFixtures(mode)
                if defect == "untrusted":
                    fixture.inline["user"]["login"] = "outsider"
                elif defect == "review":
                    fixture.inline["pull_request_review_id"] = 102
                elif defect == "head":
                    fixture.inline["commit_id"] = NEXT_HEAD
                elif defect == "comment":
                    fixture.inline["id"] = 202
                elif defect == "pr":
                    fixture.inline["pull_request_url"] = f"https://api.github.com/repos/{REPO}/pulls/30"
                else:
                    fixture.inline["body"] = "  "
                with self.subTest(mode=mode, defect=defect):
                    self.assert_rejected(payload, name, mode, fixture)

    def test_stale_webhook_body_or_untrusted_inline_text_cannot_admit_remediation(self):
        for mode in ("goal", "generic"):
            for findings in ([], [finding(login="outsider")], [dict(finding(), body="  ")]):
                payload, name = event(mode=mode)
                payload["review"]["body"] = "[P1] A body-only claim."
                fixture = ReadFixtures(mode)
                fixture.comments = findings
                with self.subTest(mode=mode, findings=findings):
                    self.assert_rejected(payload, name, mode, fixture)

    def test_substantive_goal_body_remains_actionable_without_inline_comments(self):
        for state in ("COMMENTED", "CHANGES_REQUESTED"):
            payload, name = event(state=state)
            fixture = ReadFixtures()
            fixture.reviews = [review(state=state, body="[P1] Validate the current review before launch.")]
            fixture.comments = []
            with self.subTest(state=state):
                admitted = self.prepare(payload, name, "goal", fixture)
                self.assertIsNotNone(admitted)
                self.assertIsNotNone(self.admission.goal.build_payload(admitted, name))
                self.assertIsNone(self.admission.goal.terminal_plan(admitted, name, head_sha=HEAD))

    def test_goal_boilerplate_or_clean_body_does_not_replace_actionable_findings(self):
        wrapper = ("### 💡 Codex Review\n\n"
                   "Here are some automated review suggestions for this pull request.\n\n"
                   f"**Reviewed commit:** `{HEAD}`\n\n"
                   "<details>\n<summary>ℹ️ About Codex in GitHub</summary>\n"
                   "The Codex bot reviews this repository.\n</details>")
        clean = "Codex Review: Didn't find any major issues.\n\n" + f"**Reviewed commit:** `{HEAD}`"
        for state in ("COMMENTED", "CHANGES_REQUESTED"):
            for body in ("", "  ", wrapper, clean):
                payload, name = event(state=state)
                fixture = ReadFixtures()
                fixture.reviews = [review(state=state, body=body)]
                fixture.comments = []
                with self.subTest(state=state, body=body):
                    self.assert_rejected(payload, name, "goal", fixture)

    def test_generic_body_only_review_still_requires_trusted_inline_findings(self):
        for state in ("COMMENTED", "CHANGES_REQUESTED"):
            payload, name = event(mode="generic", state=state)
            fixture = ReadFixtures("generic")
            fixture.reviews = [review(state=state, body="[P1] Validate the current review before launch.")]
            fixture.comments = []
            with self.subTest(state=state):
                self.assert_rejected(payload, name, "generic", fixture)

    def test_live_fetched_review_identity_cannot_change_under_inline_event(self):
        for mode in ("goal", "generic"):
            for defect in ("head", "user"):
                payload, name = event("inline", mode)
                fixture = ReadFixtures(mode)
                if defect == "head":
                    fixture.reviews[0]["commit_id"] = NEXT_HEAD
                else:
                    fixture.reviews[0]["user"]["login"] = "outsider"
                with self.subTest(mode=mode, defect=defect):
                    self.assert_rejected(payload, name, mode, fixture)

    def test_real_read_adapter_can_only_issue_get_api_commands(self):
        payload, name = event("summary")
        fixture = ReadFixtures()
        commands = []

        def subprocess_read(argv, **kwargs):
            commands.append(argv)
            self.assertEqual(argv[:2], ["gh", "api"])
            self.assertEqual(len(argv), 3)
            path = argv[2]
            if "per_page=100&page=" in path:
                self.assertTrue(path.endswith("page=1"))
                path = re.sub(r"[?&]per_page=100&page=1$", "", path)
                value = fixture.pages(path)
            else:
                value = fixture.read(path)
            return SimpleNamespace(returncode=0, stdout=json.dumps(value), stderr="")

        with patch("subprocess.run", side_effect=subprocess_read):
            result = self.admission.prepare_event(payload, name, "goal",
                read=self.admission.lineage.gh_read, pages=self.admission.lineage.gh_pages,
                sleep=lambda _: self.fail("No settling is allowed under admission"))
        self.assertIsNotNone(result)
        self.assertGreater(len(commands), 3)

    def test_scheduled_generic_receipt_recovery_is_independent_of_event_admission(self):
        supervisor = importlib.import_module("checkpoint_supervisor")
        generic = importlib.import_module("generic_worker")
        initial = importlib.import_module("goal_initial_launch")
        retired = pull("generic")
        retired.update(state="closed", labels=[])
        reads = []

        def recovery_pages(path):
            reads.append(path)
            if path == f"repos/{REPO}/pulls?state=all":
                return [retired]
            if path == f"repos/{REPO}/issues/29/comments":
                return [{"id": 800}]
            raise AssertionError(f"Unexpected scheduled recovery read: {path}")

        environment = {"GITHUB_REPOSITORY": REPO, "GH_TOKEN": "test-owner",
                       "CURSOR_API_KEY": "test-worker", "TREMELAY_WORKER_ADMISSION": "serialized-v1",
                       "TREMELAY_SUPERVISOR_ACTIVATION": supervisor.ACTIVATION_VALUE,
                       "GITHUB_REF": "refs/heads/main", "SUPERVISOR_MAX_CHECKPOINTS": "3",
                       "GITHUB_WORKFLOW_REF": f"{REPO}/.github/workflows/checkpoint-supervisor.yml@refs/heads/main"}
        with patch.dict(os.environ, environment, clear=True), patch.object(sys, "argv", ["supervisor"]), \
                patch.object(supervisor, "gh", return_value={"login": OWNER}), \
                patch.object(supervisor, "pages", side_effect=recovery_pages), \
                patch.object(initial, "recover_all", return_value=False), \
                patch.object(generic, "pending_generic_claim", return_value=True), \
                patch.object(generic, "reconcile") as reconcile, \
                patch.object(supervisor, "assess", side_effect=AssertionError("No model call")), \
                patch.object(supervisor, "cursor", side_effect=AssertionError("No worker call")), \
                patch.object(self.admission, "prepare_event", side_effect=AssertionError("Recovery must not use event eligibility")), \
                patch("subprocess.run", side_effect=AssertionError("No external command")):
            self.assertEqual(supervisor.main(), 0)
        reconcile.assert_called_once_with(29)
        self.assertIn(f"repos/{REPO}/pulls?state=all", reads)


if __name__ == "__main__":
    unittest.main()
