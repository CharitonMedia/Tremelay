"""Offline wire-contract and adversarial tests. No real credentials or network."""
import copy
import contextlib
from email.message import Message
import io
import json
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import anthropic_checkpoint_assessor as a

HEAD = "a" * 40
URL = ("https://pipelines.actions.githubusercontent.com/service/"
       "00000000-0000-0000-0000-000000000000/_apis/distributedtask/hubs/Actions/"
       "plans/11111111-1111-1111-1111-111111111111/jobs/"
       "22222222-2222-2222-2222-222222222222/idtoken?api-version=2.0")
DECISION = {"head": HEAD, "decision": "resume", "assessment": "A bounded defect.",
            "correction": "Fix the index and test rollback.", "reason_for_user": ""}
SCHEMA = {"type": "object", "additionalProperties": False,
          "properties": {key: {"type": "string"} for key in DECISION},
          "required": list(DECISION)}
INPUT = {"model": a.MODEL, "head": HEAD, "instructions": "Assess only supplied evidence.",
         "schema": SCHEMA, "evidence": {"head": HEAD, "repository": "CharitonMedia/Tremelay"}}


class Response(io.BytesIO):
    def __init__(self, value=None, *, raw=None, status=200, url=None, content_type="application/json",
                 encoding=None):
        super().__init__(raw if raw is not None else json.dumps(value).encode())
        self.status = status
        self.url = url
        self.headers = Message()
        self.headers["Content-Type"] = content_type
        if encoding:
            self.headers["Content-Encoding"] = encoding

    def geturl(self):
        return self.url


class Opener:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def open(self, request, timeout):
        self.calls.append((request, timeout))
        if not self.responses:
            raise AssertionError("Unexpected HTTP call; possible retry")
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        if response.url is None:
            response.url = request.full_url
        return response


class Transport(unittest.TestCase):
    def setUp(self):
        # Generated sentinel strings are non-working synthetic credentials, not
        # recordings of authentication traffic or committed real secret values.
        self.request_token = secrets.token_urlsafe(32)
        self.jwt = ".".join(secrets.token_urlsafe(32) for _ in range(3))
        self.token = "sk-ant-oat01-" + secrets.token_urlsafe(32)
        self.environment = {"ACTIONS_ID_TOKEN_REQUEST_URL": URL,
                            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": self.request_token}
        self.network_guard = patch.object(socket, "create_connection", side_effect=AssertionError(
            "Live network forbidden in assessment tests"))
        self.network_guard.start()
        self.addCleanup(self.network_guard.stop)

    def token_body(self, **updates):
        return dict({"access_token": self.token, "token_type": "Bearer", "expires_in": 599,
                     "scope": "workspace:developer"}, **updates)

    def message_body(self, **updates):
        return dict({"type": "message", "role": "assistant", "model": a.MODEL,
                     "stop_reason": "end_turn", "stop_sequence": None,
                     "content": [{"type": "text", "text": json.dumps(DECISION)}],
                     "usage": {"input_tokens": 103, "output_tokens": 57}}, **updates)

    def opener(self, token=None, message=None):
        return Opener(Response({"value": self.jwt}),
                      Response(self.token_body() if token is None else token),
                      Response(self.message_body() if message is None else message))

    def run_assessment(self, opener, value=None, **kwargs):
        return a.run(INPUT if value is None else value, environment=self.environment,
                     opener=opener, **kwargs)

    def main(self, opener, *, raw=None, args=None):
        stdout, stderr = io.StringIO(), io.StringIO()
        stdin = io.TextIOWrapper(io.BytesIO(json.dumps(INPUT).encode() if raw is None else raw))
        with patch.dict(a.os.environ, self.environment, clear=True), \
                patch.object(a, "make_opener", return_value=opener), \
                patch.object(sys, "stdin", stdin), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = a.main([] if args is None else args)
        return code, stdout.getvalue(), stderr.getvalue()

    def assert_failure(self, result, stage, http_status=None):
        code, out, err = result
        self.assertEqual((code, err), (1, a.SAFE_FAILURE + "\n"))
        self.assertEqual(len(out.splitlines()), 1)
        self.assertEqual(json.loads(out), {"status": "failed", "stage": stage, "http_status": http_status})
        for secret in (self.request_token, self.jwt, self.token):
            self.assertNotIn(secret, out + err)

    def test_exact_three_request_sequence_and_minimal_result(self):
        opener = self.opener()
        result = self.run_assessment(opener)
        self.assertEqual(result, {"status": "finished", "model": a.MODEL,
            "result": a.json_bytes(DECISION).decode(), "usage": {"input_tokens": 103, "output_tokens": 57}})
        self.assertEqual(len(opener.calls), 3)
        oidc, exchange, message = [request for request, _ in opener.calls]
        self.assertEqual(oidc.get_method(), "GET")
        self.assertEqual(oidc.full_url, URL + "&audience=https%3A%2F%2Fapi.anthropic.com")
        self.assertEqual(oidc.get_header("Authorization"), "Bearer " + self.request_token)
        self.assertIsNone(oidc.data)
        self.assertEqual(exchange.full_url, a.TOKEN_URL)
        self.assertEqual(exchange.get_method(), "POST")
        self.assertIsNone(exchange.get_header("Authorization"))
        self.assertEqual(json.loads(exchange.data), {
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": self.jwt,
            "federation_rule_id": a.FEDERATION_RULE_ID, "organization_id": a.ORGANIZATION_ID,
            "service_account_id": a.SERVICE_ACCOUNT_ID, "workspace_id": a.WORKSPACE_ID})
        self.assertEqual(message.full_url, "https://api.anthropic.com/v1/messages")
        self.assertEqual(message.get_method(), "POST")
        self.assertEqual(message.get_header("Authorization"), "Bearer " + self.token)
        self.assertEqual(message.get_header("Anthropic-version"), "2023-06-01")
        self.assertIsNone(message.get_header("X-api-key"))
        body = json.loads(message.data)
        self.assertEqual(body, {"model": a.MODEL, "max_tokens": 8192, "stream": False,
            "system": INPUT["instructions"], "thinking": {"type": "adaptive", "display": "omitted"},
            "output_config": {"effort": "high", "format": {"type": "json_schema", "schema": SCHEMA}},
            "messages": [{"role": "user", "content": a.json_bytes(INPUT["evidence"]).decode()}]})
        self.assertNotIn(self.token, message.data.decode())
        self.assertNotIn(self.jwt, message.data.decode())
        self.assertEqual([timeout for _, timeout in opener.calls],
                         [a.AUTH_TIMEOUT, a.AUTH_TIMEOUT, a.INFERENCE_TIMEOUT])
        self.assertEqual((a.AUTH_TIMEOUT, a.INFERENCE_TIMEOUT, a.MIN_TOKEN_LIFETIME), (30, 175, 270))
        self.assertLess(2 * a.AUTH_TIMEOUT + a.INFERENCE_TIMEOUT, 240)

    def test_preflight_authenticates_without_reading_stdin_or_calling_model(self):
        opener = self.opener()
        code, out, err = self.main(opener, raw=b"not assessment JSON", args=["--preflight"])
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        result = json.loads(out)
        self.assertEqual(set(result), {"authentication_succeeded", "scope", "expires_in", "model_called"})
        self.assertTrue(result["authentication_succeeded"])
        self.assertFalse(result["model_called"])
        self.assertEqual(result["scope"], a.SCOPE)
        self.assertGreaterEqual(result["expires_in"], 590)
        self.assertLessEqual(result["expires_in"], 599)
        self.assertEqual(len(opener.calls), 2)
        for secret in (self.request_token, self.jwt, self.token):
            self.assertNotIn(secret, out + err)

    def test_successful_cli_prints_only_one_json_line(self):
        code, out, err = self.main(self.opener())
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(len(out.splitlines()), 1)
        self.assertEqual(json.loads(out)["status"], "finished")

    def test_full_stdout_envelope_is_bounded_without_truncation(self):
        # The nested result JSON is below its own bound; outer string escaping
        # expands it beyond the parent's 96 KiB envelope limit.
        text = json.dumps(dict(DECISION, assessment="\\" * 25_000))
        self.assertLess(len(text.encode()), a.MAX_RESULT_BYTES)
        opener = self.opener(message=self.message_body(content=[{"type": "text", "text": text}]))
        self.assert_failure(self.main(opener), "runtime")
        self.assertEqual(len(opener.calls), 3)

    def test_current_and_regional_actions_hosts_preserve_supplied_route_and_query(self):
        for url in [URL, URL.replace("pipelines", "run-actions-1-azure-eastus"),
                    URL.replace("api-version=2.0", "api-version=3.0&route=abc%2Bdef"),
                    "https://pipelines.actions.githubusercontent.com:443/new/issued/path?",
                    "https://pipelines.actions.githubusercontent.com/new/issued/path"]:
            with self.subTest(url=url):
                actual = a.oidc_request_url(url)
                self.assertTrue(actual.startswith(url))
                self.assertEqual(urllib.parse.parse_qs(urllib.parse.urlsplit(actual).query)["audience"],
                                 [a.AUDIENCE])

    def test_actions_issued_double_slash_idtoken_route_is_preserved_through_preflight(self):
        url = ("https://run-actions-1-azure-eastus.actions.githubusercontent.com/152//idtoken/"
               "11111111-1111-1111-1111-111111111111/22222222-2222-2222-2222-222222222222?api-version=2.0")
        self.environment["ACTIONS_ID_TOKEN_REQUEST_URL"] = url
        opener = self.opener()
        code, out, err = self.main(opener, raw=b"", args=["--preflight"])
        self.assertEqual((code, err), (0, ""))
        self.assertTrue(json.loads(out)["authentication_succeeded"])
        self.assertFalse(json.loads(out)["model_called"])
        self.assertEqual(len(opener.calls), 2)
        request = opener.calls[0][0]
        self.assertEqual(request.get_method(), "GET")
        self.assertEqual(request.full_url, url + "&audience=https%3A%2F%2Fapi.anthropic.com")
        self.assertEqual(urllib.parse.urlsplit(request.full_url).path, urllib.parse.urlsplit(url).path)
        self.assertEqual(request.get_header("Authorization"), "Bearer " + self.request_token)

    def test_bad_oidc_origins_paths_and_queries_never_receive_request_token(self):
        root = "https://pipelines.actions.githubusercontent.com"
        urls = [None, "", "https://evil.example/idtoken", "http://pipelines.actions.githubusercontent.com/a",
                "https://actions.githubusercontent.com/a", root + ".evil.example/a",
                "https://pipelines.actions.githubusercontent.com@evil.example/a",
                "https://evil@pipelines.actions.githubusercontent.com/a", root + ":8443/a",
                "https://127.0.0.1/a", "https://[::1]/a", root + "./a", root + "/",
                root + "/a\\b", root + "/a\nb", " " + URL, root + "/a/../idtoken",
                root + "/a/%2e%2e/idtoken", root + "/a/%252e/idtoken",
                root + "/a%2fidtoken", root + "/a%5cidtoken", root + "/a%00/idtoken",
                root + "/a;idtoken", root + "/a%GG/idtoken", URL + "#fragment",
                URL + "&audience=other", URL + "&%61udience=other", URL + "&AUDIENCE=other",
                URL + "&api-version=2.0", URL + "&redirect=%0Asecret", URL + "&naked"]
        for url in urls:
            with self.subTest(url=url):
                opener = self.opener()
                self.environment["ACTIONS_ID_TOKEN_REQUEST_URL"] = url
                with self.assertRaises(a.Stop):
                    self.run_assessment(opener)
                self.assertEqual(opener.calls, [])

    def test_ambient_proxy_and_tls_overrides_fail_before_authentication(self):
        for key in ("https_proxy", "HTTPS_PROXY", "http_proxy", "ALL_PROXY", "no_proxy",
                    "SSL_CERT_FILE", "SSL_CERT_DIR", "SSLKEYLOGFILE"):
            with self.subTest(key=key):
                environment = dict(self.environment, **{key: ""})
                opener = self.opener()
                with self.assertRaises(a.Stop):
                    a.run(INPUT, environment=environment, opener=opener)
                self.assertEqual(opener.calls, [])

    def test_real_opener_disables_proxies_and_redirects(self):
        with patch.dict(a.os.environ, {}, clear=True):
            opener = a.make_opener()
        # An empty ProxyHandler does not install protocol handlers; no default
        # environment proxy handler can be present in the resulting opener.
        self.assertFalse(any(isinstance(h, urllib.request.ProxyHandler) and h.proxies
                             for h in opener.handlers))
        redirects = [h for h in opener.handlers if isinstance(h, urllib.request.HTTPRedirectHandler)]
        self.assertEqual(len(redirects), 1)
        self.assertIsInstance(redirects[0], a.NoRedirect)
        request = urllib.request.Request(a.TOKEN_URL)
        for code in (301, 302, 303, 307, 308):
            with self.assertRaises(a.Stop):
                redirects[0].redirect_request(request, None, code, self.token, {},
                                               "https://evil.example/" + self.token)

    def test_redirect_status_or_changed_final_url_stops_each_stage(self):
        for stage in range(3):
            for update in ({"status": 302}, {"url": "https://evil.example/reflect"}):
                with self.subTest(stage=stage, update=update):
                    opener = self.opener()
                    opener.responses[stage] = Response({}, **update)
                    with self.assertRaises(a.Stop):
                        self.run_assessment(opener)
                    self.assertEqual(len(opener.calls), stage + 1)

    def test_missing_or_malformed_request_token_has_no_api_key_fallback(self):
        for token in (None, "", "line\r\ninjected: yes", "bad token", "é"):
            with self.subTest(token=token):
                opener = self.opener()
                environment = dict(self.environment, ACTIONS_ID_TOKEN_REQUEST_TOKEN=token,
                                   ANTHROPIC_API_KEY=secrets.token_urlsafe(32),
                                   OPENAI_API_KEY=secrets.token_urlsafe(32),
                                   ANTHROPIC_PROFILE="some-profile")
                with self.assertRaises(a.Stop):
                    a.run(INPUT, environment=environment, opener=opener)
                self.assertEqual(opener.calls, [])

    def test_provider_key_and_url_overrides_cannot_change_wif_transport(self):
        environment = dict(self.environment, ANTHROPIC_API_KEY="unused", OPENAI_API_KEY="unused",
                           CURSOR_API_KEY="unused", ANTHROPIC_BASE_URL="https://evil.example",
                           ANTHROPIC_PROFILE="unread", ANTHROPIC_IDENTITY_TOKEN_FILE="/never/read")
        opener = self.opener()
        with patch("builtins.open", side_effect=AssertionError("Credential files must not be read")):
            result = a.run(INPUT, environment=environment, opener=opener)
        self.assertEqual(result["status"], "finished")
        self.assertEqual(opener.calls[1][0].full_url, a.TOKEN_URL)
        self.assertEqual(opener.calls[2][0].full_url, a.MESSAGES_URL)

    def test_malformed_or_error_identity_response_never_exchanges(self):
        for body in ({}, {"value": None}, {"value": "one-segment"}, {"value": "a.b.c"},
                     {"value": self.jwt + "\n"}, {"value": self.jwt, "error": "denied"}):
            with self.subTest(body=body):
                opener = Opener(Response(body))
                with self.assertRaises(a.Stop):
                    self.run_assessment(opener)
                self.assertEqual(len(opener.calls), 1)

    def test_exchange_requires_exact_scope_type_lifetime_and_access_token_format(self):
        updates = [{"scope": value} for value in (None, "org:admin", "workspace:inference",
                   "workspace:developer org:admin", "workspace:developer ")]
        updates += [{"token_type": value} for value in (None, "bearer", "Basic")]
        updates += [{"expires_in": value} for value in (None, True, "599", 599.0, -1, 0, 239, 269, 86_401)]
        updates += [{"access_token": value} for value in (None, "", "sk-ant-oat01-", "wrong-prefix",
                    self.token + "\r\n", self.token + " ", self.token + "☃")]
        updates += [{"error": {"message": self.token}}]
        for update in updates:
            with self.subTest(fields=list(update)):
                opener = self.opener(token=self.token_body(**update))
                with self.assertRaises(a.Stop):
                    self.run_assessment(opener)
                self.assertEqual(len(opener.calls), 2)

    def test_slow_exchange_and_elapsed_lifetime_before_message_fail_without_refresh(self):
        for times in ([0, 400], [0, 0, 400]):
            with self.subTest(times=times):
                opener = self.opener()
                with patch.object(a.time, "monotonic", side_effect=times), self.assertRaises(a.Stop):
                    self.run_assessment(opener)
                self.assertEqual(len(opener.calls), 2)

    def test_any_http_error_is_single_attempt_and_error_body_is_not_read(self):
        class Unreadable(io.BytesIO):
            def read(self, *args):
                raise AssertionError("Error bodies must never be read")
        for stage in range(3):
            for status in (400, 401, 403, 404, 408, 409, 429, 500, 529):
                with self.subTest(stage=stage, status=status):
                    opener = self.opener()
                    opener.responses[stage] = urllib.error.HTTPError(
                        "https://evil.example/" + self.token, status, self.jwt, {}, Unreadable(self.token.encode()))
                    with self.assertRaisesRegex(a.Stop, "API request rejected"):
                        self.run_assessment(opener)
                    self.assertEqual(len(opener.calls), stage + 1)

    def test_network_timeout_and_partial_body_do_not_retry_any_stage(self):
        for stage in range(3):
            for error in (urllib.error.URLError(self.token), TimeoutError(self.jwt),
                          ConnectionResetError(self.request_token)):
                with self.subTest(stage=stage, kind=type(error)):
                    opener = self.opener()
                    opener.responses[stage] = error
                    with self.assertRaises(a.Stop):
                        self.run_assessment(opener)
                    self.assertEqual(len(opener.calls), stage + 1)
            opener = self.opener()
            opener.responses[stage] = Response(raw=b'{"unfinished":')
            with self.assertRaises(a.Stop):
                self.run_assessment(opener)
            self.assertEqual(len(opener.calls), stage + 1)

    def test_json_duplicate_keys_nonfinite_invalid_utf8_and_oversize_responses_fail(self):
        for stage in range(3):
            limit = a.MAX_AUTH_BYTES if stage < 2 else a.MAX_RESPONSE_BYTES
            for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}', b'{"a":1e999}', b'\xff',
                        b'"string"', b'[]', b' ' * (limit + 1)):
                with self.subTest(stage=stage, size=len(raw)):
                    opener = self.opener()
                    opener.responses[stage] = Response(raw=raw)
                    with self.assertRaises(a.Stop):
                        self.run_assessment(opener)
                    self.assertEqual(len(opener.calls), stage + 1)

    def test_unexpected_http_success_status_content_type_and_encoding_fail(self):
        for update in ({"status": 201}, {"status": 204}, {"content_type": "text/html"},
                       {"content_type": "text/event-stream"}, {"encoding": "gzip"}):
            opener = self.opener()
            opener.responses[2] = Response(self.message_body(), **update)
            with self.assertRaises(a.Stop):
                self.run_assessment(opener)
            self.assertEqual(len(opener.calls), 3)

    def test_only_exact_model_completed_assistant_message_is_accepted(self):
        updates = [{"stop_reason": value} for value in (None, "refusal", "max_tokens", "tool_use",
                   "pause_turn", "stop_sequence", "model_context_window_exceeded")]
        updates += [{"model": value} for value in (None, "claude-sonnet-5", "claude-sonnet-5-5-latest",
                    "claude-opus-5-5")]
        updates += [{"type": "error"}, {"role": "user"}, {"stop_sequence": "done"},
                    {"stop_details": {"category": "refusal"}}, {"error": {"message": self.token}}]
        for update in updates:
            with self.subTest(update=update):
                opener = self.opener(message=self.message_body(**update))
                with self.assertRaises(a.Stop):
                    self.run_assessment(opener)
                self.assertEqual(len(opener.calls), 3)

    def test_thinking_encrypted_signatures_and_extra_metadata_never_leave_child(self):
        thought = "private-thinking-" + secrets.token_urlsafe(32)
        signature = secrets.token_urlsafe(64)
        blocks = [{"type": "thinking", "thinking": thought, "signature": signature},
                  {"type": "redacted_thinking", "data": self.token},
                  {"type": "text", "text": json.dumps(DECISION), "citations": []}]
        body = self.message_body(content=blocks, metadata={"secret": self.jwt},
                                 usage={"input_tokens": 103, "output_tokens": 57, "private": self.token})
        code, out, err = self.main(self.opener(message=body))
        self.assertEqual((code, err), (0, ""))
        for private in (thought, signature, self.token, self.jwt, self.request_token):
            self.assertNotIn(private, out)

    def test_omitted_thinking_is_accepted_and_no_tools_or_unknown_blocks_are_accepted(self):
        text = {"type": "text", "text": json.dumps(DECISION)}
        valid = [{"type": "thinking", "thinking": "", "signature": "opaque"}, text]
        self.assertEqual(self.run_assessment(self.opener(message=self.message_body(content=valid)))["status"], "finished")
        for block in ({"type": "tool_use", "name": "exfiltrate"}, {"type": "server_tool_use"},
                      {"type": "image"}, {"type": "refusal"}, {"type": "future_unknown"},
                      {"type": "thinking", "thinking": ""}, {"type": "redacted_thinking", "data": 1},
                      "malformed", {"type": "text", "text": 42}):
            with self.subTest(block=block):
                opener = self.opener(message=self.message_body(content=[block, text]))
                with self.assertRaises(a.Stop):
                    self.run_assessment(opener)
                self.assertEqual(len(opener.calls), 3)

    def test_exactly_one_bounded_json_text_object_for_supplied_head_required(self):
        texts = ["", "not JSON", "[]", '"text"', json.dumps(dict(DECISION, head="b" * 40)),
                 json.dumps({"decision": "resume"}), '{"head":"' + HEAD + '","head":"' + HEAD + '"}',
                 json.dumps(dict(DECISION, assessment="x" * a.MAX_RESULT_BYTES))]
        for text in texts:
            with self.subTest(size=len(text)):
                opener = self.opener(message=self.message_body(content=[{"type": "text", "text": text}]))
                with self.assertRaises(a.Stop):
                    self.run_assessment(opener)
        for blocks in ([], None, [{"type": "text", "text": json.dumps(DECISION)}] * 2,
                       [{"type": "text", "text": json.dumps(DECISION), "citations": [{"type": "citation"}]}]):
            with self.assertRaises(a.Stop):
                self.run_assessment(self.opener(message=self.message_body(content=blocks)))

    def test_usage_is_bounded_integers_and_not_booleans(self):
        for key, value in (("input_tokens", -1), ("input_tokens", 1_000_001), ("input_tokens", True),
                           ("input_tokens", "12"), ("output_tokens", 0), ("output_tokens", 8193),
                           ("output_tokens", False), ("output_tokens", 2.5), ("output_tokens", None)):
            usage = dict(self.message_body()["usage"], **{key: value})
            with self.assertRaises(a.Stop):
                self.run_assessment(self.opener(message=self.message_body(usage=usage)))
        for usage in (None, {}, []):
            with self.assertRaises(a.Stop):
                self.run_assessment(self.opener(message=self.message_body(usage=usage)))

    def test_reflected_credentials_in_successful_json_are_never_emitted(self):
        for secret in (self.request_token, self.jwt, self.token):
            for escaped in (False, True):
                text = json.dumps(dict(DECISION, assessment=secret))
                if escaped:
                    text = text.replace(secret, "".join("\\u%04x" % ord(char) for char in secret))
                opener = self.opener(message=self.message_body(content=[{"type": "text", "text": text}]))
                code, out, err = self.main(opener)
                self.assert_failure((code, out, err), "messages_response")
                self.assertEqual(len(opener.calls), 3)

    def test_arbitrary_exception_text_error_bodies_and_urls_are_redacted(self):
        for stage in range(3):
            opener = self.opener()
            opener.responses[stage] = RuntimeError(self.token + self.jwt + self.request_token)
            code, out, err = self.main(opener)
            self.assert_failure((code, out, err), ["github_acquisition", "anthropic_exchange", "messages"][stage])
            self.assertEqual(len(opener.calls), stage + 1)

    def test_invalid_input_fails_before_identity_call(self):
        updates = [{"model": "claude-sonnet-5-5-latest"}, {"model": "claude-sonnet-5"},
                   {"head": "b" * 40}, {"head": "short"}, {"instructions": ""},
                   {"instructions": "x" * 20_001}, {"schema": {}}, {"schema": None},
                   {"evidence": {"head": HEAD, "data": "x" * a.MAX_EVIDENCE_BYTES}},
                   {"endpoint": "https://evil.example"}, {"tools": [{"name": "execute"}]}]
        for update in updates:
            opener = self.opener()
            with self.assertRaises(a.Stop):
                self.run_assessment(opener, value=dict(INPUT, **update))
            self.assertEqual(opener.calls, [])

    def test_cli_input_byte_bound_duplicate_keys_and_invalid_flags_are_safe(self):
        for raw, args in ((b" " * (a.MAX_INPUT_BYTES + 1), []), (b"{", []), (b"\xff", []),
                          (b'{"head":1,"head":2}', []), (b'{"number":NaN}', []),
                          (b"{}", ["--model", self.token])):
            opener = self.opener()
            self.assert_failure(self.main(opener, raw=raw, args=args), "input")
            self.assertEqual(opener.calls, [])

    def test_smoke_makes_one_fixed_256_token_request_and_returns_only_safe_summary(self):
        opener = self.opener(message=self.message_body(content=[{"type": "text", "text": '{"status":"ok"}'}]))
        code, out, err = self.main(opener, raw=b"", args=["--smoke"])
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(json.loads(out), {"smoke_succeeded": True, "model_called": True,
            "model": a.MODEL, "usage": {"input_tokens": 103, "output_tokens": 57}})
        self.assertEqual(len(opener.calls), 3)
        self.assertEqual([request.full_url for request, _ in opener.calls],
            [URL + "&audience=https%3A%2F%2Fapi.anthropic.com", a.TOKEN_URL, a.MESSAGES_URL])
        payload = json.loads(opener.calls[2][0].data)
        self.assertEqual(payload, {"model": a.MODEL, "max_tokens": 256, "stream": False,
            "system": 'Return only the JSON object {"status":"ok"}.',
            "thinking": {"type": "between_tools"},
            "output_config": {"effort": "high", "format": {"type": "json_schema", "schema": {
                "type": "object", "properties": {"status": {"type": "string", "enum": ["ok"]}},
                "required": ["status"], "additionalProperties": False}}},
            "messages": [{"role": "user", "content": 'Return {"status":"ok"}.'}]})
        for secret in (self.request_token, self.jwt, self.token):
            self.assertNotIn(secret, out + err)
            self.assertNotIn(secret, opener.calls[2][0].data.decode())

    def test_smoke_rejects_stdin_evidence_and_conflicting_modes_before_authentication(self):
        for raw, args in ((json.dumps(INPUT).encode(), ["--smoke"]), (b" ", ["--smoke"]),
                          (b"", ["--smoke", "--preflight"]), (b"", ["--smoke", "--model", "other"])):
            opener = self.opener()
            self.assert_failure(self.main(opener, raw=raw, args=args), "input")
            self.assertEqual(opener.calls, [])
        for kwargs in ({"value": INPUT, "smoke": True}, {"preflight": True, "smoke": True}):
            opener = self.opener()
            with self.assertRaises(a.Stop):
                a.run(environment=self.environment, opener=opener, **kwargs)
            self.assertEqual(opener.calls, [])

    def test_smoke_requires_exact_model_normal_completion_and_exact_json_status(self):
        correct = {"type": "text", "text": '{"status":"ok"}'}
        updates = [{"model": "claude-sonnet-5"}, {"stop_reason": "max_tokens"},
                   {"stop_reason": "refusal"}, {"type": "error"}, {"role": "user"},
                   {"content": [correct, correct]}, {"content": [{"type": "tool_use"}]},
                   {"content": [{"type": "thinking", "thinking": "", "signature": "opaque"}, correct]},
                   {"usage": {"input_tokens": 1, "output_tokens": 257}}]
        for text in ('{}', '{"status":"not-ok"}', '{"status":true}', '{"status":"ok","extra":1}',
                     '{"status":"ok","status":"ok"}', 'not JSON', json.dumps(DECISION)):
            updates.append({"content": [{"type": "text", "text": text}]})
        for update in updates:
            opener = self.opener(message=self.message_body(content=[correct], **update)
                                 if "content" not in update else self.message_body(**update))
            self.assert_failure(self.main(opener, raw=b"", args=["--smoke"]), "messages_response")
            self.assertEqual(len(opener.calls), 3)

    def test_smoke_authentication_quota_and_ambiguous_errors_never_retry_or_fallback(self):
        for stage in range(3):
            for error in (TimeoutError(self.token), urllib.error.URLError(self.jwt),
                          urllib.error.HTTPError(a.MESSAGES_URL, 429, self.token, {}, io.BytesIO(self.jwt.encode()))):
                opener = self.opener()
                opener.responses[stage] = error
                self.assert_failure(self.main(opener, raw=b"", args=["--smoke"]),
                    ["github_acquisition", "anthropic_exchange", "messages"][stage],
                    429 if isinstance(error, urllib.error.HTTPError) else None)
                self.assertEqual(len(opener.calls), stage + 1)
        opener = self.opener(token=self.token_body(scope="org:admin"))
        self.assert_failure(self.main(opener, raw=b"", args=["--smoke"]), "anthropic_response")
        self.assertEqual(len(opener.calls), 2)

    def test_diagnostics_separate_url_tls_acquisition_and_response_stages(self):
        self.environment["ACTIONS_ID_TOKEN_REQUEST_URL"] = "https://evil.example/" + self.token
        opener = self.opener()
        self.assert_failure(self.main(opener), "github_url")
        self.assertEqual(opener.calls, [])
        self.environment["ACTIONS_ID_TOKEN_REQUEST_URL"] = URL
        for stage, name in enumerate(("github_response", "anthropic_response", "messages_response")):
            opener = self.opener()
            opener.responses[stage] = Response(raw=self.token.encode(), content_type="text/html")
            self.assert_failure(self.main(opener), name)
            self.assertEqual(len(opener.calls), stage + 1)
        with patch.object(a.ssl, "create_default_context", side_effect=RuntimeError(self.token)):
            with self.assertRaises(a.Stop) as error:
                a.make_opener()
        self.assertEqual(a.failure_result(error.exception),
                         {"status": "failed", "stage": "tls_setup", "http_status": None})
        self.assertNotIn(self.token, str(error.exception))

    def test_failure_projection_never_promotes_unknown_stage_or_status_values(self):
        for stage in (self.token, None, ["messages"], 42):
            self.assertEqual(a.failure_result(a.Stop(self.jwt, stage=stage, http_status=403)),
                             {"status": "failed", "stage": "runtime", "http_status": None})
        for stage in a.FAILURE_STAGES:
            for status in (True, 403.0, "403", 399, 600, self.token, None):
                result = a.failure_result(a.Stop(self.jwt, stage=stage, http_status=status))
                self.assertEqual(result, {"status": "failed", "stage": stage, "http_status": None})
            result = a.failure_result(a.Stop(self.jwt, stage=stage, http_status=403))
            self.assertEqual(result["http_status"], 403 if stage in a.HTTP_FAILURE_STAGES else None)
        self.assertEqual(a.failure_result(RuntimeError(self.token)),
                         {"status": "failed", "stage": "runtime", "http_status": None})

    def test_http_failure_diagnostics_only_include_fixed_stage_and_integer_status(self):
        for stage, name in enumerate(("github_acquisition", "anthropic_exchange", "messages")):
            for status in (302, 400, 403, 429, 500, 599, 600):
                opener = self.opener()
                opener.responses[stage] = urllib.error.HTTPError(
                    "https://evil.example/" + self.token, status, self.jwt, {}, io.BytesIO(self.token.encode()))
                self.assert_failure(self.main(opener), name, status if 400 <= status <= 599 else None)
                self.assertEqual(len(opener.calls), stage + 1)

    def test_real_helper_starts_and_imports_with_exact_isolation_without_authentication(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8"}
            for name in ("HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME",
                         "XDG_STATE_HOME", "XDG_RUNTIME_DIR"):
                path = root / name.lower()
                path.mkdir(mode=0o700)
                env[name] = str(path)
            work = root / "work"
            work.mkdir(mode=0o700)
            args = [str(Path(sys.executable).resolve()), "-I", "-B", str(Path(a.__file__).resolve())]
            # No URL or token is present, so real --preflight cannot reach any
            # network call. Unlike fake-child tests this imports the full helper.
            process = subprocess.run(args + ["--preflight"], input=b"", capture_output=True,
                                     cwd=work, env=env, timeout=10, check=False)
            self.assert_failure((process.returncode, process.stdout.decode(), process.stderr.decode()), "github_url")
            # Constructing a TLS context performs no network I/O. This exercises
            # ssl/_ssl/dynamic-library loading under the same clean environment.
            probe = ("import runpy; "
                     f"helper = runpy.run_path({str(Path(a.__file__).resolve())!r}); "
                     "helper['make_opener'](); print('runtime-ready')")
            process = subprocess.run(args[:3] + ["-c", probe], input=b"", capture_output=True,
                                     cwd=work, env=env, timeout=10, check=False)
            self.assertEqual((process.returncode, process.stdout, process.stderr), (0, b"runtime-ready\n", b""))
            self.assertEqual(list(work.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
