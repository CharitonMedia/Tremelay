#!/usr/bin/env python3
"""One isolated, non-retrying Anthropic WIF checkpoint assessment.

The trusted controller supplies bounded JSON on stdin and launches this helper
with a clean HOME/cwd and an allowlisted environment. Only the GitHub Actions
OIDC request URL/token are credentials inputs. This module never loads an SDK,
credential file, API key, profile, tool, candidate code, or endpoint override.
Authentication and thinking stay in memory; stdout contains only the documented
result projection. The controller owns reservations, audit, and decision checks.

Wire contracts verified against official documentation on 2026-10-09:
https://platform.claude.com/docs/en/manage-claude/wif-reference
https://platform.claude.com/docs/en/api/messages/create
https://platform.claude.com/docs/en/build-with-claude/structured-outputs
https://platform.claude.com/docs/en/build-with-claude/thinking
https://docs.github.com/en/actions/reference/runners/github-hosted-runners
https://github.com/actions/toolkit/blob/main/packages/core/src/oidc-utils.ts
"""
from __future__ import annotations

import json
import math
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

MODEL = "claude-sonnet-5-5"
AUDIENCE = "https://api.anthropic.com"
TOKEN_URL = AUDIENCE + "/v1/oauth/token"
MESSAGES_URL = AUDIENCE + "/v1/messages"
API_VERSION = "2023-06-01"
FEDERATION_RULE_ID = "fdrl_013Lev2Ca6SiD7qZMn7EfUU5"
ORGANIZATION_ID = "466edc9f-6dfc-43fc-94c9-9c04564e7cda"
SERVICE_ACCOUNT_ID = "svac_01SVrjZsb4viBXFasJ3V4t1J"
WORKSPACE_ID = "wrkspc_01T2N8u5EmTvb6TbGoaAmWCo"
SCOPE = "workspace:developer"
MAX_INPUT_BYTES = 1_100_000
MAX_EVIDENCE_BYTES = 1_000_000
MAX_AUTH_BYTES = 65_536
MAX_RESPONSE_BYTES = 1_000_000
MAX_RESULT_BYTES = 100_000
MAX_STDOUT_BYTES = 96 * 1024
MAX_OUTPUT_TOKENS = 8192
SMOKE_OUTPUT_TOKENS = 256
SMOKE_SCHEMA = {"type": "object", "properties": {"status": {"type": "string", "enum": ["ok"]}},
                "required": ["status"], "additionalProperties": False}
AUTH_TIMEOUT = 30
INFERENCE_TIMEOUT = 175
# Parent kills the whole isolated process at 240 seconds. Token validity is
# conservatively sufficient for that full window plus a margin, even though
# each HTTP operation has its own shorter socket timeout.
MIN_TOKEN_LIFETIME = 270
SAFE_FAILURE = "Anthropic assessment failed; no automatic replay."


class Stop(RuntimeError):
    """A fixed error; never interpolate an upstream body or exception."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Stop("Credential-bearing redirect refused")


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Stop("Duplicate JSON field refused")
        result[key] = value
    return result


def _nonfinite(_value):
    raise Stop("Non-finite JSON refused")


def _finite_float(value):
    number = float(value)
    if not math.isfinite(number):
        raise Stop("Non-finite JSON refused")
    return number


def strict_json(raw):
    try:
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="strict")
        return json.loads(raw, object_pairs_hook=_pairs, parse_constant=_nonfinite,
                          parse_float=_finite_float)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise Stop("Invalid JSON refused") from None


def json_bytes(value):
    try:
        return json.dumps(value, ensure_ascii=False, allow_nan=False,
                          separators=(",", ":")).encode("utf-8", errors="strict")
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise Stop("Invalid JSON refused") from None


def validate_input(value):
    if (not isinstance(value, dict)
            or set(value) != {"model", "head", "instructions", "schema", "evidence"}
            or value["model"] != MODEL
            or not isinstance(value["head"], str)
            or not re.fullmatch(r"[0-9a-f]{40}", value["head"])
            or not isinstance(value["instructions"], str)
            or not value["instructions"].strip()
            or len(value["instructions"].encode("utf-8")) > 20_000
            or not isinstance(value["schema"], dict)
            or value["schema"].get("type") != "object"
            or value["schema"].get("additionalProperties") is not False
            or len(json_bytes(value["schema"])) > 16_000
            or not isinstance(value["evidence"], dict)
            or value["evidence"].get("head") != value["head"]
            or len(json_bytes(value["evidence"])) > MAX_EVIDENCE_BYTES
            or len(json_bytes(value)) > MAX_INPUT_BYTES):
        raise Stop("Invalid assessment input")
    return value


def oidc_request_url(raw):
    """Bind to the trusted Actions URL, preserving its path and query.

GitHub documents *.actions.githubusercontent.com for OIDC but does not promise
a fixed path or API version. Never reconstruct a guessed route. Refuse URL
ambiguity and pre-existing audience parameters before appending our one audience.
The URL is taken only from Actions' environment, never assessment input.
"""
    if (not isinstance(raw, str) or not raw or len(raw) > 8192
            or any(ord(char) < 33 or ord(char) > 126 for char in raw)
            or "\\" in raw or "#" in raw):
        raise Stop("Invalid GitHub identity endpoint")
    try:
        parsed = urllib.parse.urlsplit(raw)
        host = parsed.hostname or ""
        if (parsed.scheme != "https" or parsed.username is not None
                or parsed.password is not None or parsed.port not in (None, 443)
                or not re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
                                    r"actions\.githubusercontent\.com", host)
                or parsed.netloc not in (host, host + ":443")
                or not parsed.path.startswith("/") or parsed.path == "/"
                or "//" in parsed.path or ";" in parsed.path
                or re.search(r"%(?![0-9A-Fa-f]{2})", parsed.path)):
            raise Stop("Invalid GitHub identity endpoint")
        decoded = urllib.parse.unquote(parsed.path, errors="strict")
        # Reject encoded separators, double encoding, dot traversal and controls.
        if (decoded.count("/") != parsed.path.count("/") or "\\" in decoded
                or "%" in decoded or any(ord(char) < 33 for char in decoded)
                or any(part in {".", ".."} for part in decoded.split("/"))):
            raise Stop("Invalid GitHub identity endpoint")
        pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True,
                                      strict_parsing=True, max_num_fields=16,
                                      encoding="utf-8", errors="strict")
        keys = [key.casefold() for key, _ in pairs]
        if (len(set(keys)) != len(keys) or "audience" in keys
                or any(not key or re.search(r"[\x00-\x20\x7f]", key + item)
                       for key, item in pairs)):
            raise Stop("Invalid GitHub identity endpoint")
    except (ValueError, UnicodeError):
        raise Stop("Invalid GitHub identity endpoint") from None
    # Do not decode/re-encode a signed or service-specific query or change path.
    separator = "&" if parsed.query else ("" if raw.endswith("?") else "?")
    return raw + separator + "audience=" + urllib.parse.quote(AUDIENCE, safe="")


def make_opener():
    # No environment proxies or alternate certificate roots. create_default_context
    # uses only the standard OS trust store with these variables absent; the
    # parent's isolated environment is also checked below before constructing it.
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()))


def read_response(opener, request, *, timeout, limit):
    """One attempt; never read, log or return an HTTP error body."""
    try:
        with opener.open(request, timeout=timeout) as response:
            if response.status != 200 or response.geturl() != request.full_url:
                raise Stop("Unexpected API response")
            if response.headers.get("Content-Encoding", "identity").lower() != "identity":
                raise Stop("Encoded API response refused")
            if response.headers.get_content_type() != "application/json":
                raise Stop("Unexpected API response type")
            raw = response.read(limit + 1)
            if len(raw) > limit:
                raise Stop("API response exceeds bound")
        value = strict_json(raw)
        if not isinstance(value, dict) or "error" in value:
            raise Stop("Invalid API response")
        return value
    except urllib.error.HTTPError as error:
        error.close()
        raise Stop("API request rejected; no automatic replay") from None
    except (OSError, ValueError):
        raise Stop("API request failed; no automatic replay") from None


def _bearer(value, *, prefix=""):
    # RFC 6750 token characters, bounded and without whitespace/header injection.
    return (isinstance(value, str) and 1 <= len(value) <= 32_768
            and value.startswith(prefix) and len(value) > len(prefix)
            and re.fullmatch(r"[A-Za-z0-9._~+/-]+=*", value) is not None)


def authenticate(environment, opener):
    # Reject ambient transport overrides rather than silently trusting a proxy or
    # user-supplied TLS root. Never inspect alternate provider credential values.
    if any(key.casefold().endswith("_proxy") or key in {
            "SSL_CERT_FILE", "SSL_CERT_DIR", "SSLKEYLOGFILE"} for key in environment):
        raise Stop("Ambient transport overrides refused")
    url = oidc_request_url(environment.get("ACTIONS_ID_TOKEN_REQUEST_URL"))
    request_token = environment.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if not _bearer(request_token):
        raise Stop("GitHub identity request token unavailable")
    if opener is None:
        opener = make_opener()
    identity = read_response(opener, urllib.request.Request(url, method="GET", headers={
        "Authorization": "Bearer " + request_token, "Accept": "application/json"}),
        timeout=AUTH_TIMEOUT, limit=MAX_AUTH_BYTES)
    jwt = identity.get("value")
    if (not isinstance(jwt, str) or not 16 <= len(jwt) <= 32_768
            or not re.fullmatch(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", jwt)):
        raise Stop("Invalid GitHub identity response")
    # Anthropic verifies the signed JWT and exact rule claims. This helper does
    # not substitute an unverified local JWT decode for that authentication.
    request = urllib.request.Request(TOKEN_URL, method="POST", headers={
        "Content-Type": "application/json", "Accept": "application/json"},
        data=json_bytes({"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                         "assertion": jwt, "federation_rule_id": FEDERATION_RULE_ID,
                         "organization_id": ORGANIZATION_ID,
                         "service_account_id": SERVICE_ACCOUNT_ID,
                         "workspace_id": WORKSPACE_ID}))
    started = time.monotonic()
    token_response = read_response(opener, request, timeout=AUTH_TIMEOUT, limit=MAX_AUTH_BYTES)
    token = token_response.get("access_token")
    expires = token_response.get("expires_in")
    if (not _bearer(token, prefix="sk-ant-oat01-")
            or token_response.get("token_type") != "Bearer"
            or token_response.get("scope") != SCOPE
            or type(expires) is not int or not 1 <= expires <= 86_400
            or expires - (time.monotonic() - started) < MIN_TOKEN_LIFETIME):
        raise Stop("Unusable Anthropic authentication response")
    # Tokens are used only in this process. The final projection cannot contain
    # any of them even if an upstream response reflects an authentication header.
    return opener, token, expires, started, (request_token, jwt, token)


def completed_result(response, head, secrets, *, smoke=False):
    if (response.get("type") != "message" or response.get("role") != "assistant"
            or response.get("model") != MODEL or response.get("stop_reason") != "end_turn"
            or response.get("stop_sequence") is not None
            or response.get("stop_details") is not None or "error" in response):
        raise Stop("Incomplete Anthropic assessment")
    blocks = response.get("content")
    if not isinstance(blocks, list) or not 1 <= len(blocks) <= 64:
        raise Stop("Invalid Anthropic assessment content")
    texts = []
    for block in blocks:
        if not isinstance(block, dict):
            raise Stop("Invalid Anthropic assessment content")
        kind = block.get("type")
        if kind == "text" and isinstance(block.get("text"), str):
            if block.get("citations") not in (None, []):
                raise Stop("Unexpected Anthropic assessment citation")
            texts.append(block["text"])
        elif (not smoke and kind == "thinking" and isinstance(block.get("thinking"), str)
              and isinstance(block.get("signature"), str) and block["signature"]):
            pass  # Never emit, log, persist, or replay thinking or its signature.
        elif (not smoke and kind == "redacted_thinking" and isinstance(block.get("data"), str)
              and block["data"]):
            pass  # Opaque encrypted content is discarded without interpretation.
        else:
            raise Stop("Unexpected Anthropic assessment content")
    if len(texts) != 1 or not texts[0].strip() or len(texts[0].encode("utf-8")) > MAX_RESULT_BYTES:
        raise Stop("Invalid Anthropic assessment text")
    decision = strict_json(texts[0])
    if (not isinstance(decision, dict)
            or (smoke and decision != {"status": "ok"})
            or (not smoke and decision.get("head") != head)):
        raise Stop("Stale Anthropic assessment")
    # Normalize before filtering, so JSON Unicode escaping cannot conceal a
    # reflected credential. Full schema/decision semantics belong to the parent.
    normalized = json_bytes(decision).decode("utf-8")
    if any(secret in normalized or secret in texts[0] for secret in secrets):
        raise Stop("Reflected authentication material refused")
    usage = response.get("usage")
    if (not isinstance(usage, dict)
            or type(usage.get("input_tokens")) is not int
            or not 0 <= usage["input_tokens"] <= 1_000_000
            or type(usage.get("output_tokens")) is not int
            or not 1 <= usage["output_tokens"] <= (SMOKE_OUTPUT_TOKENS if smoke else MAX_OUTPUT_TOKENS)):
        raise Stop("Invalid Anthropic assessment usage")
    if smoke:
        return {"smoke_succeeded": True, "model_called": True, "model": MODEL,
                "usage": {key: usage[key] for key in ("input_tokens", "output_tokens")}}
    return {"status": "finished", "model": MODEL, "result": normalized,
            "usage": {key: usage[key] for key in ("input_tokens", "output_tokens")}}


def run(value=None, *, preflight=False, smoke=False, environment=None, opener=None):
    if smoke and (preflight or value is not None):
        raise Stop("Smoke test accepts no assessment input")
    if smoke:
        # Explicit owner-approved model-access check, separate from activation
        # and assessment. Fixed prompt/schema cannot carry candidate evidence.
        # Sonnet 5.5 documents between_tools at high effort (no beta required);
        # with no tools the response contains only text, within 256 output tokens.
        payload = json_bytes({"model": MODEL, "max_tokens": SMOKE_OUTPUT_TOKENS,
            "system": 'Return only the JSON object {"status":"ok"}.', "stream": False,
            "thinking": {"type": "between_tools"},
            "output_config": {"effort": "high", "format": {
                "type": "json_schema", "schema": SMOKE_SCHEMA}},
            "messages": [{"role": "user", "content": 'Return {"status":"ok"}.'}]})
    elif not preflight:
        validate_input(value)
        # Build before obtaining the one-use JWT or exchanging it, minimizing
        # token age. No candidate field is promoted to a tool or request option.
        payload = json_bytes({"model": MODEL, "max_tokens": MAX_OUTPUT_TOKENS,
            "system": value["instructions"], "stream": False,
            "thinking": {"type": "adaptive", "display": "omitted"},
            "output_config": {"effort": "high", "format": {
                "type": "json_schema", "schema": value["schema"]}},
            "messages": [{"role": "user", "content": json_bytes(value["evidence"]).decode("utf-8")}]})
    opener, token, expires, started, secrets = authenticate(
        os.environ if environment is None else environment, opener)
    if preflight:
        return {"authentication_succeeded": True, "scope": SCOPE,
                "expires_in": math.floor(expires - (time.monotonic() - started)),
                "model_called": False}
    if expires - (time.monotonic() - started) < MIN_TOKEN_LIFETIME:
        raise Stop("Insufficient Anthropic authentication lifetime")
    response = read_response(opener, urllib.request.Request(MESSAGES_URL, method="POST",
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json",
                 "Accept": "application/json", "anthropic-version": API_VERSION},
        data=payload), timeout=INFERENCE_TIMEOUT, limit=MAX_RESPONSE_BYTES)
    return completed_result(response, None if smoke else value["head"], secrets, smoke=smoke)


def main(argv=None):
    try:
        args = sys.argv[1:] if argv is None else argv
        if args not in ([], ["--preflight"], ["--smoke"]):
            raise Stop("Unsupported assessment arguments")
        preflight = args == ["--preflight"]
        smoke = args == ["--smoke"]
        value = None
        if smoke:
            if sys.stdin.buffer.read(1):
                raise Stop("Smoke test accepts no assessment input")
        elif not preflight:
            raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
            if len(raw) > MAX_INPUT_BYTES:
                raise Stop("Assessment input exceeds bound")
            value = strict_json(raw)
        result = run(value, preflight=preflight, smoke=smoke)
        output = json_bytes(result)
        if len(output) + 1 > MAX_STDOUT_BYTES:
            raise Stop("Assessment output exceeds bound")
        sys.stdout.write(output.decode("utf-8") + "\n")
        return 0
    except Exception:
        # No traceback, URL, token, response body, or arbitrary exception text.
        sys.stderr.write(SAFE_FAILURE + "\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
