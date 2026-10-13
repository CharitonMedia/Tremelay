#!/usr/bin/env python3
"""Actual model-free named-client MCP -> synthetic hostbound SSH acceptance.

Uses only already-installed clients and the test-only SSH subprocess host.
No network service, remote login, provider account or production credential.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import struct
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import mcp_named_client_smoke as runtime

ALGORITHM = b"ssh-ed25519"
METHOD = b"publickey-hostbound-v00@openssh.com"


def string(value):
    return struct.pack(">I", len(value)) + value


def take_string(data):
    runtime.require(len(data) >= 4, "short SSH string")
    length = struct.unpack(">I", data[:4])[0]
    runtime.require(length <= len(data) - 4, "truncated SSH string")
    return data[4:4 + length], data[4 + length:]


def canonical_base64(text, maximum):
    value = base64.b64decode(text, validate=True)
    runtime.require(0 < len(value) <= maximum and base64.b64encode(value).decode() == text,
                    "noncanonical SSH value")
    return value


def public_key(blob):
    algorithm, rest = take_string(blob)
    key, rest = take_string(rest)
    runtime.require(algorithm == ALGORITHM and len(key) == 32 and not rest, "invalid SSH public key")
    return Ed25519PublicKey.from_public_bytes(key)


def preimage(session, user, key, host):
    return (string(session) + b"\x32" + string(user) + string(b"ssh-connection")
            + string(METHOD) + b"\x01" + string(ALGORITHM) + string(key) + string(host))


def exercise_ssh(call, challenge_path):
    challenge = json.loads(challenge_path.read_text())
    runtime.require(set(challenge) == {"resource", "username", "host_blob", "session_id", "bind_message"},
                    "unexpected public challenge fields")
    host = canonical_base64(challenge["host_blob"], 51)
    session = canonical_base64(challenge["session_id"], 64)
    bind = canonical_base64(challenge["bind_message"], 4096)
    catalogue = runtime.content(call("list_capabilities", {}))
    entries = catalogue.get("entries")
    runtime.require(isinstance(entries, list) and len(entries) == 2, "expected two exact SSH grants")
    selected = {}
    for entry in entries:
        runtime.require(set(entry) == {"handle", "operation", "resource", "status", "expiry"},
                        "SSH discovery disclosed identity or unexpected fields")
        runtime.require(entry["operation"] == "ssh_userauth" and entry["resource"] == challenge["resource"],
                        "unexpected SSH authority")
        runtime.require(entry["status"] not in selected, "duplicate fixture status")
        selected[entry["status"]] = entry["handle"]
        described = runtime.content(call("describe_capability", {"handle": entry["handle"]}))
        runtime.require(runtime.exact_json(described, entry), "SSH description mismatch")
    runtime.require(set(selected) == {"active", "revoked"}, "fixture lifecycle mismatch")
    runtime.require(selected["active"] != selected["revoked"], "grants shared one handle")

    def exchange(status, body):
        value = runtime.content(call("invoke_capability", {
            "handle": selected[status], "payload": base64.b64encode(body).decode()}))
        runtime.require(set(value) == {"ssh_response"}, "unexpected SSH result disclosure")
        return canonical_base64(value["ssh_response"], 88)

    runtime.require(exchange("active", b"\x0b") == b"\x0c\0\0\0\0", "identity disclosed before binding")
    runtime.require(exchange("active", bind) == b"\x06", "valid host binding failed")
    identity = exchange("active", b"\x0b")
    runtime.require(identity[:5] == b"\x0c\0\0\0\x01", "expected one post-bind identity")
    user_blob, rest = take_string(identity[5:])
    comment, rest = take_string(rest)
    runtime.require(comment == b"" and not rest, "unexpected SSH identity metadata")
    key = public_key(user_blob)
    public_key(host)
    user = challenge["username"].encode()
    message = preimage(session, user, user_blob, host)

    def sign_request(value):
        return b"\x0d" + string(user_blob) + string(value) + b"\0\0\0\0"

    response = exchange("active", sign_request(message))
    runtime.require(response[:1] == b"\x0e", "hostbound sign response missing")
    encoded_signature, rest = take_string(response[1:])
    runtime.require(not rest, "trailing sign response")
    algorithm, rest = take_string(encoded_signature)
    signature, rest = take_string(rest)
    runtime.require(algorithm == ALGORITHM and len(signature) == 64 and not rest, "invalid signature projection")
    key.verify(signature, message)
    try:
        key.verify(signature, message[:-1] + bytes([message[-1] ^ 1]))
    except InvalidSignature:
        pass
    else:
        raise RuntimeError("SSH signature verified a changed preimage")
    wrong_session = bytes([session[0] ^ 1]) + session[1:]
    runtime.require(exchange("active", sign_request(preimage(wrong_session, user, user_blob, host))) == b"\x05",
                    "wrong-session signing was not denied")
    runtime.require(exchange("active", sign_request(preimage(session, user + b"-other", user_blob, host))) == b"\x05",
                    "wrong-username signing was not denied")
    # Same principal, key, host, username and resource; the live duplicate must
    # never rescue the revoked exact handle. No operation is retried.
    runtime.require(exchange("revoked", bind) == b"\x05", "revoked grant fell back to active duplicate")
    return {"tool_calls": 10, "credential_invocations": 7, "driver_retries": 0,
            "hostbound_signatures_received": 1, "hostbound_signature_verified": True,
            "changed_preimage_rejected": True, "prebind_identity_hidden": True,
            "postbind_identity_received": True, "wrong_session_denied": True,
            "wrong_username_denied": True, "revoked_exact_grant_denied": True}


def checked_fixture(root):
    evidence = runtime.wait_fixture_evidence(root, time.monotonic() + 10)
    runtime.require(evidence["version"] == 1 and evidence["fixture"] == "synthetic-hostbound-ssh",
                    "unexpected SSH fixture receipt")
    runtime.require(runtime.exact_json(evidence["ssh_results"], {
        "active": {"allowed": 3, "completed": 1, "denied": 3},
        "revoked": {"denied_revoked": 1}}), "unexpected SSH audit counts")
    for field in ("audit_verified", "exact_authority", "own_output_secret_absent", "vault_secret_absent",
                  "observations_complete", "observed_secret_absent", "audit_context_absent", "shutdown_accepted"):
        runtime.require(evidence[field] is True, "SSH evidence check failed: " + field)
    runtime.require(evidence["observation_files"] == runtime.check_observations(root / "observations"),
                    "fixture did not scan complete declared captures")
    marker = json.loads((root / "fixture-evidence.json.launch.json").read_text())
    pid = marker["pid"]
    runtime.require(type(pid) is int and pid > 1, "invalid fixture PID")
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            state = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
        except FileNotFoundError:
            state = "gone"
        if state in {"gone", "Z"}:
            break
        time.sleep(0.02)
    runtime.require(state in {"gone", "Z"}, "fixture remained alive after cleanup")
    runtime.require(not list(root.glob(".tremelay-credential-fixture-*")), "synthetic vault cleanup incomplete")
    return {"fixture": evidence, "fixture_process_exited": True, "fixture_exit_status_observed": False,
            "exclusive_fixture_launch_marker": True, "synthetic_vault_removed": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path)
    parser.add_argument("--client", choices=("codex", "claude", "hermes"))
    parser.add_argument("--codex", type=Path)
    parser.add_argument("--claude", type=Path)
    parser.add_argument("--hermes-python", type=Path)
    parser.add_argument("--hermes-source", type=Path)
    parser.add_argument("--hermes-child", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    if args.hermes_child:
        runtime.hermes_child(args.hermes_child, scenario=lambda call: exercise_ssh(
            call, args.hermes_child.parent / "public-challenge.json"))
        return
    runtime.require(args.fixture and args.client and args.output_dir, "fixture, client and output directory required")
    runtime.require(os.name == "posix" and Path("/proc").is_dir(), "this process observer requires Linux")
    root = args.output_dir.resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    env = runtime.environment(root)
    runtime.observation_manifest(root, args.client, "ssh-userauth")
    config = {"command": str(args.fixture.resolve(strict=True)), "args": ["-test.run=^TestMCPSyntheticSSHFixture$"],
              "env": {"TREMELAY_MCP_SYNTHETIC_SSH_FIXTURE": "1",
                      "TREMELAY_MCP_FIXTURE_EVIDENCE": str(root / "fixture-evidence.json"),
                      "TREMELAY_MCP_FIXTURE_OBSERVE_DIR": str(root / "observations")}}
    runtime.write_json(root / "observations/fixture-command.json", config)
    scenario = lambda call: exercise_ssh(call, root / "observations/public-challenge.json")
    if args.client == "codex":
        result = runtime.codex_smoke(args.codex.resolve(strict=True), config, env, root,
                                     scenario=scenario, finalize=checked_fixture)
    elif args.client == "claude":
        result = runtime.claude_smoke(args.claude.resolve(strict=True), config, env, root, scenario=scenario)
    else:
        result = runtime.hermes_smoke(args.hermes_python.absolute(), args.hermes_source.resolve(strict=True),
                                     config, env, root, child_script=Path(__file__).resolve())
    if "fixture" not in result:
        result.update(checked_fixture(root))
    result.update(evidence_scope="actual named-client MCP and test-only hostbound SSH broker; no shipping CLI custody or remote login",
                  observation_manifest="observations/observation-manifest.json", model_turns=0,
                  raw_client_output_capture_complete=True, all_tool_responses_captured_before_close=True,
                  secret_scan_scope="fixture output/audit/vault and manifest captures at fixture finalization; excludes native-home code, caches, SQLite and late client output")
    runtime.write_json(root / "result.json", result)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
