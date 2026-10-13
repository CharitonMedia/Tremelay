#!/usr/bin/env python3
"""One model-free attestation through a real named client and shipping Tremelay.

The trusted outer process reuses the existing synthetic setup and official
pinentry PTY harness unchanged. Only public challenge material reaches clients.
This tests CLI custody, not a network credential broker or hostile-host isolation.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import shutil
import subprocess

import mcp_named_client_smoke as runtime
import mcp_stdio_smoke as custody


def attestation_scenario(call, challenge, binary, vault):
    pids = custody.process_ids(binary, vault)
    runtime.require(len(pids) == 1, "expected one named-client-launched shipping Tremelay")
    catalogue = runtime.content(call("list_capabilities", {}))
    entries = catalogue.get("entries")
    runtime.require(isinstance(entries, list) and len(entries) == 1, "expected one attestation grant")
    entry = entries[0]
    runtime.require(set(entry) == {"handle", "operation", "resource", "key_id", "status", "expiry"},
                    "unexpected attestation metadata")
    public = base64.b64decode(challenge["public_key"], validate=True)
    runtime.require(entry["operation"] == "local_artifact_attest"
                    and entry["resource"] == challenge["resource"]
                    and entry["key_id"] == public.hex() and entry["status"] == "active",
                    "attestation grant binding mismatch")
    described = runtime.content(call("describe_capability", {"handle": entry["handle"]}))
    runtime.require(runtime.exact_json(described, entry), "attestation description mismatch")
    attestation = runtime.content(call("invoke_capability", {
        "handle": entry["handle"], "payload": challenge["payload"]}))
    return {"tool_calls": 3, "credential_invocations": 1, "driver_retries": 0,
            "server_pids": sorted(pids), "attestation": attestation}


def hermes_child(config_path):
    config = json.loads(config_path.read_text())
    challenge = json.loads((config_path.parent / "public-challenge.json").read_text())
    args = config["args"]
    vault = Path(args[args.index("--path") + 1])
    runtime.hermes_child(config_path, scenario=lambda call: attestation_scenario(
        call, challenge, Path(config["command"]), vault))


def scan_observations(root, fixture):
    count = runtime.check_observations(root / "observations")
    for path in (root / "observations").iterdir():
        fixture.no_secret(path.read_bytes())
        runtime.require(custody.SESSION_FAILED not in path.read_bytes(),
                        "shipping server failure diagnostic was observed")
    return {"files": count, "secret_absent": True,
            "scope": "manifest-listed full client captures and generated public configuration after client EOF"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--pinentry", type=Path)
    parser.add_argument("--client", choices=("codex", "claude", "hermes"))
    parser.add_argument("--codex", type=Path)
    parser.add_argument("--claude", type=Path)
    parser.add_argument("--hermes-python", type=Path)
    parser.add_argument("--hermes-source", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--hermes-child", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.hermes_child:
        hermes_child(args.hermes_child)
        return
    runtime.require(args.binary and args.pinentry and args.client and args.output_dir,
                    "binary, pinentry, client and output directory required")
    runtime.require(os.name == "posix" and Path("/proc").is_dir(), "custody observer requires Linux PTYs and /proc")
    root = args.output_dir.resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    binary = args.binary.resolve(strict=True)
    helper = args.pinentry.resolve(strict=True)
    helper_version = subprocess.run([str(helper), "--version"], capture_output=True, check=True,
                                    timeout=5, env={"PATH": "/usr/bin:/bin"}).stdout.decode().splitlines()[0]
    runtime.require("pinentry" in helper_version, "expected installed official pinentry")
    fixture = None
    try:
        # Only this trusted process and its setup CLI children hold the private
        # key/passphrase. Fixture removes the temporary key before any client starts.
        fixture = custody.Fixture(root, binary, helper)
        runtime.require(not (root / "synthetic-key.der").exists(), "setup key was not removed")
        env = dict(runtime.environment(root), TERM="xterm")
        runtime.observation_manifest(root, args.client, "shipping-attestation")
        challenge = {"resource": custody.RESOURCE,
                     "public_key": base64.b64encode(fixture.public).decode(),
                     "payload": base64.b64encode(fixture.payload).decode()}
        runtime.write_json(root / "observations/public-challenge.json", challenge)
        observed_pids = set()

        def scenario(call):
            value = attestation_scenario(call, challenge, binary, fixture.vault)
            observed_pids.update(value["server_pids"])
            return value

        def finalize(_root):
            runtime.require(len(observed_pids) == 1, "shipping process was not observed")
            custody.require_exited(observed_pids)
            return {"shipping_server_exited_before_app_server_eof": True}

        with custody.PinentryTerminal(fixture.passphrase, helper) as terminal:
            config = {"command": str(binary), "args": fixture.args(terminal.path), "env": {}}
            fixture.no_secret(json.dumps(config).encode())
            fixture.no_secret(json.dumps(env).encode())
            runtime.write_json(root / "observations/fixture-command.json", config)
            if args.client == "codex":
                result = runtime.codex_smoke(args.codex.resolve(strict=True), config, env, root,
                                             scenario=scenario, finalize=finalize)
            elif args.client == "claude":
                result = runtime.claude_smoke(args.claude.resolve(strict=True), config, env, root,
                                              scenario=scenario)
            else:
                result = runtime.hermes_smoke(args.hermes_python.absolute(), args.hermes_source.resolve(strict=True),
                                              config, env, root, child_script=Path(__file__).resolve())
                observed_pids.update(result["server_pids"])
            runtime.require(len(observed_pids) == 1, "shipping process count mismatch")
            custody.require_exited(observed_pids)
            fixture.verify(result.pop("attestation"))
            pinentry = terminal.verify()
        result.update(evidence_scope="shipping CLI launch/unlock/attestation/custody; no network credential operation",
                      public_signature_verified=True, server_process_count=1, server_process_exited=True,
                      server_exit_status_observed=False, model_turns=0,
                      observation_manifest="observations/observation-manifest.json",
                      raw_client_output_capture_complete=True, pinentry=dict(pinentry, version=helper_version),
                      audit=fixture.audit(), secret_scan=scan_observations(root, fixture))
    finally:
        # Preserve only non-secret evidence. Never erase a vault under a live server.
        vault = root / "synthetic.vault"
        custody.require_exited(custody.process_ids(binary, vault))
        keyfile = root / "synthetic-key.der"
        if keyfile.exists():
            keyfile.unlink()
        if vault.is_dir():
            shutil.rmtree(vault)
        elif vault.exists():
            vault.unlink()
    result.update(synthetic_vault_removed=not vault.exists(), setup_key_removed=not keyfile.exists())
    fixture.no_secret(json.dumps(result).encode())
    runtime.write_json(root / "result.json", result)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
