#!/usr/bin/env python3
"""Private, model-free Windows driver for the Go official-GUI custody controller.

The controller owns all synthetic secret material, GUI automation, process
handles, public verification and final audit/scans. This driver receives only
public configuration. It neither installs clients nor declares custody success.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time

import mcp_named_client_smoke as runtime


class WindowsJsonProcess(runtime.JsonProcess):
    """Drain ordinary subprocess pipes without Unix select or socket emulation."""

    def __init__(self, argv, env, root):
        super().__init__(argv, env, root)
        self.condition = threading.Condition()
        self.stdout_done = False
        self.stdout_error = False
        self.stdout_worker = threading.Thread(target=self._read_stdout, daemon=True)
        self.stdout_worker.start()
        runtime.write_json(root / "client-launch.json", {"pid": self.process.pid})

    def _read_stdout(self):
        try:
            while raw := os.read(self.process.stdout.fileno(), 65536):
                with self.condition:
                    self.total += len(raw)
                    if self.total <= runtime.LIMIT:
                        self.wire.write(raw)
                        self.buffer += raw
                    self.condition.notify_all()
        except OSError:
            self.stdout_error = True
        finally:
            with self.condition:
                self.stdout_done = True
                self.condition.notify_all()

    def receive(self, deadline):
        with self.condition:
            while True:
                runtime.require(self.total <= runtime.LIMIT and not self.stdout_error,
                                "native client capture exceeded its bound or failed")
                if b"\n" in self.buffer:
                    raw, self.buffer = self.buffer.split(b"\n", 1)
                    value = json.loads(raw)
                    self.transcript.write(json.dumps({"direction": "out", "message": value}).encode() + b"\n")
                    return value
                runtime.require(not self.stdout_done, "native client closed output before response")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("native client control request timed out")
                self.condition.wait(min(remaining, 0.1))

    def close(self):
        if self.process.stdin and not self.process.stdin.closed:
            self.process.stdin.close()
        try:
            self.process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            self.escalated = True
            self.process.terminate()
            self.process.wait(timeout=5)
        self.stdout_worker.join(timeout=5)
        self.stderr_worker.join(timeout=5)
        runtime.require(self.stdout_done and self.stderr_done.is_set(), "native client captures did not reach EOF")
        self.process.stdout.close()
        self.process.stderr.close()
        self.stderr.close()
        self.transcript.close()
        self.wire.close()
        runtime.require(not self.stdout_error and not self.stderr_error and not self.stderr_overflow
                        and self.total <= runtime.LIMIT, "native client capture incomplete")
        cleanup = {"exit_code": self.process.returncode, "shutdown_escalated": self.escalated}
        runtime.write_json(self.root / "client-cleanup.json", cleanup)
        return cleanup


def environment(root):
    env = runtime.environment(root)
    for key in ("USER", "LOGNAME", "SHELL", "TMPDIR"):
        env.pop(key)
    system = Path(os.environ["SYSTEMROOT"])
    runtime.require(system.is_absolute() and system.is_dir(), "Windows system directory unavailable")
    for name in ("appdata", "localappdata"):
        (root / name).mkdir(mode=0o700)
    env.update(SYSTEMROOT=str(system), WINDIR=str(system),
               PATH=str(system / "System32") + ";" + str(system),
               USERPROFILE=str(root / "home"), APPDATA=str(root / "appdata"),
               LOCALAPPDATA=str(root / "localappdata"), TEMP=str(root / "tmp"),
               TMP=str(root / "tmp"), LANG="C", PYTHONNOUSERSITE="1", PYTHONDONTWRITEBYTECODE="1")
    return env


def scenario(call, challenge):
    entries = runtime.content(call("list_capabilities", {})).get("entries")
    runtime.require(isinstance(entries, list) and len(entries) == 2, "expected two attestation grants")
    runtime.require({entry["resource"] for entry in entries} == {"gui-allowed", "gui-revoked"},
                    "unexpected grant resources")
    attestation = None
    for entry in sorted(entries, key=lambda value: value["resource"]):
        runtime.require(set(entry) == {"handle", "operation", "resource", "key_id", "status", "expiry"}
                        and entry["operation"] == "local_artifact_attest"
                        and entry["key_id"] == challenge["key_id"]
                        and entry["status"] == ("active" if entry["resource"] == "gui-allowed" else "revoked"),
                        "attestation binding changed")
        runtime.require(runtime.exact_json(runtime.content(call("describe_capability", {
            "handle": entry["handle"]})), entry), "attestation description changed")
        result = call("invoke_capability", {"handle": entry["handle"], "payload": challenge["payload"]})
        if entry["resource"] == "gui-allowed":
            attestation = runtime.content(result)
            runtime.require(set(attestation) == {"resource", "signature", "public_key", "domain", "purpose"},
                            "attestation disclosed unexpected fields")
        else:
            runtime.require(result.get("isError") or "error" in result, "revoked operation was not denied")
    # The trusted controller separately checks the exact denial audit and signature.
    return {"tool_calls": 5, "credential_invocations": 2, "driver_retries": 0, "attestation": attestation}


def codex_before_unsubscribe(root):
    # The test controller owns the process handle and must independently
    # prove the shipping CLI is STILL RUNNING after all five MCP requests.
    # A file marker alone is never interpreted as process-liveness proof.
    ready = root / "codex-pre-unsubscribe.json"
    temporary = root / "codex-pre-unsubscribe.tmp"
    runtime.write_json(temporary, {"stage": "post-tool-calls", "tool_calls": 5})
    temporary.replace(ready)
    approved = root / "codex-server-alive.json"
    deadline = time.monotonic() + 18
    while time.monotonic() < deadline:
        try:
            marker = json.loads(approved.read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            time.sleep(0.02)
            continue
        runtime.require(marker == {"server_alive_before_unsubscribe": True},
                        "native Codex parent server-liveness attestation changed")
        return
    raise RuntimeError("native Codex pre-unsubscribe process-liveness barrier timed out")


def hermes_child(path):
    challenge = json.loads((path.parent / "public-challenge.json").read_text())
    runtime.hermes_child(path, scenario=lambda call: scenario(call, challenge))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", type=Path)
    parser.add_argument("--hermes-child", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    runtime.require(os.name == "nt", "this custody lane requires native Windows")
    runtime.require(sys.version_info[:3] == (3, 14, 8), "unreviewed Windows Python version")
    if args.hermes_child:
        hermes_child(args.hermes_child)
        return
    request = json.loads(args.request.read_text())
    root = args.request.parent
    env = environment(root)
    client, config, challenge = request["client"], request["server"], request["challenge"]
    runtime.observation_manifest(root, client, "shipping-attestation")
    runtime.write_json(root / "observations/fixture-command.json", config)
    runtime.write_json(root / "observations/public-challenge.json", challenge)

    def finalize(_root):
        receipt = runtime.wait_fixture_evidence(root, time.monotonic() + 15)
        runtime.require(receipt == {"shipping_server_exited": True}, "shipping process exit was not observed")
        return receipt

    kwargs = {"scenario": lambda call: scenario(call, challenge), "process_factory": WindowsJsonProcess}
    if client == "codex":
        result = runtime.codex_smoke(Path(request["executable"]), config, env, root, finalize=finalize,
                                     before_unsubscribe=codex_before_unsubscribe, **kwargs)
    elif client == "claude":
        result = runtime.claude_smoke(Path(request["executable"]), config, env, root, **kwargs)
    else:
        runtime.require(client == "hermes", "unknown native runtime")
        result = runtime.hermes_smoke(Path(request["executable"]), Path(request["hermes_source"]), config, env,
                                     root, child_script=Path(__file__).resolve(), process_factory=WindowsJsonProcess)
    runtime.check_observations(root / "observations")
    result["raw_client_output_capture_complete"] = True
    # This is public intermediate client evidence, not a custody pass receipt.
    runtime.write_json(root / "client-result.json", result)


if __name__ == "__main__":
    main()
