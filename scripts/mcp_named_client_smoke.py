#!/usr/bin/env python3
"""Model-free named-client integration against a test-only broker subprocess.

The fixture owns fresh synthetic credentials and an explicitly injected TLS
upstream. This is not stock CLI network/custody proof (see mcp_stdio_smoke.py).
No client receives a vault passphrase, bearer token, provider key, or model turn.
Installations are deliberately separate; this script never installs anything.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import threading
import time

NAME = "tremelay_smoke"
TOOLS = {"list_capabilities", "describe_capability", "invoke_capability"}
TIMEOUT = 45
LIMIT = 4 << 20
OBSERVATION_COMMON = {
    "client-command.json", "client-environment.json", "client-stderr.log",
    "client-stdout.jsonl", "client-transcript.jsonl", "fixture-command.json",
}
OBSERVATION_CLIENT = {
    "codex": {"codex-config.toml", "client-status.json"},
    "claude": {"mcp-config.json", "client-status.json", "client-final-status.json"},
    "hermes": {"hermes-server.json", "hermes-config.yaml", "hermes-tool-inventory.json",
               "hermes-calls.jsonl", "hermes-result-before-close.json"},
}
HERMES_MODULES = {
    "tools/mcp_tool.py": "8c20af5a8da975b44ea7909bea53865179a7557a044d0623ee8d050030a1aa0a",
    "tools/mcp_tool_discovery.py": "cf2dc204fd293727e0e13a045428152f8e1925aa48ea521f6ec97035dd1e86d9",
    "tools/mcp_tool_handlers.py": "d3f99c5832dd7a99b0a39447f97981281cccd13ba582587b97f914c726cdb5d6",
    "tools/mcp_tool_transport.py": "b8f415a5d90c9ad2f0f0a7468fa863e3ebd14bbe9a58e99e46654b02e05375f9",
    "tools/mcp_tool_lifecycle.py": "243bb5f655964ba32e4b8a9855ac2b60a189627628ec58a86487cf998acd3811",
}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def write_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
    path.chmod(0o600)


def exact_json(actual, expected):
    # Python equality otherwise treats 0 == False and 3.0 == 3.
    return json.dumps(actual, sort_keys=True) == json.dumps(expected, sort_keys=True)


def environment(root):
    for name in ("home", "codex", "claude", "hermes", "runtime", "tmp", "work", "cache", "observations"):
        (root / name).mkdir(mode=0o700, exist_ok=True)
    # Explicit allowlist: neither caller's HOME/config nor ambient secrets/proxies.
    return {
        "HOME": str(root / "home"), "CODEX_HOME": str(root / "codex"),
        "CLAUDE_CONFIG_DIR": str(root / "claude"), "HERMES_HOME": str(root / "hermes"),
        "XDG_RUNTIME_DIR": str(root / "runtime"), "XDG_CACHE_HOME": str(root / "cache"),
        "TMPDIR": str(root / "tmp"), "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
        "USER": "tremelay-smoke", "LOGNAME": "tremelay-smoke", "SHELL": "/bin/sh",
        "DISABLE_AUTOUPDATER": "1", "DISABLE_TELEMETRY": "1", "DISABLE_ERROR_REPORTING": "1",
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1", "MCP_TIMEOUT": "30000",
    }


def fixture_config(binary, root):
    return {
        "command": str(binary), "args": ["-test.run=^TestMCPSyntheticCredentialFixture$"],
        "env": {"TREMELAY_MCP_SYNTHETIC_FIXTURE": "1",
                "TREMELAY_MCP_FIXTURE_EVIDENCE": str(root / "fixture-evidence.json"),
                "TREMELAY_MCP_FIXTURE_OBSERVE_DIR": str(root / "observations")},
    }


def observation_manifest(root, client, scenario="credential-brokers"):
    require(scenario in {"credential-brokers", "shipping-attestation"}, "unknown observation scenario")
    extra = {"public-challenge.json"} if scenario == "shipping-attestation" else set()
    write_json(root / "observations/observation-manifest.json", {
        "client": client, "scenario": scenario,
        "required_files": sorted(OBSERVATION_COMMON | OBSERVATION_CLIENT[client] | extra),
        "scope": "raw captures and generated configuration; excludes native-home code, caches, SQLite and late-output scan",
    })


def check_observations(directory):
    manifest = json.loads((directory / "observation-manifest.json").read_text())
    expected = OBSERVATION_COMMON | OBSERVATION_CLIENT[manifest["client"]]
    require(manifest["scenario"] in {"credential-brokers", "shipping-attestation"}, "unknown observation scenario")
    if manifest["scenario"] == "shipping-attestation":
        expected = expected | {"public-challenge.json"}
    require(set(manifest["required_files"]) == expected, "observation manifest mismatch")
    require({p.name for p in directory.iterdir()} == expected | {"observation-manifest.json"},
            "observation files missing or unexpected")
    for name in expected:
        path = directory / name
        require(not path.is_symlink() and path.is_file() and path.stat().st_size <= LIMIT,
                "required observation is unavailable or exceeds bounds")
    return len(expected) + 1


def content(value):
    require(not value.get("isError") and "error" not in value, "MCP operation failed")
    if isinstance(value.get("structuredContent"), dict):
        return value["structuredContent"]
    # Hermes deliberately deduplicates equivalent text + structuredContent.
    result = value.get("result")
    if isinstance(result, dict):
        return result
    if isinstance(result, str):
        return json.loads(result)
    blocks = value.get("content", [])
    if len(blocks) == 1 and blocks[0].get("type") == "text":
        return json.loads(blocks[0]["text"])
    raise RuntimeError("MCP operation omitted an inspectable result")


def exercise(call):
    catalogue = content(call("list_capabilities", {}))
    entries = catalogue.get("entries")
    require(isinstance(entries, list) and len(entries) == 3, "expected three fixture grants")
    wanted = {"GET https://protected.example/v1/ping", "GET https://protected.example/v1/denied",
              "GET https://api.github.com/repos/octocat/Hello-World/issues/17"}
    require({entry["resource"] for entry in entries} == wanted, "unexpected fixture resources")
    results = []
    for entry in sorted(entries, key=lambda row: row["resource"]):
        require(set(entry) == {"handle", "operation", "resource", "status", "expiry"},
                "network metadata exposed unexpected fields")
        require(entry["status"] == ("revoked" if entry["resource"].endswith("/denied") else "active"),
                "unexpected grant lifecycle state")
        described = content(call("describe_capability", {"handle": entry["handle"]}))
        require(described == entry, "capability description mismatch")
        result = call("invoke_capability", {"handle": entry["handle"]})
        if entry["resource"].endswith("/denied"):
            require(result.get("isError") or "error" in result, "revoked operation was not denied")
            results.append({"operation": "http_request", "result": "denied"})
        elif entry["operation"] == "http_request":
            require(exact_json(content(result), {"status_code": 200}), "unexpected HTTP disclosure")
            results.append({"operation": "http_request", "result": "completed"})
        else:
            require(entry["operation"] == "github_issue_state", "unexpected operation")
            require(exact_json(content(result), {"number": 17, "state": "open", "locked": False, "comments": 3}),
                    "unexpected GitHub disclosure")
            results.append({"operation": "github_issue_state", "result": "completed"})
    return {"tool_calls": 7, "credential_invocations": 3, "results": results, "driver_retries": 0}


class JsonProcess:
    def __init__(self, argv, env, root):
        self.root = root
        observed = root / "observations"
        self.stderr = open(observed / "client-stderr.log", "wb")
        self.transcript = open(observed / "client-transcript.jsonl", "wb", buffering=0)
        self.wire = open(observed / "client-stdout.jsonl", "wb", buffering=0)
        write_json(observed / "client-environment.json", env)
        write_json(observed / "client-command.json", argv)
        self.process = subprocess.Popen(argv, env=env, cwd=root / "work", stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.stderr_overflow = False
        self.stderr_error = False
        self.stderr_done = threading.Event()
        self.stderr_worker = threading.Thread(target=self._read_stderr, daemon=True)
        self.stderr_worker.start()
        self.buffer = b""
        self.total = 0
        self.seq = 0
        self.escalated = False
        self.notifications = []

    def _read_stderr(self):
        total = 0
        try:
            while raw := os.read(self.process.stderr.fileno(), 8192):
                remaining = LIMIT - total
                if remaining > 0:
                    self.stderr.write(raw[:remaining])
                    self.stderr.flush()
                total += len(raw)
                if total > LIMIT:
                    self.stderr_overflow = True
        except OSError:
            self.stderr_error = True
        finally:
            self.stderr_done.set()

    def send(self, value):
        data = json.dumps(value, separators=(",", ":")).encode() + b"\n"
        self.transcript.write(json.dumps({"direction": "in", "message": value}).encode() + b"\n")
        self.process.stdin.write(data)
        self.process.stdin.flush()

    def receive(self, deadline):
        while time.monotonic() < deadline:
            if b"\n" in self.buffer:
                raw, self.buffer = self.buffer.split(b"\n", 1)
                value = json.loads(raw)
                self.transcript.write(json.dumps({"direction": "out", "message": value}).encode() + b"\n")
                return value
            if select.select([self.process.stdout], [], [], 0.05)[0]:
                raw = os.read(self.process.stdout.fileno(), 65536)
                require(bool(raw), "client closed output before response; inspect private synthetic logs")
                self.total += len(raw)
                require(self.total <= LIMIT, "client output exceeded bound")
                self.wire.write(raw)
                self.buffer += raw
        raise TimeoutError("named client control request timed out")

    def rpc(self, method, params):
        self.seq += 1
        number = self.seq
        self.send({"id": number, "method": method, "params": params})
        deadline = time.monotonic() + TIMEOUT
        while True:
            value = self.receive(deadline)
            if value.get("id") == number:
                require("error" not in value, "Codex control request failed")
                return value["result"]
            require("id" not in value, "unexpected client request requiring human action")
            self.notifications.append(value)

    def wait_notification(self, method, params, deadline):
        while True:
            for value in self.notifications:
                if value.get("method") == method and value.get("params") == params:
                    return
            value = self.receive(deadline)
            require("id" not in value, "unexpected client request while waiting for shutdown")
            self.notifications.append(value)

    def control(self, request, *, tool_result=False, deadline=None):
        self.seq += 1
        number = str(self.seq)
        self.send({"type": "control_request", "request_id": number, "request": request})
        if deadline is None:
            deadline = time.monotonic() + TIMEOUT
        while True:
            value = self.receive(deadline)
            if value.get("type") == "control_response" and value["response"].get("request_id") == number:
                response = value["response"]
                if tool_result and response.get("subtype") == "error":
                    # Claude maps MCP isError into a control error. This is only
                    # accepted as the intended denial when fixture audit agrees.
                    return {"error": response.get("error", "control request failed")}
                require(response.get("subtype") == "success", "Claude control request failed")
                return response.get("response", {})
            require(value.get("type") != "control_request", "unexpected Claude request requiring human action")
            require(value.get("type") not in {"assistant", "result", "user"}, "unexpected model/session turn")

    def close(self):
        # Every call's correlated response has already been captured and flushed.
        # Drain currently readable, unsolicited output before the teardown snapshot.
        while select.select([self.process.stdout], [], [], 0)[0]:
            raw = os.read(self.process.stdout.fileno(), 65536)
            if not raw:
                break
            self.total += len(raw)
            if self.total > LIMIT:
                break
            self.wire.write(raw)
        if self.process.stdin and not self.process.stdin.closed:
            self.process.stdin.close()
        try:
            self.process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            self.escalated = True
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        stdout_eof = False
        drain_deadline = time.monotonic() + 5
        while (remaining := drain_deadline - time.monotonic()) > 0:
            if not select.select([self.process.stdout], [], [], min(1, remaining))[0]:
                continue
            raw = os.read(self.process.stdout.fileno(), 65536)
            if not raw:
                stdout_eof = True
                break
            self.total += len(raw)
            if self.total > LIMIT:
                break
            self.wire.write(raw)
        self.process.stdout.close()
        self.stderr_worker.join(timeout=5)
        require(self.stderr_done.is_set(), "client stderr did not close")
        self.process.stderr.close()
        self.stderr.close()
        self.transcript.close()
        self.wire.close()
        require(not self.stderr_error and not self.stderr_overflow, "stderr capture incomplete")
        require(self.total <= LIMIT, "stdout exceeded bound")
        require(stdout_eof, "client stdout capture did not reach EOF")
        cleanup = {"exit_code": self.process.returncode, "shutdown_escalated": self.escalated}
        write_json(self.root / "client-cleanup.json", cleanup)
        return cleanup


def wait_fixture_evidence(root, deadline):
    path = root / "fixture-evidence.json"
    while time.monotonic() < deadline:
        try:
            return json.loads(path.read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            # The fixture exclusively creates and then writes this small file.
            # Observe completion only; never replay an MCP operation.
            time.sleep(0.02)
    raise RuntimeError("fixture did not finalize evidence")


def checked_fixture(root):
    evidence_path = root / "fixture-evidence.json"
    evidence = wait_fixture_evidence(root, time.monotonic() + 10)
    result = {"fixture": evidence}
    require(exact_json(evidence["broker_results"], {
        "http_request": {"allowed": 1, "completed": 1, "denied_revoked": 1},
        "github_issue_state": {"allowed": 1, "completed": 1}}), "unexpected broker audit counts")
    require(evidence["authenticated_requests"] == 2 and evidence["unauthenticated_self_checks"] == 2,
            "unexpected protected-service counts")
    require(evidence["unexpected_requests"] == 0, "unexpected upstream request")
    for field in ("audit_verified", "allowed_before_request", "own_output_secret_absent",
                  "vault_secret_absent", "observations_complete", "observed_secret_absent", "shutdown_accepted"):
        require(evidence[field] is True, "fixture evidence check failed: " + field)
    require(evidence["observation_files"] == check_observations(root / "observations"),
            "fixture did not scan the complete observation manifest")
    marker = json.loads(Path(str(evidence_path) + ".launch.json").read_text())
    pid = marker["pid"]
    require(isinstance(pid, int) and pid > 1, "invalid fixture launch PID")
    if Path("/proc").is_dir():
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                state = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
            except FileNotFoundError:
                state = "gone"
            if state in {"gone", "Z"}:
                break
            time.sleep(0.02)
        require(state in {"gone", "Z"}, "fixture remained alive after client cleanup")
        result["fixture_process_exited"] = True
    result["fixture_exit_status_observed"] = False
    result["exclusive_fixture_launch_marker"] = True
    return result


def codex_smoke(command, config, env, root, *, scenario=exercise, finalize=checked_fixture):
    env = dict(env, RUST_LOG="error,codex_rmcp_client::stdio_server_launcher=info")
    path = root / "codex/config.toml"
    path.write_text('\n'.join([
        'thread_unload_delay_secs = 0',
        '[analytics]', 'enabled = false', '[mcp_servers.' + NAME + ']',
        'command = ' + json.dumps(config['command']), 'args = ' + json.dumps(config['args']),
        'startup_timeout_sec = 35', 'tool_timeout_sec = 30',
        '[mcp_servers.' + NAME + '.env]',
        *[key + ' = ' + json.dumps(value) for key, value in config['env'].items()], '',
    ]))
    (root / "observations/codex-config.toml").write_bytes(path.read_bytes())
    app = JsonProcess([str(command), "app-server", "--stdio"], env, root)
    try:
        initialized = app.rpc("initialize", {"clientInfo": {"name": "tremelay_broker_smoke", "version": "1"},
                                             "capabilities": {"experimentalApi": True}})
        require("/0.159.2 " in initialized["userAgent"], "unreviewed Codex version")
        app.send({"method": "initialized", "params": {}})
        thread = app.rpc("thread/start", {"ephemeral": True, "environments": [],
                         "cwd": str(root / "work"), "approvalPolicy": "never", "sandbox": "read-only"})
        require(thread["thread"]["ephemeral"] and not thread["thread"]["turns"], "unexpected model turn")
        thread_id = thread["thread"]["id"]
        status = app.rpc("mcpServerStatus/list", {"threadId": thread_id, "serverName": NAME,
                                                 "detail": "toolsAndAuthOnly"})
        require(len(status["data"]) == 1, "unexpected Codex server inventory")
        inventory = {tool["name"] for tool in status["data"][0]["tools"].values()}
        require(inventory == TOOLS, "unexpected Codex tool inventory")
        write_json(root / "observations/client-status.json", status)
        result = scenario(lambda tool, args: app.rpc("mcpServer/tool/call", {
            "threadId": thread_id, "server": NAME, "tool": tool, "arguments": args}))
        result.update(client="Codex app-server", version=initialized["userAgent"], tools=sorted(inventory),
                      protocol=None, protocol_observed=False)
        check_observations(root / "observations")
        # Keep Tokio alive while Codex asynchronously closes its MCP transport.
        # App-server EOF alone does not join that background transport cleanup.
        unsubscribed = app.rpc("thread/unsubscribe", {"threadId": thread_id})
        require(unsubscribed == {"status": "unsubscribed"}, "Codex thread did not unsubscribe")
        app.wait_notification("thread/closed", {"threadId": thread_id}, time.monotonic() + 15)
        result.update(finalize(root))
        result["thread_closed_before_app_server_eof"] = True
    finally:
        cleanup = app.close()
    require(cleanup == {"exit_code": 0, "shutdown_escalated": False}, "Codex cleanup failed")
    return dict(result, cleanup=cleanup, model_turns=0)


def claude_smoke(command, config, env, root, *, scenario=exercise):
    path = root / "observations/mcp-config.json"
    write_json(path, {"mcpServers": {NAME: dict(config, type="stdio")}})
    version = subprocess.run([str(command), "--version"], env=env, cwd=root / "work",
                             capture_output=True, check=True, timeout=10).stdout.decode().strip()
    require(version.startswith("2.1.296 "), "unreviewed Claude Code version")
    app = JsonProcess([str(command), "--print", "--input-format", "stream-json",
                       "--output-format", "stream-json", "--verbose", "--no-session-persistence",
                       "--mcp-config", str(path), "--strict-mcp-config", "--tools", "",
                       "--permission-mode", "dontAsk"], env, root)
    try:
        app.control({"subtype": "initialize"})
        startup_deadline = time.monotonic() + TIMEOUT
        while True:
            status = app.control({"subtype": "mcp_status"}, deadline=startup_deadline)
            servers = status.get("mcpServers", [])
            require(len(servers) == 1 and servers[0]["name"] == NAME, "unexpected Claude startup inventory")
            state = servers[0]["status"]
            inventory = {tool["name"] for tool in servers[0].get("tools", [])}
            if state == "connected" and inventory == TOOLS:
                break
            require(state in {"pending", "connected"}, "Claude MCP startup failed or requires authentication")
            require(not inventory or inventory == TOOLS, "unexpected Claude startup tool inventory")
            require(time.monotonic() < startup_deadline, "Claude MCP startup did not finish")
            # Status reads wait for the first connection. No tool call is replayed.
            time.sleep(0.1)
        write_json(root / "observations/client-status.json", status)
        result = scenario(lambda tool, args: app.control({"subtype": "mcp_call",
                          "tool": "mcp__" + NAME + "__" + tool, "arguments": args}, tool_result=True))
        final_status = app.control({"subtype": "mcp_status"})
        write_json(root / "observations/client-final-status.json", final_status)
        servers = final_status.get("mcpServers", [])
        require(len(servers) == 1 and servers[0]["name"] == NAME and servers[0]["status"] == "connected",
                "unexpected Claude server inventory")
        inventory = {tool["name"] for tool in servers[0].get("tools", [])}
        require(inventory == TOOLS, "unexpected Claude tool inventory")
        result.update(client="Claude Code stream-json control", version=version, tools=sorted(inventory),
                      protocol=None, protocol_observed=False)
        check_observations(root / "observations")
    finally:
        cleanup = app.close()
    require(cleanup == {"exit_code": 0, "shutdown_escalated": False}, "Claude cleanup failed")
    return dict(result, cleanup=cleanup, model_turns=0)


def hermes_child(config_path, *, scenario=exercise):
    # Runs under the separate, pinned Hermes interpreter/source environment.
    from tools import mcp_tool as core
    from tools.mcp_tool_discovery import register_mcp_servers
    from tools.mcp_tool_handlers import _make_tool_handler
    from tools.mcp_tool_lifecycle import shutdown_mcp_servers
    from tools.mcp_tool_schema import mcp_prefixed_tool_name
    config = json.loads(config_path.read_text())
    result = None
    try:
        inventory = register_mcp_servers({NAME: config})
        write_json(config_path.parent / "hermes-tool-inventory.json", inventory)
        require(set(inventory) == {mcp_prefixed_tool_name(NAME, tool) for tool in TOOLS},
                "unexpected Hermes native tool inventory")
        server = core._servers[NAME]
        init = server.initialize_result
        protocol = getattr(init, "protocol_version", getattr(init, "protocolVersion", None))
        require(protocol in {"2025-06-18", "2025-11-25"}, "unexpected Hermes negotiated protocol")
        require(importlib.metadata.version("mcp") == "2.0.0", "unreviewed Hermes MCP SDK version")
        with open(config_path.parent / "hermes-calls.jsonl", "w", buffering=1) as transcript:
            def call(tool, args):
                value = json.loads(_make_tool_handler(NAME, tool, 30)(args))
                transcript.write(json.dumps({"tool": tool, "arguments": args, "response": value}) + "\n")
                transcript.flush()
                return value
            result = scenario(call)
        result.update(client="Hermes native MCP runtime", version="v0.21.7",
                      commit="71d34bad1045610252eda02ee79549436896e784",
                      python=sys.version.split()[0], mcp=importlib.metadata.version("mcp"),
                      tools=sorted(inventory), protocol=protocol, protocol_observed=True, model_turns=0)
        write_json(config_path.parent / "hermes-result-before-close.json", result)
        check_observations(config_path.parent)
    finally:
        shutdown_mcp_servers()
    print(json.dumps(result, sort_keys=True), flush=True)


def hermes_smoke(python, source, config, env, root, *, child_script=None):
    for relative, expected in HERMES_MODULES.items():
        require(hashlib.sha256((source / relative).read_bytes()).hexdigest() == expected,
                "unreviewed Hermes runtime module: " + relative)
    env = dict(env, PYTHONPATH=str(source), PYTHONDONTWRITEBYTECODE="1")
    config = dict(config, protocol="legacy", connect_timeout=30, tool_timeout=30,
                  supports_parallel_tool_calls=False, sampling={"enabled": False},
                  elicitation={"enabled": False})
    path = root / "observations/hermes-server.json"
    write_json(path, config)
    write_json(root / "hermes/config.yaml", {"mcp_servers": {NAME: config}})
    write_json(root / "observations/hermes-config.yaml", {"mcp_servers": {NAME: config}})
    script = Path(__file__).resolve() if child_script is None else child_script
    app = JsonProcess([str(python), str(script), "--hermes-child", str(path)], env, root)
    # The child does not consume this control pipe; Hermes owns the fixture pipe.
    try:
        result = app.receive(time.monotonic() + 90)
    finally:
        cleanup = app.close()
    require(cleanup == {"exit_code": 0, "shutdown_escalated": False}, "Hermes cleanup failed")
    return dict(result, cleanup=cleanup)


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
        hermes_child(args.hermes_child)
        return
    require(args.fixture and args.client and args.output_dir, "fixture, client and output directory required")
    root = args.output_dir.resolve()
    require(os.name == "posix", "this process observer is currently POSIX-only")
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    env = environment(root)
    observation_manifest(root, args.client)
    config = fixture_config(args.fixture.resolve(strict=True), root)
    write_json(root / "observations/fixture-command.json", config)
    if args.client == "codex":
        result = codex_smoke(args.codex.resolve(strict=True), config, env, root)
    elif args.client == "claude":
        result = claude_smoke(args.claude.resolve(strict=True), config, env, root)
    else:
        result = hermes_smoke(args.hermes_python.absolute(), args.hermes_source.resolve(strict=True), config, env, root)
    if "fixture" not in result:
        result.update(checked_fixture(root))
    result["secret_scan_scope"] = "fixture output/audit/vault and manifest-listed captures/configuration present at fixture finalization; excludes native-home bundled code, caches, SQLite and late client output"
    result["observation_manifest"] = "observations/observation-manifest.json"
    result["all_tool_responses_captured_before_close"] = True
    result["raw_client_output_capture_complete"] = True
    result["evidence_scope"] = "real named client and broker runtime; synthetic upstream; not stock CLI network proof"
    write_json(root / "result.json", result)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
