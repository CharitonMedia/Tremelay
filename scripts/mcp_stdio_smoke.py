#!/usr/bin/env python3
"""Synthetic, model-free real-client smoke test for Tremelay's stdio profile.

Requires an already-built Tremelay, official Python mcp and cryptography, an
installed Codex app-server, and official pinentry-curses. Nothing is installed.
Uses fresh keys/vaults and private disposable client homes; no user config or
credentials are read. A dedicated PTY supplies synthetic pinentry input, never
MCP stdin. This is compatibility evidence, not a host-compromise boundary.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import datetime as dt
import fcntl
import importlib.metadata
import json
import os
from pathlib import Path
import secrets
import select
import shutil
import struct
import subprocess
import tempfile
import termios
import threading
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

TOOLS = {"list_capabilities", "describe_capability", "invoke_capability"}
DOMAIN = "tremelay/local-artifact-attestation/v1"
PURPOSE = "local-artifact-attestation"
RESOURCE = "stdio-smoke-artifact"
TIMEOUT = 40


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def environment(root: Path) -> dict[str, str]:
    for name in ("home", "codex", "runtime", "tmp", "work"):
        (root / name).mkdir(mode=0o700, exist_ok=True)
    return {
        "HOME": str(root / "home"), "CODEX_HOME": str(root / "codex"),
        "XDG_RUNTIME_DIR": str(root / "runtime"), "TMPDIR": str(root / "tmp"),
        "PATH": "/usr/bin:/bin", "TERM": "xterm", "LANG": "C.UTF-8",
        "USER": "tremelay-smoke", "LOGNAME": "tremelay-smoke", "SHELL": "/bin/sh",
    }


def process_ids(binary: Path, vault: Path) -> set[int]:
    """Observe only processes belonging to this fresh disposable vault."""
    result = set()
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            args = (entry / "cmdline").read_bytes().split(b"\0")
            if args and args[0] == os.fsencode(binary) and os.fsencode(vault) in args:
                result.add(int(entry.name))
        except (OSError, ProcessLookupError):
            pass
    return result


def alive(pid: int) -> bool:
    try:
        # A zombie has exited, even if its parent has not yet reaped it.
        return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0] != "Z"
    except (OSError, ProcessLookupError):
        return False


def require_exited(pids: set[int]) -> None:
    deadline = time.monotonic() + 10
    while any(alive(pid) for pid in pids) and time.monotonic() < deadline:
        time.sleep(0.02)
    require(not any(alive(pid) for pid in pids), "server or pinentry did not exit")


class PinentryTerminal:
    """Observe official curses UI and send one disposable passphrase no-echo."""

    def __init__(self, passphrase: bytes, helper: Path):
        self.master, self.slave = os.openpty()
        fcntl.ioctl(self.slave, termios.TIOCSWINSZ, struct.pack("HHHH", 30, 100, 0, 0))
        self.path = os.ttyname(self.slave)
        self.initial_attrs = termios.tcgetattr(self.slave)
        self.passphrase = passphrase
        self.helper = helper
        self.transcript = bytearray()
        self.sent = False
        self.no_echo = False
        self.pids: set[int] = set()
        self.error: Exception | None = None
        self.stop = threading.Event()
        self.worker = threading.Thread(target=self._run, daemon=True)

    def __enter__(self):
        self.worker.start()
        return self

    def _run(self):
        try:
            deadline = time.monotonic() + TIMEOUT
            while not self.stop.is_set() and time.monotonic() < deadline:
                if select.select([self.master], [], [], 0.02)[0]:
                    self.transcript.extend(os.read(self.master, 8192))
                    require(len(self.transcript) <= 131072, "pinentry UI exceeded capture bound")
                if not self.sent and b"Vault passphrase" in self.transcript:
                    attrs = termios.tcgetattr(self.slave)
                    if not attrs[3] & termios.ECHO:
                        self.no_echo = True
                        for entry in Path("/proc").iterdir():
                            if not entry.name.isdecimal():
                                continue
                            try:
                                if (entry / "exe").resolve() == self.helper.resolve():
                                    # Only record the helper attached to our synthetic PTY.
                                    for fd in (entry / "fd").iterdir():
                                        if os.readlink(fd) == self.path:
                                            self.pids.add(int(entry.name))
                                            break
                            except (OSError, ProcessLookupError):
                                pass
                        os.write(self.master, self.passphrase + b"\r")
                        self.sent = True
            if not self.stop.is_set() and not self.sent:
                raise RuntimeError("pinentry did not show its no-echo prompt")
        except Exception as exc:
            self.error = exc

    def __exit__(self, *_):
        self.stop.set()
        self.worker.join(timeout=2)
        os.close(self.master)
        os.close(self.slave)

    def verify(self) -> dict:
        require(self.error is None, "pinentry UI observer failed")
        require(self.sent and self.no_echo, "pinentry was not entered with terminal echo disabled")
        require(self.passphrase not in self.transcript, "passphrase appeared in terminal output")
        require(termios.tcgetattr(self.slave) == self.initial_attrs, "pinentry terminal settings were not restored")
        require(bool(self.pids), "official pinentry helper lifecycle was not observed")
        require_exited(self.pids)
        return {"official_helper": True, "dedicated_pty": True, "echo_disabled": True,
                "passphrase_not_echoed": True, "terminal_restored": True, "helper_exited": True}


class Fixture:
    def __init__(self, root: Path, binary: Path, pinentry: Path):
        self.root, self.binary, self.pinentry = root, binary, pinentry
        self.env = environment(root)
        self.vault = root / "synthetic.vault"
        self.passphrase = ("synthetic-" + secrets.token_hex(24)).encode()
        self.key = Ed25519PrivateKey.generate()
        self.public = self.key.public_key().public_bytes_raw()
        self.payload = ("stdio-smoke-payload-" + secrets.token_hex(24)).encode()
        self.private = self.key.private_bytes(serialization.Encoding.DER,
                                             serialization.PrivateFormat.PKCS8,
                                             serialization.NoEncryption())
        keyfile = root / "synthetic-key.der"
        keyfile.write_bytes(self.private)
        keyfile.chmod(0o600)
        self.cli("vault", "create")
        self.credential = self.cli("credential", "put", "--label", "synthetic signing key",
                                   "--type", "ed25519", "--secret-file", str(keyfile)).strip()
        self.agent = self.cli("agent", "create", "--label", "synthetic stdio client").strip()
        self.grant = self.cli("grant", "create", "--agent", self.agent, "--credential", self.credential,
                              "--operation", "local_artifact_attest", "--resource", RESOURCE,
                              "--expires", (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=1))
                              .strftime("%Y-%m-%dT%H:%M:%SZ")).strip()
        keyfile.unlink()

    def cli(self, *args: str) -> str:
        env = dict(self.env, TREMELAY_PASSPHRASE=self.passphrase.decode())
        result = subprocess.run([str(self.binary), *args, "--path", str(self.vault)],
                                env=env, cwd=self.root / "work", stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=TIMEOUT)
        require(result.returncode == 0, "synthetic vault control-plane setup/check failed")
        self.no_secret(result.stdout + result.stderr)
        return result.stdout.decode()

    def args(self, tty: str) -> list[str]:
        return ["mcp", "serve", "--path", str(self.vault), "--agent", self.agent,
                "--pinentry", str(self.pinentry), "--pinentry-tty", tty, "--unlock-timeout", "30s"]

    def no_secret(self, data: bytes) -> None:
        for value in (self.passphrase, self.private, self.private[-32:],
                      base64.b64encode(self.private), self.private.hex().encode()):
            require(value not in data, "synthetic secret appeared in observed output")

    def verify(self, value: dict) -> None:
        require(set(value) == {"resource", "signature", "public_key", "domain", "purpose"},
                "unexpected attestation response shape")
        require(value["resource"] == RESOURCE and value["domain"] == DOMAIN and value["purpose"] == PURPOSE,
                "attestation context mismatch")
        require(base64.b64decode(value["public_key"], validate=True) == self.public, "unexpected signing key")
        message = b"TREMELAY1"
        for component in (DOMAIN.encode(), PURPOSE.encode(), RESOURCE.encode(), self.payload):
            message += struct.pack(">I", len(component)) + component
        self.key.public_key().verify(base64.b64decode(value["signature"], validate=True), message)
        self.no_secret(json.dumps(value).encode())

    def audit(self) -> dict:
        self.cli("audit", "verify")
        rows = [json.loads(line) for line in self.cli("audit", "list", "--agent", self.agent).splitlines()]
        # The final control-plane unlock may add unrelated non-attestation rows.
        attest = [row for row in rows if row.get("action") == "local_attest"]
        require([row["result"] for row in attest] == ["allowed", "completed"],
                "expected exactly one allowed/completed attestation pair")
        serialized = json.dumps(rows).encode()
        require(self.payload not in serialized and base64.b64encode(self.payload) not in serialized,
                "payload appeared in audit")
        self.no_secret(serialized)
        return {"chain_verified": True, "attestation_allowed": 1, "attestation_completed": 1,
                "payload_and_private_key_absent": True}


def success_content(value: dict) -> dict:
    require(not value.get("isError"), "MCP tool returned an error")
    content = value.get("structuredContent")
    require(isinstance(content, dict), "MCP tool omitted structured content")
    return content


def catalogue(value: dict, fixture: Fixture) -> dict:
    entries = value.get("entries")
    require(isinstance(entries, list) and len(entries) == 1, "expected one exact capability")
    entry = entries[0]
    require(set(entry) == {"handle", "operation", "resource", "key_id", "status", "expiry"},
            "unexpected capability metadata")
    fixture.no_secret(json.dumps(value).encode())
    require(entry["operation"] == "local_artifact_attest" and entry["resource"] == RESOURCE
            and entry["key_id"] == fixture.public.hex() and entry["status"] == "active",
            "capability binding mismatch")
    return entry


async def python_smoke(fixture: Fixture, read_rounds: int = 1) -> dict:
    pids = set()

    with PinentryTerminal(fixture.passphrase, fixture.pinentry) as terminal, tempfile.TemporaryFile(mode="w+") as stderr:
        params = StdioServerParameters(command=str(fixture.binary), args=fixture.args(terminal.path),
                                       env=fixture.env, cwd=str(fixture.root / "work"))
        async with asyncio.timeout(90):
            async with stdio_client(params, errlog=stderr) as (read, write):
                async with ClientSession(read, write, read_timeout_seconds=dt.timedelta(seconds=TIMEOUT)) as session:
                    initialized = await session.initialize()
                    require(initialized.protocolVersion in {"2025-06-18", "2025-11-25"},
                            "unexpected negotiated Python MCP revision")
                    pids = process_ids(fixture.binary, fixture.vault)
                    require(len(pids) == 1, "expected one Python-launched Tremelay process")
                    tools = await session.list_tools()
                    require({tool.name for tool in tools.tools} == TOOLS, "unexpected Python tool inventory")
                    for _ in range(read_rounds):
                        listed = await session.call_tool("list_capabilities", {})
                        entry = catalogue(success_content(listed.model_dump(by_alias=True)), fixture)
                        described = await session.call_tool("describe_capability", {"handle": entry["handle"]})
                        require(success_content(described.model_dump(by_alias=True)) == entry, "description mismatch")
                    invoked = await session.call_tool("invoke_capability", {
                        "handle": entry["handle"], "payload": base64.b64encode(fixture.payload).decode()})
                    fixture.verify(success_content(invoked.model_dump(by_alias=True)))
        require_exited(pids)
        stderr.seek(0)
        fixture.no_secret(stderr.read().encode())
        pinentry = terminal.verify()
    return {"client": "official Python mcp", "version": importlib.metadata.version("mcp"),
            "protocol": initialized.protocolVersion, "initialize": True, "three_tools": True,
            "sequential_read_rounds": read_rounds,
            "list_describe_invoke": True, "public_signature_verified": True,
            "server_exited_after_client_close": True, "pinentry": pinentry, "audit": fixture.audit(), "call_retries": 0}


class AppServer:
    """App-server control transport only; Codex itself owns the MCP connection."""

    def __init__(self, command: Path, fixture: Fixture):
        self.stderr = tempfile.TemporaryFile()
        self.process = subprocess.Popen([str(command), "app-server", "--stdio"], env=fixture.env,
                                        cwd=fixture.root / "work", stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=self.stderr)
        self.buffer = b""
        self.next_id = 0

    def send(self, value: dict) -> None:
        self.process.stdin.write(json.dumps(value, separators=(",", ":")).encode() + b"\n")
        self.process.stdin.flush()

    def request(self, method: str, params: dict) -> dict:
        self.next_id += 1
        request_id = self.next_id
        self.send({"id": request_id, "method": method, "params": params})
        deadline = time.monotonic() + TIMEOUT
        while time.monotonic() < deadline:
            while b"\n" in self.buffer:
                raw, self.buffer = self.buffer.split(b"\n", 1)
                value = json.loads(raw)
                if value.get("id") == request_id:
                    require("error" not in value, f"Codex app-server rejected {method}")
                    return value["result"]
                require("id" not in value, "unexpected app-server request requiring user action")
            if select.select([self.process.stdout], [], [], 0.05)[0]:
                raw = os.read(self.process.stdout.fileno(), 65536)
                require(bool(raw), "Codex app-server closed its output")
                self.buffer += raw
                require(len(self.buffer) <= 2 << 20, "app-server frame exceeded smoke capture bound")
        raise TimeoutError(f"Codex app-server timed out during {method}")

    def close(self) -> tuple[int, bytes]:
        self.process.stdin.close()
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.process.stdout.close()
        self.stderr.seek(0)
        output = self.stderr.read(1 << 20)
        self.stderr.close()
        return self.process.returncode, output


def codex_smoke(fixture: Fixture, codex: Path, read_rounds: int = 1) -> dict:
    pids = set()
    with PinentryTerminal(fixture.passphrase, fixture.pinentry) as terminal:
        # No auth, user configuration, plugin catalogue, model invocation, or listener.
        config = '\n'.join([
            '[analytics]', 'enabled = false', '[mcp_servers.tremelay_smoke]',
            'command = ' + json.dumps(str(fixture.binary)),
            'args = ' + json.dumps(fixture.args(terminal.path)),
            'startup_timeout_sec = 35', 'tool_timeout_sec = 30', '',
        ])
        (Path(fixture.env["CODEX_HOME"]) / "config.toml").write_text(config)
        app = AppServer(codex, fixture)
        try:
            initialized = app.request("initialize", {
                "clientInfo": {"name": "tremelay_stdio_smoke", "version": "1"},
                "capabilities": {"experimentalApi": True}})
            app.send({"method": "initialized", "params": {}})
            thread = app.request("thread/start", {
                "ephemeral": True, "environments": [], "cwd": str(fixture.root / "work"),
                "approvalPolicy": "never", "sandbox": "read-only"})
            thread_id = thread["thread"]["id"]
            require(thread["thread"]["ephemeral"] and not thread["thread"]["turns"], "unexpected model turn")
            status = app.request("mcpServerStatus/list", {
                "threadId": thread_id, "serverName": "tremelay_smoke", "detail": "toolsAndAuthOnly"})
            servers = status["data"]
            require(len(servers) == 1 and servers[0]["name"] == "tremelay_smoke", "unexpected MCP status inventory")
            tool_names = {tool["name"] for tool in servers[0]["tools"].values()}
            require(tool_names == TOOLS, "unexpected Codex tool inventory")
            pids = process_ids(fixture.binary, fixture.vault)
            require(len(pids) == 1, "expected one Codex-launched Tremelay process")

            def call(tool: str, arguments: dict) -> dict:
                return success_content(app.request("mcpServer/tool/call", {
                    "threadId": thread_id, "server": "tremelay_smoke", "tool": tool, "arguments": arguments}))

            for _ in range(read_rounds):
                entry = catalogue(call("list_capabilities", {}), fixture)
                require(call("describe_capability", {"handle": entry["handle"]}) == entry, "description mismatch")
            fixture.verify(call("invoke_capability", {
                "handle": entry["handle"], "payload": base64.b64encode(fixture.payload).decode()}))
        finally:
            exit_code, errors = app.close()
            fixture.no_secret(errors)
        require(exit_code == 0, "Codex did not close normally")
        require_exited(pids)
        pinentry = terminal.verify()
    return {"client": "installed Codex app-server", "version": initialized["userAgent"],
            "transport": "stdio", "ephemeral_thread": True, "model_turns": 0,
            "sequential_read_rounds": read_rounds,
            "three_tools": True, "list_describe_invoke": True, "public_signature_verified": True,
            "same_thread_connection": True, "server_exited_after_client_close": True,
            "app_server_exit": exit_code, "pinentry": pinentry, "audit": fixture.audit(), "call_retries": 0}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--pinentry", type=Path, default=shutil.which("pinentry-curses"))
    parser.add_argument("--codex", type=Path, default=shutil.which("codex"))
    parser.add_argument("--client", choices=("python", "codex", "both"), default="both")
    parser.add_argument("--sessions", type=int, default=1, help="fresh sessions per selected client (1..20)")
    parser.add_argument("--read-rounds", type=int, default=1, help="sequential list/describe rounds per session (1..20)")
    args = parser.parse_args()
    require(1 <= args.sessions <= 20 and 1 <= args.read_rounds <= 20, "smoke repetition bound exceeded")
    require(os.name == "posix" and Path("/proc").is_dir(), "this smoke observer requires Linux /proc and PTYs")
    binary = args.binary.resolve(strict=True)
    require(args.pinentry is not None, "install official pinentry-curses before running this smoke test")
    helper = args.pinentry.resolve(strict=True)
    helper_version = subprocess.run([str(helper), "--version"], capture_output=True, check=True,
                                    timeout=5, env={"PATH": "/usr/bin:/bin"}).stdout.decode().splitlines()[0]
    require("pinentry" in helper_version, "expected official pinentry helper")
    clients = ("python", "codex") if args.client == "both" else (args.client,)
    for client in clients:
        for session_number in range(1, args.sessions + 1):
            with tempfile.TemporaryDirectory(prefix="tremelay-stdio-smoke-", dir=Path.cwd()) as directory:
                fixture = Fixture(Path(directory), binary, helper)
                if client == "python":
                    result = asyncio.run(python_smoke(fixture, args.read_rounds))
                else:
                    require(args.codex is not None, "Codex is not installed")
                    result = codex_smoke(fixture, args.codex.resolve(strict=True), args.read_rounds)
                result["pinentry"]["version"] = helper_version
                result["session_number"] = session_number
                print(json.dumps(result, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
