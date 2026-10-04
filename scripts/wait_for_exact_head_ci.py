#!/usr/bin/env python3
"""Wait for exact-head Linux and Windows GitHub Actions test workflows."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from typing import Any

REQUIRED_WORKFLOWS = ("Test Linux", "Test Windows")


def classify_runs(payload: dict[str, Any]) -> tuple[str, str]:
    runs = payload.get("workflow_runs")
    if not isinstance(runs, list):
        return "waiting", "no workflow runs yet"

    matched = [
        run
        for run in runs
        if isinstance(run, dict) and run.get("name") in REQUIRED_WORKFLOWS
    ]
    names = {run.get("name") for run in matched}
    missing = [name for name in REQUIRED_WORKFLOWS if name not in names]
    if missing:
        return "waiting", "missing " + ", ".join(missing)

    pending = [
        run for run in matched if str(run.get("status") or "").casefold() != "completed"
    ]
    if pending:
        return "waiting", "test workflows still running"

    failed = [
        run
        for run in matched
        if str(run.get("conclusion") or "").casefold() != "success"
    ]
    if failed:
        detail = ", ".join(
            f"{run.get('name')}={run.get('conclusion')}" for run in failed
        )
        return "failure", detail

    return "success", "Linux and Windows exact-head CI passed"


def fetch_runs(repo: str, sha: str) -> dict[str, Any]:
    completed = subprocess.run(
        [
            "gh",
            "api",
            "-X",
            "GET",
            f"repos/{repo}/actions/runs",
            "-f",
            f"head_sha={sha}",
            "-f",
            "per_page=100",
        ],
        check=False,
        capture_output=True,
        text=True,
        env=os.environ,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()
        raise RuntimeError(detail or "could not read GitHub Actions runs")
    return json.loads(completed.stdout)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--max-polls", type=int, default=120)
    parser.add_argument("--poll-seconds", type=int, default=15)
    args = parser.parse_args(argv)

    for _ in range(args.max_polls):
        state, detail = classify_runs(fetch_runs(args.repo, args.sha))
        print(f"{state}: {detail}", flush=True)
        if state == "success":
            return 0
        if state == "failure":
            return 1
        time.sleep(args.poll_seconds)

    print("timeout: exact-head CI did not finish within the poll budget", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
