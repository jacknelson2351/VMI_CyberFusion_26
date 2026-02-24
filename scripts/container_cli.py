#!/usr/bin/env python3
"""
Attach to a challenge container for manual intervention and/or watch agent activity.

Examples:
  python scripts/container_cli.py 1234abcd --shell
  python scripts/container_cli.py 1234abcd --watch
  python scripts/container_cli.py 1234abcd --both
"""

from __future__ import annotations

import argparse
import json
import subprocess
import threading
import time
from urllib.error import URLError
from urllib.request import Request, urlopen


CONTAINER_PREFIX = "ctf-agent-"


def _run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=check)


def _capture(cmd: list[str]) -> str:
    p = subprocess.run(cmd, check=True, capture_output=True, text=True)
    return p.stdout.strip()


def _container_exists(name: str) -> bool:
    try:
        names = _capture(["docker", "ps", "-a", "--format", "{{.Names}}"]).splitlines()
        return name in {n.strip() for n in names}
    except Exception:
        return False


def _watch(name: str):
    _run([
        "docker", "exec", "-i", name, "bash", "-lc",
        "touch /ctf/.agent_live.log && tail -n 120 -f /ctf/.agent_live.log",
    ])


def _shell(name: str):
    _run(["docker", "exec", "-it", name, "bash"])


def _start_via_api(base_url: str, cid: str) -> bool:
    url = f"{base_url.rstrip('/')}/api/challenges/{cid}/manual-start"
    req = Request(url, method="POST", headers={"Content-Type": "application/json"}, data=b"{}")
    try:
        with urlopen(req, timeout=10) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
            if payload.get("error"):
                print(f"manual-start failed: {payload['error']}")
                return False
            print("Manual container started via API.")
            return True
    except URLError as e:
        print(f"manual-start request failed: {e}")
        return False


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("cid", help="Challenge id")
    ap.add_argument("--shell", action="store_true", help="Open interactive shell in container")
    ap.add_argument("--watch", action="store_true", help="Watch live agent command/output log")
    ap.add_argument("--both", action="store_true", help="Open shell and watch in parallel")
    ap.add_argument("--start", action="store_true", help="Start challenge container via API if missing")
    ap.add_argument("--base-url", default="http://127.0.0.1:7331", help="Server base URL for --start")
    args = ap.parse_args()

    if not (args.shell or args.watch or args.both):
        args.both = True

    name = f"{CONTAINER_PREFIX}{args.cid}"
    if not _container_exists(name):
        if args.start:
            if not _start_via_api(args.base_url, args.cid):
                return 1
            time.sleep(0.6)
        if not _container_exists(name):
            print(f"Container not found: {name}")
            print("Use --start (with backend running) or launch the challenge first.")
            return 1

    if args.both:
        t = threading.Thread(target=_watch, args=(name,), daemon=True)
        t.start()
        time.sleep(0.6)
        _shell(name)
        return 0

    if args.watch:
        _watch(name)
        return 0

    if args.shell:
        _shell(name)
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
