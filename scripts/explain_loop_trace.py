#!/usr/bin/env python3
"""
Summarize CTFAgent loop trace events into a readable timeline.

Usage:
  python scripts/explain_loop_trace.py --file logs.json
  python scripts/explain_loop_trace.py --cid 1234abcd --base-url http://127.0.0.1:7331
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from urllib.request import urlopen


def load_logs_from_file(path: str) -> list[dict]:
    with open(path, "r", encoding="utf-8") as f:
        payload = json.load(f)
    if isinstance(payload, list):
        return payload
    raise ValueError("Expected a JSON array of log entries.")


def load_logs_from_api(base_url: str, cid: str) -> list[dict]:
    url = f"{base_url.rstrip('/')}/api/challenges/{cid}/logs"
    with urlopen(url, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


def fmt_ts(ts: float | None) -> str:
    if not ts:
        return "--:--:--"
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S")


def explain(logs: list[dict]) -> list[str]:
    out = []
    for entry in logs:
        ev = entry.get("event")
        data = entry.get("data") or {}
        ts = fmt_ts(entry.get("ts"))
        if ev != "loop_trace":
            continue
        step = data.get("step", 0)
        phase = data.get("phase", "")
        note = ""

        if phase == "step_start":
            note = (
                f"start (evidence_v={data.get('evidence_version')}, "
                f"no_progress={data.get('no_progress_steps')}, "
                f"errors={data.get('consecutive_errors')})"
            )
        elif phase == "step_model_response":
            note = f"model response (tools={data.get('tool_call_count')}, content={data.get('has_content')})"
        elif phase == "tool_dispatch_start":
            note = f"dispatch -> {data.get('tool')}"
        elif phase == "tool_dispatch_end":
            note = (
                f"tool done ({data.get('tool')}, progress={data.get('progress')}, "
                f"error={data.get('error')})"
            )
        elif phase == "run_command_blocked":
            note = f"run_command blocked ({data.get('reason')}, family={data.get('family')})"
        elif phase == "run_command_exit":
            note = (
                f"run_command exit (family={data.get('family')}, progress={data.get('progress')}, "
                f"hyp_np={data.get('hypothesis_no_progress')}, fam_np={data.get('family_no_progress')})"
            )
        elif phase == "step_forced_shift":
            note = (
                f"forced strategy shift (no_progress={data.get('no_progress_steps')}, "
                f"errors={data.get('consecutive_errors')})"
            )
        else:
            details = {k: v for k, v in data.items() if k not in {"cid", "step", "phase"}}
            note = json.dumps(details, ensure_ascii=True) if details else ""

        out.append(f"[{ts}] step={step:02d} {phase}: {note}".rstrip())
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", help="Path to a saved logs JSON array.")
    ap.add_argument("--cid", help="Challenge id to fetch from running server.")
    ap.add_argument("--base-url", default="http://127.0.0.1:7331", help="Server base URL.")
    args = ap.parse_args()

    if not args.file and not args.cid:
        print("Provide --file or --cid.", file=sys.stderr)
        return 2

    try:
        logs = load_logs_from_file(args.file) if args.file else load_logs_from_api(args.base_url, args.cid)
        lines = explain(logs)
        if not lines:
            print("No loop_trace events found.")
            return 0
        print("\n".join(lines))
        return 0
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

