"""
Small, deterministic agent strategy helpers.

These keep the control-loop policy testable and separate from provider/tool
adapters. The phase model is inspired by AIRecon's staged workflow, but mapped
to CTF solve runs.
"""
from __future__ import annotations

from copy import deepcopy


PHASE_SEQUENCE = ("recon", "analyze", "exploit", "verify", "report")
PHASE_LABELS = {
    "idle": "Idle",
    "recon": "Recon",
    "analyze": "Analysis",
    "exploit": "Exploit",
    "verify": "Verify",
    "report": "Report",
    "stop": "Stopped",
    "done": "Done",
}

PHASE_TOOL_PRIORITIES = {
    "recon": ["list_files", "run_command", "http_request", "extract_artifact", "run_gdb", "search_flag"],
    "analyze": ["run_command", "list_files", "run_gdb", "http_request", "extract_artifact", "search_flag"],
    "exploit": ["write_file", "run_command", "http_request", "run_gdb", "search_flag", "save_note"],
    "verify": ["search_flag", "run_command", "http_request", "submit_flag", "save_note"],
    "report": ["save_note", "search_flag", "run_command"],
}

CATEGORY_TOOL_BONUS = {
    "web": {"http_request": 5, "run_command": 2, "write_file": 1},
    "pwn": {"run_gdb": 5, "write_file": 3, "run_command": 2},
    "rev": {"run_gdb": 4, "run_command": 3, "write_file": 1},
    "forensics": {"extract_artifact": 5, "search_flag": 3, "run_command": 2, "list_files": 2},
    "crypto": {"write_file": 4, "run_command": 3, "list_files": 2},
    "network": {"run_command": 3, "extract_artifact": 2, "search_flag": 2},
    "osint": {"run_command": 3, "save_note": 2},
}


def normalize_phase(value: str | None, default: str = "recon") -> str:
    phase = (value or "").strip().lower()
    if phase in PHASE_LABELS:
        return phase
    return default


def choose_phase(
    *,
    step: int,
    current_phase: str,
    has_flag_candidate: bool = False,
    no_progress_streak: int = 0,
    finished: bool = False,
) -> str:
    if finished:
        return "report"
    if has_flag_candidate:
        return "verify"
    if step <= 1:
        return "recon"
    if step <= 4:
        return "analyze"
    if no_progress_streak >= 3:
        return "analyze"
    cur = normalize_phase(current_phase)
    if cur in {"idle", "recon", "analyze"}:
        return "exploit"
    return cur


def checkpoint_due(step: int, last_step: int, interval: int) -> bool:
    if step <= 0:
        return False
    interval = max(1, int(interval or 1))
    return step - int(last_step or 0) >= interval


def cadence_due(step: int, interval: int) -> bool:
    if step <= 0:
        return False
    interval = max(1, int(interval or 1))
    return step % interval == 0


def rank_tool_names(category: str, phase: str, tool_stats: dict | None, tool_names: list[str]) -> list[str]:
    stats = tool_stats if isinstance(tool_stats, dict) else {}
    category_bonus = CATEGORY_TOOL_BONUS.get((category or "").strip().lower(), {})
    phase_order = PHASE_TOOL_PRIORITIES.get(normalize_phase(phase), PHASE_TOOL_PRIORITIES["exploit"])
    phase_bonus = {name: len(phase_order) - idx for idx, name in enumerate(phase_order)}

    def score(name: str) -> tuple[float, str]:
        item = stats.get(name) if isinstance(stats.get(name), dict) else {}
        calls = int(item.get("calls") or 0)
        progress = int(item.get("progress") or 0)
        errors = int(item.get("errors") or 0)
        no_progress = max(0, calls - progress - errors)
        value = float(phase_bonus.get(name, 0) + category_bonus.get(name, 0))
        value += min(progress, 5) * 1.25
        value -= min(errors, 5) * 1.5
        value -= min(no_progress, 6) * 0.75
        return (value, name)

    return sorted(list(tool_names or []), key=score, reverse=True)


def reorder_tool_definitions(category: str, phase: str, tool_stats: dict | None, tools: list[dict]) -> list[dict]:
    copied = deepcopy(list(tools or []))

    def tool_name(tool: dict) -> str:
        if "function" in tool and isinstance(tool["function"], dict):
            return tool["function"].get("name") or ""
        return tool.get("name") or ""

    ordered_names = rank_tool_names(category, phase, tool_stats, [tool_name(t) for t in copied])
    order = {name: idx for idx, name in enumerate(ordered_names)}
    copied.sort(key=lambda t: order.get(tool_name(t), len(order)))
    return copied
