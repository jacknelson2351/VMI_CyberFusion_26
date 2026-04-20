"""
Readable persisted memory for the single-agent harness.
"""
from __future__ import annotations

import json
from copy import deepcopy

from storage import (
    ensure_memory_files,
    read_memory_file,
    write_memory_file,
    utc_now_iso,
)


DEFAULT_STATE = {
    "status": "idle",
    "phase": "idle",
    "step": 0,
    "run_id": None,
    "active_hypothesis_id": None,
    "planner_summary": "",
    "verifier_summary": "",
    "last_tool_summary": "",
    "last_updated_at": None,
}

DEFAULT_FACTS = {
    "confirmed": [],
    "ruled_out": [],
    "flag_candidates": [],
    "updated_at": None,
}

DEFAULT_CANDIDATES = {
    "flags": [],
    "other": [],
    "updated_at": None,
}


class ChallengeMemoryStore:
    def __init__(self, cid: str):
        self.cid = str(cid)
        ensure_memory_files(self.cid)

    def _load_json(self, name: str, default):
        raw = read_memory_file(self.cid, name)
        try:
            value = json.loads(raw)
        except Exception:
            return deepcopy(default)
        if isinstance(default, dict) and isinstance(value, dict):
            merged = deepcopy(default)
            merged.update(value)
            return merged
        if isinstance(default, list) and isinstance(value, list):
            return value
        return deepcopy(default)

    def _save_json(self, name: str, payload):
        write_memory_file(self.cid, name, json.dumps(payload, indent=2, ensure_ascii=True) + "\n")

    def load_state(self) -> dict:
        return self._load_json("state.json", DEFAULT_STATE)

    def save_state(self, payload: dict):
        merged = deepcopy(DEFAULT_STATE)
        merged.update(payload or {})
        merged["last_updated_at"] = utc_now_iso()
        self._save_json("state.json", merged)

    def load_hypotheses(self) -> list[dict]:
        items = self._load_json("hypotheses.json", [])
        return items if isinstance(items, list) else []

    def save_hypotheses(self, items: list[dict]):
        self._save_json("hypotheses.json", items or [])

    def load_facts(self) -> dict:
        return self._load_json("facts.json", DEFAULT_FACTS)

    def save_facts(self, payload: dict):
        merged = deepcopy(DEFAULT_FACTS)
        merged.update(payload or {})
        merged["updated_at"] = utc_now_iso()
        self._save_json("facts.json", merged)

    def load_artifacts(self) -> list[dict]:
        items = self._load_json("artifacts.json", [])
        return items if isinstance(items, list) else []

    def save_artifacts(self, items: list[dict]):
        self._save_json("artifacts.json", items or [])

    def load_dead_ends(self) -> list[dict]:
        items = self._load_json("dead_ends.json", [])
        return items if isinstance(items, list) else []

    def save_dead_ends(self, items: list[dict]):
        self._save_json("dead_ends.json", items or [])

    def load_candidates(self) -> dict:
        return self._load_json("candidates.json", DEFAULT_CANDIDATES)

    def save_candidates(self, payload: dict):
        merged = deepcopy(DEFAULT_CANDIDATES)
        merged.update(payload or {})
        merged["updated_at"] = utc_now_iso()
        self._save_json("candidates.json", merged)

    def load_all(self) -> dict:
        return {
            "state": self.load_state(),
            "hypotheses": self.load_hypotheses(),
            "facts": self.load_facts(),
            "artifacts": self.load_artifacts(),
            "dead_ends": self.load_dead_ends(),
            "candidates": self.load_candidates(),
            "overview": read_memory_file(self.cid, "overview.md"),
        }

    def save_overview(
        self,
        challenge_name: str,
        category: str,
        state: dict,
        hypotheses: list[dict],
        facts: dict,
        artifacts: list[dict],
        dead_ends: list[dict],
        candidates: dict,
    ):
        active_id = (state or {}).get("active_hypothesis_id")
        active = next((h for h in (hypotheses or []) if h.get("id") == active_id), None)
        confirmed = (facts or {}).get("confirmed") or []
        ruled_out = (facts or {}).get("ruled_out") or []
        flags = (candidates or {}).get("flags") or []

        lines = [
            "# Agent Overview",
            "",
            f"- Challenge: `{challenge_name or 'Untitled'}`",
            f"- Category: `{(category or 'misc').upper()}`",
            f"- Status: `{(state or {}).get('status') or 'idle'}`",
            f"- Phase: `{(state or {}).get('phase') or 'idle'}`",
            f"- Step: `{int((state or {}).get('step') or 0)}`",
            f"- Updated: `{(state or {}).get('last_updated_at') or utc_now_iso()}`",
            "",
            "## Active Hypothesis",
            "",
        ]
        if active:
            lines.extend([
                f"- ID: `{active.get('id')}`",
                f"- Title: {active.get('title') or 'Untitled'}",
                f"- Goal: {active.get('goal') or 'No goal recorded.'}",
                f"- Next Action: {active.get('next_action') or 'None'}",
                f"- Expected Signal: {', '.join(active.get('expected_signals') or []) or 'None'}",
                f"- Attempts: `{int(active.get('attempts') or 0)}`",
                f"- Status: `{active.get('status') or 'open'}`",
            ])
        else:
            lines.append("- None selected.")

        lines.extend(["", "## Verified Facts", ""])
        if confirmed:
            for item in confirmed[-8:]:
                if isinstance(item, dict):
                    lines.append(f"- {item.get('text') or ''}")
                else:
                    lines.append(f"- {item}")
        else:
            lines.append("- None yet.")

        lines.extend(["", "## Ruled Out", ""])
        if ruled_out:
            for item in ruled_out[-6:]:
                if isinstance(item, dict):
                    lines.append(f"- {item.get('text') or ''}")
                else:
                    lines.append(f"- {item}")
        else:
            lines.append("- None yet.")

        lines.extend(["", "## Recent Artifacts", ""])
        if artifacts:
            for item in artifacts[-6:]:
                lines.append(f"- {item.get('label') or item.get('path') or item.get('text') or 'artifact'}")
        else:
            lines.append("- None yet.")

        lines.extend(["", "## Dead Ends", ""])
        if dead_ends:
            for item in dead_ends[-6:]:
                lines.append(f"- {item.get('title') or item.get('text') or 'dead end'}")
        else:
            lines.append("- None yet.")

        lines.extend(["", "## Candidate Flags", ""])
        if flags:
            for item in flags[-6:]:
                lines.append(f"- {item.get('value') or ''} ({item.get('status') or 'candidate'})")
        else:
            lines.append("- None yet.")

        planner_summary = (state or {}).get("planner_summary") or ""
        verifier_summary = (state or {}).get("verifier_summary") or ""
        if planner_summary:
            lines.extend(["", "## Planner Summary", "", planner_summary.strip()])
        if verifier_summary:
            lines.extend(["", "## Verifier Summary", "", verifier_summary.strip()])

        write_memory_file(self.cid, "overview.md", "\n".join(lines).rstrip() + "\n")
