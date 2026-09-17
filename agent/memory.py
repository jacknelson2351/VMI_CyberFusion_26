"""
ChallengeMemory — single JSON file per challenge.
Replaces the old six-file state/hypotheses/facts/artifacts/dead_ends/candidates approach.
"""
from __future__ import annotations

import json
from copy import deepcopy

from storage import read_memory_file, write_memory_file, utc_now_iso
from utils import _is_high_signal_evidence_text


_DEFAULT: dict = {
    "status": "idle",
    "phase": "idle",
    "step": 0,
    "run_id": None,
    "hypotheses": [],
    "confirmed": [],
    "ruled_out": [],
    "artifacts": [],
    "dead_ends": [],
    "flag_candidates": [],
    "phase_history": [],
    "tool_stats": {},
    "next_best_action": "",
    "checkpoint_summary": "",
    "repeated_failure_count": 0,
    "planner_summary": "",
    "updated_at": None,
}


class ChallengeMemory:
    def __init__(self, cid: str):
        self.cid = str(cid)
        self._data = self._load()

    # ── Properties ────────────────────────────────────────────────────────────

    @property
    def hypotheses(self) -> list[dict]:
        return self._data["hypotheses"]

    @hypotheses.setter
    def hypotheses(self, v: list):
        self._data["hypotheses"] = list(v or [])

    @property
    def confirmed(self) -> list:
        return self._data["confirmed"]

    @property
    def ruled_out(self) -> list:
        return self._data["ruled_out"]

    @property
    def artifacts(self) -> list:
        return self._data["artifacts"]

    @property
    def dead_ends(self) -> list:
        return self._data["dead_ends"]

    @property
    def flag_candidates(self) -> list:
        return self._data["flag_candidates"]

    @property
    def phase_history(self) -> list:
        return self._data["phase_history"]

    @property
    def tool_stats(self) -> dict:
        return self._data["tool_stats"]

    @property
    def next_best_action(self) -> str:
        return self._data.get("next_best_action") or ""

    @next_best_action.setter
    def next_best_action(self, v: str):
        self._data["next_best_action"] = v or ""

    @property
    def checkpoint_summary(self) -> str:
        return self._data.get("checkpoint_summary") or ""

    @checkpoint_summary.setter
    def checkpoint_summary(self, v: str):
        self._data["checkpoint_summary"] = v or ""

    @property
    def repeated_failure_count(self) -> int:
        return int(self._data.get("repeated_failure_count") or 0)

    @repeated_failure_count.setter
    def repeated_failure_count(self, v: int):
        self._data["repeated_failure_count"] = max(0, int(v or 0))

    @property
    def planner_summary(self) -> str:
        return self._data.get("planner_summary") or ""

    @planner_summary.setter
    def planner_summary(self, v: str):
        self._data["planner_summary"] = v or ""

    @property
    def step(self) -> int:
        return int(self._data.get("step") or 0)

    @step.setter
    def step(self, v: int):
        self._data["step"] = int(v)

    @property
    def status(self) -> str:
        return self._data.get("status") or "idle"

    @status.setter
    def status(self, v: str):
        self._data["status"] = v or "idle"

    @property
    def phase(self) -> str:
        return self._data.get("phase") or "idle"

    @phase.setter
    def phase(self, v: str):
        self._data["phase"] = v or "idle"

    # ── Mutations ─────────────────────────────────────────────────────────────

    def _trim_text_items(self, items: list, cap: int, preserve_high_signal: bool = False):
        overflow = len(items) - cap
        if overflow <= 0:
            return
        if preserve_high_signal:
            idx = 0
            while overflow > 0 and idx < len(items):
                item = items[idx]
                text = item.get("text") if isinstance(item, dict) else str(item)
                if not _is_high_signal_evidence_text(text):
                    del items[idx]
                    overflow -= 1
                else:
                    idx += 1
        if overflow > 0:
            del items[:overflow]

    def add_confirmed(self, text: str) -> bool:
        t = (text or "").strip()
        if not t:
            return False
        existing = {(i.get("text") if isinstance(i, dict) else str(i)) for i in self.confirmed}
        if t in existing:
            return False
        self.confirmed.append({"text": t, "step": self.step})
        self._trim_text_items(self.confirmed, 30, preserve_high_signal=True)
        return True

    def add_ruled_out(self, text: str) -> bool:
        t = (text or "").strip()
        if not t:
            return False
        existing = {(i.get("text") if isinstance(i, dict) else str(i)) for i in self.ruled_out}
        if t in existing:
            return False
        self.ruled_out.append({"text": t, "step": self.step})
        self._trim_text_items(self.ruled_out, 20)
        return True

    def add_artifact(self, label: str, path: str = "", note: str = "") -> bool:
        t = (label or "").strip()
        if not t:
            return False
        for item in self.artifacts:
            if isinstance(item, dict) and item.get("label") == t:
                return False
        self.artifacts.append({"label": t, "path": path or "", "note": note or "", "step": self.step})
        if len(self.artifacts) > 30:
            del self.artifacts[:len(self.artifacts) - 30]
        return True

    def add_flag_candidate(self, value: str, source: str = "") -> bool:
        v = (value or "").strip()
        if not v:
            return False
        for item in self.flag_candidates:
            if isinstance(item, dict) and item.get("value") == v:
                return False
        self.flag_candidates.append({"value": v, "source": source or "", "step": self.step})
        return True

    def record_phase(self, phase: str, reason: str = "") -> bool:
        p = (phase or "").strip().lower()
        if not p:
            return False
        last = self.phase_history[-1] if self.phase_history else {}
        if isinstance(last, dict) and last.get("phase") == p and last.get("step") == self.step:
            return False
        self.phase_history.append({"phase": p, "step": self.step, "reason": reason or ""})
        if len(self.phase_history) > 40:
            del self.phase_history[:len(self.phase_history) - 40]
        return True

    def record_tool_result(self, name: str, progress: bool, error: bool = False):
        tool = (name or "unknown").strip() or "unknown"
        stats = self.tool_stats.setdefault(tool, {
            "calls": 0,
            "progress": 0,
            "errors": 0,
            "last_step": 0,
        })
        stats["calls"] = int(stats.get("calls") or 0) + 1
        if progress:
            stats["progress"] = int(stats.get("progress") or 0) + 1
        if error:
            stats["errors"] = int(stats.get("errors") or 0) + 1
        stats["last_step"] = self.step

    def set_checkpoint(self, summary: str, next_action: str = "", repeated_failures: int = 0):
        self.checkpoint_summary = (summary or "").strip()
        self.next_best_action = (next_action or "").strip()
        self.repeated_failure_count = repeated_failures

    def get_summary_text(self) -> str:
        confirmed = [(i.get("text") if isinstance(i, dict) else str(i)) for i in self.confirmed[-8:]]
        ruled_out = [(i.get("text") if isinstance(i, dict) else str(i)) for i in self.ruled_out[-6:]]
        artifacts = [(i.get("label") or i.get("path") or str(i)) for i in self.artifacts[-5:]]
        checkpoint = self.checkpoint_summary or "none"
        next_action = self.next_best_action or "unset"
        return (
            f"Phase: {self.phase} at step {self.step}; stalled actions: {self.repeated_failure_count}\n"
            f"Confirmed: {'; '.join(confirmed) or 'none'}\n"
            f"Ruled out: {'; '.join(ruled_out) or 'none'}\n"
            f"Recent artifacts: {'; '.join(a for a in artifacts if a) or 'none'}\n"
            f"Checkpoint: {checkpoint}\n"
            f"Next best action: {next_action}"
        )

    # ── Persistence ───────────────────────────────────────────────────────────

    def _load(self) -> dict:
        raw = read_memory_file(self.cid, "memory.json")
        try:
            data = json.loads(raw)
        except Exception:
            data = {}
        if not isinstance(data, dict):
            data = {}
        merged = deepcopy(_DEFAULT)
        merged.update(data)
        for key in ("hypotheses", "confirmed", "ruled_out", "artifacts", "dead_ends", "flag_candidates", "phase_history"):
            if not isinstance(merged.get(key), list):
                merged[key] = []
        if not isinstance(merged.get("tool_stats"), dict):
            merged["tool_stats"] = {}
        return merged

    def save(self):
        self._data["updated_at"] = utc_now_iso()
        write_memory_file(self.cid, "memory.json", json.dumps(self._data, indent=2, ensure_ascii=True) + "\n")
        self._write_overview()

    def load_overview(self) -> str:
        return read_memory_file(self.cid, "overview.md")

    def _write_overview(self):
        d = self._data
        hyps = d.get("hypotheses") or []
        active = next((h for h in hyps if h.get("status") in {"active", "open"}), None)
        confirmed = [(i.get("text") if isinstance(i, dict) else str(i)) for i in (d.get("confirmed") or [])[-8:]]
        ruled_out = [(i.get("text") if isinstance(i, dict) else str(i)) for i in (d.get("ruled_out") or [])[-6:]]
        artifacts = [(i.get("label") or i.get("path") or str(i)) for i in (d.get("artifacts") or [])[-6:]]
        flags = [(i.get("value") or str(i)) for i in (d.get("flag_candidates") or [])[-4:]]
        dead_ends = [(i.get("title") or str(i)) for i in (d.get("dead_ends") or [])[-4:]]
        phase_history = d.get("phase_history") or []
        tool_stats = d.get("tool_stats") if isinstance(d.get("tool_stats"), dict) else {}
        ranked_tools = sorted(
            tool_stats.items(),
            key=lambda kv: int((kv[1] or {}).get("progress") or 0),
            reverse=True,
        )[:5]

        lines = [
            "# Agent Memory",
            f"- Status: `{d.get('status') or 'idle'}`  Phase: `{d.get('phase') or 'idle'}`  Step: `{d.get('step') or 0}`",
            f"- Repeated no-progress actions: `{d.get('repeated_failure_count') or 0}`",
            f"- Updated: `{d.get('updated_at') or ''}`",
            "",
        ]
        if d.get("checkpoint_summary") or d.get("next_best_action"):
            lines += [
                "## Current Checkpoint",
                f"- Summary: {d.get('checkpoint_summary') or 'none'}",
                f"- Next best action: {d.get('next_best_action') or 'unset'}",
                "",
            ]
        if phase_history:
            recent = phase_history[-6:]
            lines += ["## Recent Phases"] + [
                f"- step {int(p.get('step') or 0)}: `{p.get('phase') or 'unknown'}`"
                + (f" - {p.get('reason')}" if p.get("reason") else "")
                for p in recent if isinstance(p, dict)
            ] + [""]
        if ranked_tools:
            lines += ["## Tool Performance"] + [
                f"- `{name}`: {int((stat or {}).get('progress') or 0)} progress / "
                f"{int((stat or {}).get('calls') or 0)} calls"
                for name, stat in ranked_tools
            ] + [""]
        if active:
            lines += [
                "## Active Hypothesis",
                f"- **{active.get('title')}** (conf: {float(active.get('confidence') or 0):.1f})",
                f"  Goal: {active.get('goal', '')}",
                f"  Next: {active.get('next_action', '')}",
                "",
            ]
        if confirmed:
            lines += ["## Confirmed Facts"] + [f"- {t}" for t in confirmed] + [""]
        if ruled_out:
            lines += ["## Ruled Out"] + [f"- {t}" for t in ruled_out] + [""]
        if artifacts:
            lines += ["## Artifacts"] + [f"- {a}" for a in artifacts if a] + [""]
        if dead_ends:
            lines += ["## Dead Ends"] + [f"- {t}" for t in dead_ends if t] + [""]
        if flags:
            lines += ["## Flag Candidates"] + [f"- {f}" for f in flags if f] + [""]
        if d.get("planner_summary"):
            lines += ["## Planner Summary", d["planner_summary"].strip(), ""]

        write_memory_file(self.cid, "overview.md", "\n".join(lines).rstrip() + "\n")


# Backward-compat alias
ChallengeMemoryStore = ChallengeMemory
