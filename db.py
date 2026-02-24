"""
Challenge database: load/save/query/update challenges.json.
Also houses the capability evaluation report.
"""
import json
import os
import threading
import time
from datetime import datetime

from config import DB_PATH, CATEGORIES, CONFIG_PATH, load_config
from utils import _safe_float

_db_lock = threading.RLock()


# ── Low-level read/write (must be called with _db_lock held) ─────────────────

def _load_challenges_unlocked() -> list[dict]:
    if not DB_PATH.exists():
        return []
    with open(DB_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def _save_challenges_unlocked(challenges: list[dict]):
    tmp_path = DB_PATH.with_name(DB_PATH.name + ".tmp")
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(challenges, f, indent=2)
    os.replace(tmp_path, DB_PATH)


# ── Public CRUD helpers ───────────────────────────────────────────────────────

def load_challenges() -> list[dict]:
    with _db_lock:
        return _load_challenges_unlocked()


def save_challenges(challenges: list[dict]):
    with _db_lock:
        _save_challenges_unlocked(challenges)


def get_challenge(cid: str) -> dict | None:
    with _db_lock:
        return next((c for c in _load_challenges_unlocked() if c["id"] == cid), None)


def update_challenge(cid: str, **kwargs):
    with _db_lock:
        chals = _load_challenges_unlocked()
        for c in chals:
            if c["id"] == cid:
                c.update(kwargs)
        _save_challenges_unlocked(chals)


# ── Capability evaluation report ──────────────────────────────────────────────

def build_capability_report(challenges: list[dict] | None = None, cfg: dict | None = None) -> dict:
    cfg   = cfg or load_config()
    chals = challenges if challenges is not None else load_challenges()
    per_cat = {c: {"total": 0, "solved": 0} for c in CATEGORIES}

    solved_total = 0
    for ch in chals:
        cat = (ch.get("category") or "misc").lower()
        if cat not in per_cat:
            per_cat[cat] = {"total": 0, "solved": 0}
        per_cat[cat]["total"] += 1
        if ch.get("status") == "solved":
            per_cat[cat]["solved"] += 1
            solved_total += 1

    min_total         = int(cfg.get("broad_eval_min_total_challenges") or 100)
    min_categories    = int(cfg.get("broad_eval_min_categories") or 5)
    min_per_category  = int(cfg.get("broad_eval_min_challenges_per_category") or 10)
    min_solve_rate    = _safe_float(cfg.get("broad_eval_min_solve_rate"), 0.60)

    categories_meeting_bar = []
    by_category = {}
    for cat, stats in sorted(per_cat.items()):
        total  = stats["total"]
        solved = stats["solved"]
        rate   = (solved / total) if total else 0.0
        meets  = total >= min_per_category and rate >= min_solve_rate
        if meets:
            categories_meeting_bar.append(cat)
        by_category[cat] = {
            "total":      total,
            "solved":     solved,
            "solve_rate": round(rate, 4),
            "meets_bar":  meets,
        }

    overall_rate = (solved_total / len(chals)) if chals else 0.0
    broad_ready  = len(chals) >= min_total and len(categories_meeting_bar) >= min_categories

    return {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "overall": {
            "total":      len(chals),
            "solved":     solved_total,
            "solve_rate": round(overall_rate, 4),
        },
        "thresholds": {
            "min_total_challenges":         min_total,
            "min_categories_meeting_bar":   min_categories,
            "min_challenges_per_category":  min_per_category,
            "min_solve_rate":               min_solve_rate,
        },
        "categories_meeting_bar": categories_meeting_bar,
        "by_category":            by_category,
        "broad_ctf_ready":        broad_ready,
        "readiness_note": (
            "Readiness bar met for broad CTF claims."
            if broad_ready else
            "Readiness bar not met yet; use this report as the source of truth for capability claims."
        ),
    }
