"""
Challenge database: load/save/query/update challenges.json.
Also houses the capability evaluation report.
"""
import json
import os
import re
import threading
from datetime import datetime

from config import (
    DB_PATH, CATEGORIES, CONFIG_PATH, load_config,
    CHALLENGE_SETS_DIR, SETS_INDEX_PATH, current_db_path,
)
from storage import apply_challenge_defaults, utc_now_iso, write_workspace_manifest
from utils import _safe_float

_db_lock = threading.RLock()


# ── Low-level read/write (must be called with _db_lock held) ─────────────────

def _load_challenges_unlocked() -> list[dict]:
    ensure_sets_seeded()
    path = current_db_path()
    if not path.exists():
        return []
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    return [apply_challenge_defaults(item) for item in raw]


def _save_challenges_unlocked(challenges: list[dict]):
    path = current_db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(path.name + ".tmp")
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(challenges, f, indent=2)
    os.replace(tmp_path, path)


# ── Challenge sets (competitions) ─────────────────────────────────────────────

def _slugify(name: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", (name or "").strip().lower()).strip("-")
    return s or "set"


def _read_index_unlocked() -> dict:
    if SETS_INDEX_PATH.exists():
        try:
            with open(SETS_INDEX_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                data.setdefault("sets", {})
                return data
        except Exception:
            pass
    return {"active": "", "sets": {}}


def _write_index_unlocked(idx: dict):
    CHALLENGE_SETS_DIR.mkdir(parents=True, exist_ok=True)
    tmp = SETS_INDEX_PATH.with_name(SETS_INDEX_PATH.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(idx, f, indent=2)
    os.replace(tmp, SETS_INDEX_PATH)


def ensure_sets_seeded():
    """Idempotently migrate the legacy challenges.json into a first named set."""
    with _db_lock:
        idx = _read_index_unlocked()
        if idx.get("sets"):
            return
        CHALLENGE_SETS_DIR.mkdir(parents=True, exist_ok=True)
        sid = "umdctf"
        seed_path = CHALLENGE_SETS_DIR / f"{sid}.json"
        if DB_PATH.exists() and not seed_path.exists():
            with open(DB_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            with open(seed_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        elif not seed_path.exists():
            with open(seed_path, "w", encoding="utf-8") as f:
                json.dump([], f)
        idx = {"active": sid, "sets": {sid: {
            "name": "UMD CTF", "competition": "UMDCTF", "created_at": utc_now_iso()}}}
        _write_index_unlocked(idx)


def list_challenge_sets() -> list[dict]:
    with _db_lock:
        ensure_sets_seeded()
        idx = _read_index_unlocked()
        active = idx.get("active") or ""
        out = []
        for sid, meta in idx.get("sets", {}).items():
            path = CHALLENGE_SETS_DIR / f"{sid}.json"
            count = solved = 0
            try:
                with open(path, "r", encoding="utf-8") as f:
                    chals = json.load(f)
                count = len(chals)
                solved = sum(1 for c in chals if c.get("status") == "solved")
            except Exception:
                pass
            out.append({
                "id": sid,
                "name": meta.get("name") or sid,
                "competition": meta.get("competition") or "",
                "count": count,
                "solved": solved,
                "active": sid == active,
            })
        return sorted(out, key=lambda s: (not s["active"], s["name"].lower()))


def activate_challenge_set(sid: str) -> bool:
    with _db_lock:
        ensure_sets_seeded()
        idx = _read_index_unlocked()
        if sid not in idx.get("sets", {}):
            return False
        idx["active"] = sid
        _write_index_unlocked(idx)
        return True


def create_challenge_set(name: str, competition: str = "", challenges: list | None = None) -> str:
    with _db_lock:
        ensure_sets_seeded()
        idx = _read_index_unlocked()
        base = _slugify(name)
        sid = base
        n = 2
        while sid in idx.get("sets", {}) or (CHALLENGE_SETS_DIR / f"{sid}.json").exists():
            sid = f"{base}-{n}"
            n += 1
        normalized = [apply_challenge_defaults(c) for c in (challenges or [])]
        with open(CHALLENGE_SETS_DIR / f"{sid}.json", "w", encoding="utf-8") as f:
            json.dump(normalized, f, indent=2)
        idx.setdefault("sets", {})[sid] = {
            "name": name or sid, "competition": competition or "", "created_at": utc_now_iso()}
        _write_index_unlocked(idx)
        return sid


def rename_challenge_set(sid: str, name: str | None = None, competition: str | None = None) -> bool:
    with _db_lock:
        idx = _read_index_unlocked()
        meta = idx.get("sets", {}).get(sid)
        if not meta:
            return False
        if name is not None:
            meta["name"] = name
        if competition is not None:
            meta["competition"] = competition
        _write_index_unlocked(idx)
        return True


def delete_challenge_set(sid: str) -> tuple[bool, str]:
    with _db_lock:
        idx = _read_index_unlocked()
        sets = idx.get("sets", {})
        if sid not in sets:
            return False, "not found"
        if len(sets) <= 1:
            return False, "cannot delete the only remaining set"
        was_active = idx.get("active") == sid
        sets.pop(sid, None)
        if was_active:
            idx["active"] = next(iter(sets.keys()))
        _write_index_unlocked(idx)
        try:
            (CHALLENGE_SETS_DIR / f"{sid}.json").unlink(missing_ok=True)
        except Exception:
            pass
        return True, idx["active"]


# ── Public CRUD helpers ───────────────────────────────────────────────────────

def load_challenges() -> list[dict]:
    with _db_lock:
        return _load_challenges_unlocked()


def save_challenges(challenges: list[dict]):
    with _db_lock:
        normalized = [apply_challenge_defaults(item) for item in challenges]
        _save_challenges_unlocked(normalized)
        for chal in normalized:
            if chal.get("id"):
                write_workspace_manifest(chal)


def get_challenge(cid: str) -> dict | None:
    with _db_lock:
        return next((c for c in _load_challenges_unlocked() if c["id"] == cid), None)


def update_challenge(cid: str, **kwargs):
    with _db_lock:
        chals = _load_challenges_unlocked()
        for c in chals:
            if c["id"] == cid:
                c.update(kwargs)
                c["last_activity_at"] = utc_now_iso()
                normalized = apply_challenge_defaults(c)
                c.clear()
                c.update(normalized)
                write_workspace_manifest(c)
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
