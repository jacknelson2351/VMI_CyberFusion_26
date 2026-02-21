#!/usr/bin/env python3
"""Compute objective CTF solver capability metrics from challenges.json."""

import json
from collections import defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
DB_PATH = ROOT / "challenges.json"
CFG_PATH = ROOT / "config.json"

DEFAULTS = {
    "broad_eval_min_total_challenges": 100,
    "broad_eval_min_categories": 5,
    "broad_eval_min_challenges_per_category": 10,
    "broad_eval_min_solve_rate": 0.60,
}


def load_json(path: Path, fallback):
    if not path.exists():
        return fallback
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def main() -> int:
    challenges = load_json(DB_PATH, [])
    cfg = load_json(CFG_PATH, {})
    thresholds = {
        k: cfg.get(k, v) for k, v in DEFAULTS.items()
    }

    per_cat = defaultdict(lambda: {"total": 0, "solved": 0})
    solved_total = 0
    for ch in challenges:
        cat = (ch.get("category") or "misc").lower()
        per_cat[cat]["total"] += 1
        if ch.get("status") == "solved":
            per_cat[cat]["solved"] += 1
            solved_total += 1

    total = len(challenges)
    overall_rate = (solved_total / total) if total else 0.0
    min_total = int(thresholds["broad_eval_min_total_challenges"])
    min_cats = int(thresholds["broad_eval_min_categories"])
    min_cat_samples = int(thresholds["broad_eval_min_challenges_per_category"])
    min_rate = float(thresholds["broad_eval_min_solve_rate"])

    qualified = []
    print("CTF Solver Evaluation")
    print("=====================")
    print(f"Total challenges: {total}")
    print(f"Solved: {solved_total}")
    print(f"Overall solve rate: {overall_rate:.2%}")
    print("")
    print("By category:")
    for cat in sorted(per_cat):
        t = per_cat[cat]["total"]
        s = per_cat[cat]["solved"]
        r = (s / t) if t else 0.0
        meets = (t >= min_cat_samples and r >= min_rate)
        if meets:
            qualified.append(cat)
        marker = "PASS" if meets else "FAIL"
        print(f"- {cat:12s} total={t:3d} solved={s:3d} rate={r:6.2%}  {marker}")

    broad_ready = (total >= min_total and len(qualified) >= min_cats)
    print("")
    print("Readiness bar:")
    print(f"- min total challenges: {min_total}")
    print(f"- min categories meeting bar: {min_cats}")
    print(f"- min challenges/category: {min_cat_samples}")
    print(f"- min solve rate/category: {min_rate:.0%}")
    print(f"- categories meeting bar: {len(qualified)} ({', '.join(qualified) if qualified else 'none'})")
    print("")
    print(f"BROAD CTF READY: {'YES' if broad_ready else 'NO'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
