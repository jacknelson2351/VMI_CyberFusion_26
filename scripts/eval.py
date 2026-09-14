#!/usr/bin/env python3
"""
Lean eval / stress-test harness (Spec H).

Runs a subset of the active (or chosen) challenge set through the agent headlessly, with a HARD
dollar budget cap, and writes a solve-rate + cost report. No web server needed. Use it to see
whether agent changes actually help.

Examples:
  python3 scripts/eval.py --count 3 --model gpt-4.1-mini --budget 2.00
  python3 scripts/eval.py --ids 0820f92f,a53d6842 --arch single_loop --budget 5 --max-steps 20
  python3 scripts/eval.py --set umdctf --category rev --budget 3

Nothing runs until you pass --go (dry-run by default), so it never spends money by accident.
"""
import argparse
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))


# ── pure helpers (unit-tested) ────────────────────────────────────────────────
def select_challenges(all_chals, ids=None, category=None, count=None):
    """Pick challenges by explicit ids, else by category, else the first `count`."""
    if ids:
        wanted = [i.strip() for i in ids if i.strip()]
        by_id = {c["id"]: c for c in all_chals}
        return [by_id[i] for i in wanted if i in by_id]
    pool = all_chals
    if category:
        pool = [c for c in all_chals if (c.get("category") or "").lower() == category.lower()]
    if count:
        pool = pool[:count]
    return pool


def budget_exhausted(spent, budget):
    return budget is not None and spent >= budget


def summarize(results):
    total = len(results)
    # A verified flag halts to pending_approval (Spec B); with no ground-truth flags loaded we
    # count "found a confident flag" (solved OR pending_approval) as the success signal.
    found = sum(1 for r in results if r["status"] in ("solved", "pending_approval"))
    solved = sum(1 for r in results if r["status"] == "solved")
    pending = sum(1 for r in results if r["status"] == "pending_approval")
    cost = round(sum(r.get("cost_usd") or 0.0 for r in results), 4)
    return {
        "total": total,
        "found": found,
        "solved": solved,
        "pending_approval": pending,
        "found_rate": round(found / total, 4) if total else 0.0,
        "total_cost_usd": cost,
    }


def format_markdown(meta, results, totals):
    lines = [
        f"# Eval report — {meta['generated_at']}",
        "",
        f"- set: `{meta['set']}`  model: `{meta['model']}`  arch: `{meta['arch']}`  "
        f"budget: ${meta['budget']}  max_steps: {meta['max_steps']}",
        f"- **flag found {totals['found']}/{totals['total']}** "
        f"(rate {totals['found_rate']:.0%}) — of which auto-solved {totals['solved']}, "
        f"awaiting approval {totals['pending_approval']}; cost **${totals['total_cost_usd']:.4f}**",
        "- note: no ground-truth flags loaded, so this measures *confident flag reached*, not verified-correct.",
        "",
        "| challenge | category | status | flag | cost | steps | secs |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in results:
        flag = (r.get("flag") or "")[:40]
        lines.append(
            f"| {r['name']} | {r['category']} | {r['status']} | `{flag}` | "
            f"${r.get('cost_usd') or 0:.4f} | {r.get('steps') or ''} | {r.get('secs') or ''} |"
        )
    if meta.get("stopped_for_budget"):
        lines.append("")
        lines.append(f"> ⚠️ stopped early: budget ${meta['budget']} reached.")
    return "\n".join(lines) + "\n"


# ── live orchestration ────────────────────────────────────────────────────────
def run_one(cid, model, step_timeout):
    """Run one challenge to completion (or timeout) and return its result row."""
    from db import get_challenge, update_challenge
    import routes  # registers app; _spawn_agent_for + _agents live here

    chal = get_challenge(cid)
    # Isolate this run's cost/status.
    update_challenge(cid, status="unsolved", cost_usd=0.0, tokens_in=0, tokens_out=0,
                     flag=None, flag_candidate=None)
    t0 = time.time()
    ok, err, _ = routes._spawn_agent_for(cid, model)
    if not ok:
        return {"id": cid, "name": chal.get("name"), "category": chal.get("category"),
                "status": "launch_failed", "error": err, "cost_usd": 0.0}
    agent = routes._agents.get(cid)
    worker = getattr(agent, "_worker_thread", None) if agent else None
    if worker is not None:
        worker.join(timeout=step_timeout)
        if worker.is_alive():
            agent.stop()
            worker.join(timeout=30)
    secs = round(time.time() - t0, 1)
    final = get_challenge(cid) or {}
    # Clean up the challenge container + agent registry so the eval doesn't leak "running"
    # containers (they'd otherwise show up forever in the dashboard's Docker pill).
    try:
        from docker_mgr import _containers
        conn = _containers.pop(cid, None)
        if conn is not None:
            conn.stop()
        routes._agents.pop(cid, None)
    except Exception:
        pass
    return {
        "id": cid,
        "name": final.get("name"),
        "category": final.get("category"),
        "status": final.get("status") or "unsolved",
        "flag": final.get("flag") or final.get("flag_candidate") or "",
        "cost_usd": round(final.get("cost_usd") or 0.0, 4),
        "steps": (agent.step if agent else None),
        "secs": secs,
    }


def main():
    ap = argparse.ArgumentParser(description="CTF Copilot eval / stress-test harness")
    ap.add_argument("--set", help="challenge set id (default: active)")
    ap.add_argument("--ids", help="comma-separated challenge ids")
    ap.add_argument("--category", help="filter by category")
    ap.add_argument("--count", type=int, help="run the first N of the (filtered) set")
    ap.add_argument("--model", default="gpt-4.1-mini", help="solver model (default gpt-4.1-mini)")
    ap.add_argument("--arch", choices=["single_loop", "planner_executor"], default="single_loop")
    ap.add_argument("--budget", type=float, default=5.0, help="hard USD cap (default 5.0)")
    ap.add_argument("--max-steps", type=int, default=20, help="per-challenge step cap (default 20)")
    ap.add_argument("--timeout", type=int, default=1200, help="per-challenge wall-clock secs")
    ap.add_argument("--out", default=None, help="report path (default runs/eval-<ts>.md)")
    ap.add_argument("--go", action="store_true", help="actually run (spends money). Omit for dry-run.")
    args = ap.parse_args()

    # Env overrides picked up by config.load_config at agent construction.
    os.environ["CTF_AGENT_ARCH"] = args.arch
    os.environ["CTF_MAX_STEPS"] = str(args.max_steps)

    from db import list_challenge_sets, activate_challenge_set, load_challenges
    if args.set:
        if not activate_challenge_set(args.set):
            print(f"error: set '{args.set}' not found. Available: "
                  f"{[s['id'] for s in list_challenge_sets()]}")
            return 2

    all_chals = load_challenges()
    ids = args.ids.split(",") if args.ids else None
    chosen = select_challenges(all_chals, ids=ids, category=args.category, count=args.count)
    if not chosen:
        print("No challenges matched the selection.")
        return 1

    active_set = next((s["id"] for s in list_challenge_sets() if s["active"]), "?")
    print(f"Selected {len(chosen)} challenge(s) from set '{active_set}': "
          f"{', '.join(c['name'] for c in chosen)}")
    print(f"model={args.model} arch={args.arch} budget=${args.budget} "
          f"max_steps={args.max_steps} timeout={args.timeout}s")
    if not args.go:
        print("\nDRY RUN — pass --go to actually run (this will spend money on API calls).")
        return 0

    results = []
    spent = 0.0
    stopped_for_budget = False
    for c in chosen:
        if budget_exhausted(spent, args.budget):
            stopped_for_budget = True
            print(f"Budget ${args.budget} reached — stopping before '{c['name']}'.")
            break
        print(f"\n▶ running '{c['name']}' ({c['category']}) … spent so far ${spent:.4f}")
        row = run_one(c["id"], args.model, args.timeout)
        spent = round(spent + (row.get("cost_usd") or 0.0), 4)
        results.append(row)
        print(f"   → {row['status']}  cost ${row.get('cost_usd') or 0:.4f}  "
              f"flag={row.get('flag') or '—'}")

    totals = summarize(results)
    meta = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "set": active_set, "model": args.model, "arch": args.arch,
        "budget": args.budget, "max_steps": args.max_steps,
        "stopped_for_budget": stopped_for_budget,
    }
    md = format_markdown(meta, results, totals)
    out = Path(args.out) if args.out else (BASE / "runs" / f"eval-{int(time.time())}.md")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(md)
    out.with_suffix(".json").write_text(json.dumps(
        {"meta": meta, "totals": totals, "results": results}, indent=2))
    print("\n" + md)
    print(f"Report: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
