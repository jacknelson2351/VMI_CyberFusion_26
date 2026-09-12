# Spec B — Loop control & flag handling rebuild

**Date:** 2026-09-12
**Branch:** `feature/ctf-framework-overhaul`
**Status:** Design, ready for implementation
**Part of:** CTF Copilot overhaul (round 2). Depends on A (shipped). Siblings: C/D/E/F/G/H.

## Problem (from the deep dive + forensic memo)

The agent sabotages its own runs:

1. **Auto-stop on the first candidate.** `_finalize_flag_candidate` sets `self.running = False`
   the instant *any* flag-shaped token appears — including a regex scrape of untrusted tool
   output ([core.py] `_maybe_auto_submit_from_output`). The LangGraph loop then hard-ends
   (`run_tools` breaks + `after_tools` returns END when status is `pending_approval`). One
   planted **decoy** ends the whole solve. (dualflow false-positive; Pixel Vault decoy.)
2. **Wrong flag = dead run.** Rejecting a candidate reverts status to `unsolved` and emits
   `done`, but nothing resumes the agent — `running` is already False and the graph returned.
3. **Pause-for-a-human-who-isn't-there.** Runs stop and wait for approval mid-batch; in an
   unattended batch that means the run is simply over (rainbet was cut ~a dozen steps from the
   flag). ~14/30 challenges never effectively ran.
4. **Broken anti-loop.** `no_progress_streak` observed stuck at 0 in real runs, so the
   "pivot after 3 no-progress steps" never fired; roulette burned 381 events repeating itself.
5. **Hardcoded flag heuristics** (`flags.py`, ~230 lines): command allow/deny lists, npf/GUID
   special-cases, prefix lists — brittle, and wired so a scrape auto-submits *and stops*.

## Goal

The agent keeps working until it has a **verified** flag or exhausts its step budget. Finding a
flag-shaped string is a *signal*, never an automatic stop. Wrong/decoy candidates are recorded
and the agent moves on. A rejection resumes solving. Anti-loop actually fires. Flag acceptance
is evidence/format-driven and configurable, not a pile of special-cases.

## Design

### 1. Candidate ledger (replaces stop-on-first)

Add a per-run **candidate ledger** on the agent: `self._candidates: list[Candidate]` where each
is `{flag, source, how, confidence, status: proposed|submitted|rejected|verified, step}`.

- `_finalize_flag_candidate(flag, how, source, confidence)` now: dedupes against the ledger,
  records the candidate, emits a `flag` event — and **decides whether to stop** via
  `_should_halt_for(candidate)` instead of always halting.
- `_should_halt_for` returns True only for a **verified/high-confidence** flag:
  - matches an explicit `flag_format` for the challenge, OR
  - was produced by a deterministic solve step (exploit output, not a raw file/HTTP scrape) AND
    corroborated, OR
  - `confidence == "verified"` (the model called `submit_flag` with a stated derivation).
  Decoy-shaped tokens (`test`, `fake`, `placeholder`, `example`) never halt and are marked
  `rejected` in the ledger with a reason.
- When not halting, the tool result fed back to the model says: *"Recorded candidate X (low
  confidence / possible decoy). Keep solving and verify or find the real flag."*

### 2. Stop policy is config-driven

New config (in `DEFAULT_CONFIG`, editable in Settings → Agent later):
- `flag_stop_policy`: `"verified_only"` (default) | `"first_candidate"` (legacy) | `"never"`.
- `require_flag_approval`: bool (default True) — when a run *does* halt on a verified flag, it
  goes to `pending_approval`; when False it auto-marks solved.
`verified_only` is the fix: the loop only stops when `_should_halt_for` is satisfied.

### 3. Graph keeps going past a candidate

`agent/graph.py`:
- `run_tools` no longer sets `submitted=True` merely because status is `pending_approval`. It
  breaks the tool loop only when the agent actually halted (`not agent.running`).
- `after_tools` returns END only on real termination (`not agent.running` or step budget),
  never just because a candidate exists.
- The `submit_flag` tool: if the policy is `verified_only` and the submission is high-confidence,
  it halts (as today). Otherwise it records the candidate and the loop continues.

### 4. Resume-after-reject (unattended-safe)

`routes.py` approve/reject:
- On **reject**, mark the ledger entry `rejected`, append a user-role message
  ("Candidate `X` was rejected — it is wrong, do not resubmit it; keep solving."), and
  **resume the agent** (`resume_from_current_state()` in a thread) instead of only emitting
  `done`. The run continues from where it was.
- On **approve**, unchanged (mark solved, generate writeup, stop).
- If a run halted for approval but no human is present, an optional `auto_continue_after`
  seconds (config, default off) can auto-resume as if rejected — but v1 keeps this manual;
  the real unattended fix is `flag_stop_policy="verified_only"` so weak candidates never halt.

### 5. Anti-loop actually fires

- Fix `no_progress_streak`: `_score_progress`/`_record_tool_result` must increment the streak on
  genuinely non-advancing results (same output hash, repeated command, empty/error). Verify with
  a test that N no-progress tool results raise the streak to N and flip the phase to a pivot.
- Keep the existing repeated-command block; add: after `>=3` no-progress, the next system nudge
  explicitly forces a *different primitive* (already partly present in `_next_best_action_text`).

### 6. De-hardcode flag logic

- Keep `flags.py`'s decode/extract helpers (base64/hex chains are genuinely useful) but:
  - Remove the special-case allow/deny command lists driving auto-submit; replace with a single
    `confidence` score (format match + corroboration + deterministic-source) surfaced to the
    stop policy.
  - The npf/GUID artifact filter stays as a *decoy* filter (marks rejected), not a submit gate.
  - No prefix hardcoding beyond: "matches challenge `flag_format` if given, else looks like
    `WORD{...}`" — everything else is confidence, not a hard gate.

## Testing

- **Unit (no network):**
  - decoy token (`FLAG{test_flag}`) → recorded `rejected`, `_should_halt_for` False, run continues.
  - real-looking corroborated token with matching `flag_format` → `_should_halt_for` True.
  - `flag_stop_policy="first_candidate"` reproduces legacy halt (back-compat).
  - N no-progress tool results → `no_progress_streak == N` and phase pivots at 3.
  - reject flow appends the "keep solving" message and re-arms `running`.
- **Graph:** a candidate mid-run does not END the graph under `verified_only`; a verified flag does.
- **Live (old OpenAI key, Spec H, $5 cap):** run 1+1 / exponential / gnalekcip; confirm the agent
  no longer dies on the first scraped token and reaches a real flag or exhausts steps cleanly.

## Definition of done

A planted decoy in tool output no longer ends a run. A rejected candidate resumes solving
automatically. `no_progress_streak` drives real pivots. Stop behavior is one config switch,
defaulting to "only stop on a verified flag." Legacy behavior remains available via config.
