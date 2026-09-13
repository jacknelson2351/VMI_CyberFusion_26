# Spec C — Agent core rebuild (Planner/Executor + Interactive Agent Tools + ACI)

**Date:** 2026-09-13
**Branch:** `feature/ctf-framework-overhaul`
**Status:** Design, building now
**Depends on:** A (provider layer, shipped), B (loop control, shipped)

## Why

The agent is a single flat `model → tools → model` loop ([agent/graph.py]) driving mostly
**one-shot** commands (`run_gdb` batch mode, `remote_interact` connect-send-close,
`run_command` per-call). Current SOTA CTF agents beat this decisively with three ideas we are
adopting (grounded in research, 2026):

1. **Planner / Executor decomposition** — D-CIPHER (SOTA on NYU CTF / CyBench / HackTheBox):
   a Planner holds the strategy and delegates focused subtasks to **fresh-context Executors**;
   each task is a new conversation, which cuts context bloat and hallucination and lets a task
   go deep without polluting the global thread. (arXiv 2502.10931)
2. **Interactive Agent Tools (IATs)** — EnIGMA: *persistent* interactive sessions (a live gdb,
   a held-open remote socket, a stateful shell) instead of one-shot calls, plus **summarization**
   of long tool output. IATs "substantially assist." (arXiv 2409.16165)
3. **ACI design principles** — SWE-agent: efficiency over familiarity, information density,
   error prevention, context awareness. Every tool returns concise, actionable feedback.
   (arXiv 2405.15793)

## Architecture

Keep LangGraph (already present, well-suited to multi-node flows). Introduce a config switch
`agent_architecture: "planner_executor" (default) | "single_loop" (legacy fallback)` so we can
A/B and always have a safe path.

### 1. Planner / Executor graph (`agent/graph_pe.py`, new)

Nodes:
- **auto_prompter** (reuse/upgrade current `_auto_recon`): explores the workspace + target for
  a few cheap steps, emits a tailored situation brief for the Planner. (D-CIPHER Auto-prompter.)
- **planner**: given the brief + global memory + executor summaries, produces/updates a **plan**
  (ordered list of concrete subtasks, each with a goal + success test + suggested tools) and
  picks the next subtask. Planner never runs solve tools itself — it strategizes and delegates.
  Runs on the Solver model.
- **executor**: spawned per subtask with a **fresh, minimal context** (the subtask, relevant
  evidence slice, available tools). Runs its own bounded `model → tools` mini-loop (the current
  loop logic, reused), then returns a **structured summary**: `{outcome, evidence[],
  flag_candidates[], next_hint, spent_steps}`. Executors are where tools run.
- **integrator**: folds the executor summary into global memory + the candidate ledger (Spec B),
  updates confirmed/ruled-out evidence, and routes back to Planner (re-plan) or to END
  (verified flag via Spec B `_should_halt_for`, or global step budget hit).

State: `{brief, plan[], current_task, executor_summaries[], rounds, stop_reason}`. Global step
budget = category limit; per-executor sub-budget keeps a single task from running away.

The existing single-loop (`run_solver_graph`) stays as the executor's inner engine AND as the
`single_loop` fallback — so this is additive, not a rewrite-from-zero.

### 2. Interactive Agent Tools (`agent/interactive.py`, new)

Persistent, session-backed tools living in the challenge container (via `docker exec` with a
kept-open process, tracked by session id):
- **`shell_session`**: a persistent bash session (cwd, env, and shell state persist across
  calls). ops: `run`, `read`, `close`. Replaces stateless `run_command` for multi-step work.
- **`gdb_session`**: a persistent gdb+pwndbg session — `start`, `send` (any gdb cmd), `read`,
  `close`. Enables real dynamic analysis / interactive exploitation (batch `run_gdb` stays for
  quick triage). This is the EnIGMA interactive-debugger equivalent.
- **`remote_session`**: a held-open TCP/WebSocket/ssh connection — `connect`, `send`, `recv`,
  `close` — for multi-round remote exploitation (the current one-shot `remote_interact` closed
  the socket every call, which broke stateful services).
Each returns ACI-style output: current session state + **summarized** tail of new output, with
a hard cap and a one-line status. Long output is summarized by the Aux model (Spec A) before it
enters context.

### 3. ACI feedback layer (`agent/aci.py`, new helper used by all tools)

`format_tool_result(raw, *, kind, limit, summarize=True)`:
- trims to an information-dense window (head+tail, not blind truncation),
- extracts salient lines (errors, addresses, hex, flag-shaped tokens, http status),
- optionally Aux-summarizes the middle,
- returns `<= limit` chars with a consistent, parseable shape.
Errors become **actionable** ("binary not found at /ctf/x — list files with shell_session").
Applied uniformly so the model always gets clean, dense feedback.

### 4. Injection/refusal boundary (folds in old Spec C intent)

Executor context wraps all tool output in an explicit untrusted-data envelope (already partly in
`_defang_injection`) — but now it is structural (a dedicated `role:tool` block the Planner never
treats as instructions) rather than regex-gated. With the abliterated Solver model (Spec A) the
refusal problem largely disappears; this boundary stops the agent from *obeying* planted
injections regardless of model.

## Implementation order (staged, each keeps tests green + app running)

1. **ACI layer** (`aci.py`) + route existing tools' output through it. Low risk, immediate polish.
2. **Interactive tools** (`interactive.py`) + register `shell_session` / `gdb_session` /
   `remote_session` as tools. High value for pwn/rev/remote.
3. **Planner/Executor graph** (`graph_pe.py`) behind `agent_architecture` flag; wire
   `_run`/`_resume_run` to pick the graph. Biggest lever.
4. Tests at each stage; a `$5` live eval (Spec H) after stage 3 to measure the delta.

## Testing

- ACI: summarization preserves flag-shaped tokens, errors, addresses; respects the char cap.
- Interactive: session persistence (a var set in one `shell_session.run` is visible in the next);
  gdb session survives multiple sends; remote session keeps the socket open across sends (mocked).
- Planner/Executor: planner emits a plan; an executor returns a structured summary; a verified
  flag from an executor halts per Spec B; global step budget respected; `single_loop` fallback
  still works (existing 39 tests must stay green).

## Definition of done

`agent_architecture="planner_executor"` runs a challenge as Planner delegating to fresh-context
Executors that use persistent interactive tools with clean ACI feedback; a verified flag halts
via Spec B; the legacy single loop remains selectable and all existing tests pass.
