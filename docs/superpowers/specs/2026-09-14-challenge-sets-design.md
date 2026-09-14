# Spec F — Competitions & challenge sets

**Date:** 2026-09-14
**Branch:** `feature/ctf-framework-overhaul`
**Status:** Design, building now
**Depends on:** existing db.py/storage.py.

## Problem

All challenges live in one flat `challenges.json` (the last UMD CTF set). There's no way to keep
multiple competitions/sets, switch between them, or run one set to stress-test without clobbering
another. The user wants to select different competitions and challenge sets from the UI and run
subsets to measure the agent.

## Design (additive — legacy file keeps working)

Introduce **challenge sets** as a directory, with the active set backing the existing DB path:

- `challenge_sets/<id>.json` — a set's challenges, **same schema** as `challenges.json`, so all
  existing db/storage/agent code works unchanged once the path points here.
- `challenge_sets/index.json` — `{ "active": "<id>", "sets": { "<id>": {"name","competition",
  "created_at"} } }`. Single source of truth for which set is active + per-set metadata.
- `config.current_db_path()` resolves to `challenge_sets/<active>.json` when an active set exists,
  else falls back to the legacy `challenges.json`. `db.py` reads/writes through this instead of the
  `DB_PATH` constant.
- **Seeding (idempotent):** on first access, if `challenge_sets/` has no sets and legacy
  `challenges.json` exists, copy it to `challenge_sets/umdctf.json`, register it in the index as
  "UMD CTF" (competition "UMDCTF"), and mark it active. Nothing is lost; the legacy file remains.

## Backend (`db.py` set helpers + `routes.py`)

- `list_challenge_sets()` → `[{id, name, competition, count, solved, active}]`.
- `activate_challenge_set(id)` → set index active (validates existence).
- `create_challenge_set(name, competition, challenges=[])` → new id (slug), writes file + index.
- `delete_challenge_set(id)` → remove (guard: cannot delete the active set unless another exists).
- `rename_challenge_set(id, name, competition)`.
- Routes: `GET /api/challenge-sets`, `POST /api/challenge-sets` (create),
  `POST /api/challenge-sets/<id>/activate`, `PUT /api/challenge-sets/<id>` (rename),
  `DELETE /api/challenge-sets/<id>`. Existing `/api/challenges/import` can target the active set
  (unchanged) or a new set via `?as_new_set=Name`.

## UI (surgical)

A compact **set selector in the header**: a dropdown showing the active set (name + count +
solved), switching triggers `activate` then reloads the challenge list. A small "New set" action
opens a minimal create form (name + competition, or import a JSON). Matches the dark/orange theme.
(Deeper set-management UX can move to a Settings tab under Spec G.)

## Testing

- Seeding is idempotent and preserves the legacy file.
- `current_db_path` returns the active set's path, falls back when none.
- create/activate/list/delete round-trip against a temp sets dir; delete guards the active set.
- Existing 57 tests stay green (DB behavior unchanged for the active set).

## Definition of done

Multiple challenge sets coexist; switching the active set in the UI swaps the challenge list; the
UMD set is auto-migrated as the first set; agent/db code is unchanged apart from the dynamic path.
