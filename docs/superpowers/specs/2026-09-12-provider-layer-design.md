# Spec A — Provider-agnostic model layer

**Date:** 2026-09-12
**Branch:** `feature/ctf-framework-overhaul`
**Status:** Design approved (brainstorm), ready for implementation plan
**Part of:** CTF Copilot overhaul (round 2). Sibling specs: B loop-control, C injection-resilience, D web-pentest, E category-coverage, F competitions/challenge-sets, G UI/observability, H eval-harness.

## Problem

The agent can only talk to OpenAI or Anthropic, and the provider is *guessed* from the
model name (`_is_anthropic_model()`, [config.py:128]). Clients are built as bare
`OpenAI(api_key=...)` / `Anthropic(...)` with **no `base_url`** ([core.py:102]), so there
is no way to point at an OpenAI-compatible endpoint. The next competition will be run on an
**abliterated Kimi-K3** (no refusal layer) served by a third party or self-hosted — both are
OpenAI-compatible endpoints the current code cannot reach. Refusals on planted prompt
injections are the #1 cause of failed runs; changing the model is the highest-leverage fix,
and it is currently impossible.

## Goal

Make the model fully data-driven: register any number of OpenAI-compatible or Anthropic
endpoints, see their cost + capabilities, assign roles (Solver / Aux), and switch freely —
managed from a clean Settings → Models tab with a Test-connection step. Ship with an
abliterated-Kimi-K3 preset. No behavior in the solve loop, flag logic, tools, or challenges
changes.

## Non-goals (owned by other specs)

- Auto-stop / flag-detection / resume behavior → **Spec B**
- Prompt-injection / refusal-recovery handling → **Spec C**
- Web-pentest tools, category tooling → **Specs D / E**
- Challenge-set / competition management → **Spec F**
- Breaking up the 4,480-line `templates/index.html` monolith, observability "student view"
  → **Spec G** (Spec A adds the Models tab *surgically* into the existing file)

## Data model

Stored in `config.json` (already git-untracked). Three new top-level keys:

```jsonc
{
  "models": [
    {
      "id": "kimi-k3-abl",              // stable internal id (slug)
      "name": "Kimi-K3 abliterated",    // display name
      "provider_kind": "openai_compat", // "openai_compat" | "anthropic"
      "base_url": "https://api.shannon-ai.com/v1",
      "api_key_ref": "shannon",         // -> keys["shannon"]
      "model_id": "kimi-k3-3bit-reap",  // the string sent to the API
      "pricing": { "in": 3.83, "out": 19.12 },   // USD per 1M tokens
      "capabilities": { "tools": true, "vision": true },
      "context": 262144
    }
  ],
  "keys": { "shannon": "sk-...", "openai": "sk-...", "anthropic": "" },
  "roles": { "solver": "kimi-k3-abl", "aux": "gpt-5-mini" }
}
```

Design rules:
- **Keys are never inline in a model entry** — always referenced via `api_key_ref` into the
  `keys` map, so a `models` list can be exported/shared without leaking secrets.
- `provider_kind` is explicit. `_is_anthropic_model()` is no longer used for routing (kept only
  as a fallback during migration).
- `roles` holds model **ids**, not model strings. Exactly two roles in v1: `solver` (drives the
  reasoning + tool loop) and `aux` (cheap context summarization / other bulk text).
- Environment variables still work as a fallback for keys (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`,
  and a new generic `<REF>_API_KEY` lookup by uppercased ref).

## Backend components

### `providers.py` (new — the missing seam)

Single-purpose module, no local imports beyond `config`/`pricing`:

- `ModelSpec` dataclass: `id, name, provider_kind, base_url, api_key, model_id, pricing (in,out),
  caps {tools, vision}, context`.
- `list_models(cfg) -> list[ModelSpec]`
- `resolve_model(cfg, ref_or_id) -> ModelSpec | None` — accepts a model id, a role name
  (`"solver"`/`"aux"`), or (migration) a raw model string.
- `resolve_role(cfg, role) -> ModelSpec` — role → spec, with sane fallback (aux falls back to
  solver; solver falls back to first available/legacy `model`).
- `build_client(spec) -> (client, kind)` — returns an `OpenAI(base_url=spec.base_url or None,
  api_key=spec.api_key)` for `openai_compat`, or `Anthropic(api_key=spec.api_key,
  base_url=spec.base_url or None)` for `anthropic`.
- `key_for(cfg, ref) -> str` — resolve `keys[ref]` else `os.environ[f"{ref.upper()}_API_KEY"]`.

### `config.py`

- Add `models`, `keys`, `roles` to `DEFAULT_CONFIG` (empty list / empty dict / empty dict).
- Add `PROVIDER_PRESETS`: name → `{provider_kind, base_url, default pricing, caps}` for
  Shannon (K3 abliterated), OpenAI, Anthropic, OpenRouter, Self-hosted vLLM. Used by the UI
  add-flow and by migration.
- `migrate_config(cfg) -> cfg` (idempotent): if `models` is absent/empty, seed it from the
  legacy fields — `openai_api_key`/`anthropic_api_key` → `keys.openai`/`keys.anthropic`;
  `LAUNCH_MODEL_CHOICES` → one `models` entry each (with pricing from `MODEL_COSTS`);
  `solver_model`/`recon_model` (or `model`) → `roles.solver`/`roles.aux`. Called on load.
- Keep `LAUNCH_MODEL_CHOICES` as the seed source only; the UI stops depending on it directly.

### `agent/core.py` + `agent/llm.py`

- In `__init__`: replace the openai/anthropic client construction ([core.py:100-103]) and the
  `_is_anthropic_model` provider inference ([core.py:95-98]) with:
  `self.solver_spec = resolve_role(cfg, "solver")`, `self.aux_spec = resolve_role(cfg, "aux")`,
  `self.client, self.provider = build_client(self.solver_spec)`,
  `self.aux_client, self.aux_provider = build_client(self.aux_spec)`.
  `self.model` becomes `self.solver_spec.model_id`.
- `_call()` routes on `self.solver_spec.provider_kind` instead of `self.provider` string
  guessing. `_call_openai` uses `self.client`; `_call_anthropic` uses the anthropic client.
- `_complete_text()` (aux/summaries) uses `self.aux_spec` + `self.aux_client`, falling back to
  the solver client if aux is unset — replacing today's `_is_anthropic_model(use_model)` branch.
- `analyze_image` ([tooling.py:138]) checks `self.solver_spec.caps["vision"]`; if false, it
  returns a clear "solver has no vision; assign a vision-capable model" message rather than
  failing cryptically. (A dedicated vision role is a later enhancement, not v1.)

### `pricing.py`

- `resolve_model_rates` already honors config overrides. Add: if a `ModelSpec` carries
  `pricing`, that wins. Practically, cost tracking reads the spec's pricing directly so any
  custom model meters correctly. The built-in `MODEL_COSTS` table stays as a fallback.

### Routes (`routes.py`)

- `GET /api/config` (`_public_config_payload`): include `models` (with keys **redacted** to a
  `key_set: bool` + last-4), `roles`, and `presets`. Never return raw key material.
- `POST /api/config`: accept `models` (full replace of the list), `roles`, and `keys`
  (merge; a blank value with a `clear_<ref>` flag removes). Validate each model entry
  (required fields, provider_kind enum, numeric pricing). Keep existing per-field handling for
  back-compat.
- `POST /api/models/test` (new): body `{provider_kind, base_url, model_id, api_key_ref | api_key}`.
  Builds a throwaway client and fires **one** minimal request — a 1-token completion including a
  dummy tool definition — then returns `{ok, status, tools, vision, context, latency_ms, error}`.
  `tools` = whether the endpoint accepted the tool schema without error; `vision`/`context` come
  from the preset/known metadata or the endpoint's `/models` response when available. Hard 10s
  timeout. Cost of the probe is negligible (1 token) but still metered to the run-independent
  ledger.
- Launch/readiness: `_default_launch_model()` and the launch model list source from
  `list_models(cfg)` (solver role default) instead of `LAUNCH_MODEL_CHOICES`.

## UI (surgical additions to `templates/index.html`)

The Settings modal becomes a **left tab rail**: General · Models · Agent · Security · Docker.
Existing controls move under General/Agent/Security/Docker unchanged. New **Models tab**:

- **Row list** — one row per registered model: status dot (key set + last test), name,
  provider badge, `provider · model_id · context`, capability chips (tools/vision/no-refusal),
  cost `$in/$out`, and a **role tag** (`◆ Solver`, `Aux`, or `set role`). Clicking a role tag
  opens a tiny menu to assign Solver/Aux.
- **＋ New endpoint** slide-over — provider **preset** chips (Shannon K3 / OpenAI / Anthropic /
  OpenRouter / Self-hosted vLLM) prefill `base_url` + pricing + caps; fields: Name, Base URL,
  Model ID, API key; **Test connection** button → shows `200 OK · tools ✓ · vision ✓ · ctx ·
  latency`; **Save model**. Edit/delete via a row overflow menu.
- Ships with the Shannon abliterated-K3 preset so adding it needs only a key.
- Data flows through the existing `fetch("/api/config")` GET/POST plus the new
  `/api/models/test`. Matches the current dark/orange aesthetic (mockups in
  `.superpowers/brainstorm/`).

## Migration & safety

- `migrate_config` runs on every `load_config` and is idempotent — existing installs keep
  working with zero manual steps; the old flat Settings fields still round-trip.
- No keys ever leave the backend in API responses.
- If `models` is empty after migration (fresh install, no legacy keys), the UI shows an empty
  state prompting "Add your first model".

## Testing

- **Unit:** `migrate_config` idempotency + correct seeding from each legacy shape;
  `resolve_role` fallbacks; `build_client` returns a base_url'd OpenAI client for `openai_compat`;
  pricing resolves from a `ModelSpec`.
- **Route:** `/api/config` GET redacts keys; POST validates/round-trips a `models` list;
  `/api/models/test` returns a structured result on a mocked client and on a bad endpoint.
- **Manual:** add the Shannon K3 preset with a real key, Test connection passes, assign Solver,
  launch one offline challenge, confirm it calls the endpoint and meters cost. (Counts against
  the $5 Spec-H budget — a single cheap challenge.)

## Definition of done

Add an abliterated-Kimi-K3 endpoint through the UI in well under a minute (preset + key + test),
set it as Solver, and run a challenge on it end-to-end with correct cost metering — without
editing any Python. OpenAI/Anthropic setups that exist today keep working untouched.
