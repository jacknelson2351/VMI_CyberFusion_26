"""
Application configuration: paths, model lists, config-file helpers.
No local imports — safe for everything else to import.
"""
import json
from pathlib import Path

BASE_DIR    = Path(__file__).parent
CONFIG_PATH = BASE_DIR / "config.json"
DB_PATH     = BASE_DIR / "challenges.json"
UPLOAD_DIR  = BASE_DIR / "uploads"
WORKSPACES_DIR = BASE_DIR / "workspaces"
RUNS_DIR       = BASE_DIR / "runs"
UPLOAD_DIR.mkdir(exist_ok=True)
WORKSPACES_DIR.mkdir(exist_ok=True)
RUNS_DIR.mkdir(exist_ok=True)

CATEGORIES = ["pwn", "web", "crypto", "forensics", "rev", "misc", "osint", "network"]

LAUNCH_MODEL_CHOICES: list[dict[str, str]] = [
    # OpenAI — cheap
    {"id": "gpt-4.1-nano",       "label": "gpt-4.1-nano (cheapest)"},
    {"id": "gpt-4.1-mini",       "label": "gpt-4.1-mini (cheap)"},
    {"id": "gpt-5-mini",         "label": "gpt-5-mini (cheap)"},
    # OpenAI — mid
    {"id": "gpt-4.1",            "label": "gpt-4.1 (mid)"},
    {"id": "gpt-5.1",            "label": "gpt-5.1 (mid)"},
    {"id": "gpt-5.2",            "label": "gpt-5.2 (mid)"},
    {"id": "gpt-5.5",            "label": "gpt-5.5 (mid, newest)"},
    # OpenAI — reasoning
    {"id": "o4-mini",            "label": "o4-mini (reasoning, cheap)"},
    {"id": "o3",                 "label": "o3 (reasoning, mid)"},
    # Anthropic — cheap
    {"id": "claude-haiku-4-5",   "label": "claude-haiku-4-5 (anthropic, cheap)"},
    # Anthropic — mid
    {"id": "claude-sonnet-4-6",  "label": "claude-sonnet-4-6 (anthropic, mid)"},
    # Anthropic — expensive
    {"id": "claude-opus-4-6",    "label": "claude-opus-4-6 (anthropic, expensive)"},
    {"id": "claude-opus-4-7",    "label": "claude-opus-4-7 (anthropic, expensive, newest)"},
]
LAUNCH_MODEL_IDS = {m["id"] for m in LAUNCH_MODEL_CHOICES}
LAUNCH_MODEL_ALIASES = {
    "gpt5-mini":           "gpt-5-mini",
    "gpt5.1":              "gpt-5.1",
    "gpt5.2":              "gpt-5.2",
    "gpt5.5":              "gpt-5.5",
    "gpt4.1":              "gpt-4.1",
    "gpt4.1-mini":         "gpt-4.1-mini",
    "gpt4.1-nano":         "gpt-4.1-nano",
    "o4mini":              "o4-mini",
    "haiku":               "claude-haiku-4-5",
    "haiku-4.5":           "claude-haiku-4-5",
    "claude-haiku-4.5":    "claude-haiku-4-5",
    "sonnet":              "claude-sonnet-4-6",
    "sonnet-4.6":          "claude-sonnet-4-6",
    "claude-sonnet-4.6":   "claude-sonnet-4-6",
    "claude sonnet 4.6":   "claude-sonnet-4-6",
    "opus 4.6":            "claude-opus-4-6",
    "opus-4.6":            "claude-opus-4-6",
    "claude-opus-4.6":     "claude-opus-4-6",
    "claude opus 4.6":     "claude-opus-4-6",
    "opus 4.7":            "claude-opus-4-7",
    "opus-4.7":            "claude-opus-4-7",
    "claude-opus-4.7":     "claude-opus-4-7",
    "claude opus 4.7":     "claude-opus-4-7",
}

# Provider presets for the "New endpoint" UI flow and for migration. Each prefills the
# base_url / pricing / capabilities so adding a model needs only a name + key + model id.
PROVIDER_PRESETS = {
    "shannon": {
        "label": "Shannon (Kimi-K3 abliterated)",
        "provider_kind": "openai_compat",
        "base_url": "https://api.shannon-ai.com/v1",
        "api_key_ref": "shannon",
        "model_id": "kimi-k3-3bit-reap",
        "pricing": {"in": 3.83, "out": 19.12},
        "capabilities": {"tools": True, "vision": True},
        "context": 262144,
    },
    "openai": {
        "label": "OpenAI",
        "provider_kind": "openai_compat",
        "base_url": "",
        "api_key_ref": "openai",
        "model_id": "gpt-5.1",
        "pricing": {"in": 1.25, "out": 10.00},
        "capabilities": {"tools": True, "vision": True},
        "context": 400000,
    },
    "anthropic": {
        "label": "Anthropic",
        "provider_kind": "anthropic",
        "base_url": "",
        "api_key_ref": "anthropic",
        "model_id": "claude-opus-4-7",
        "pricing": {"in": 15.00, "out": 75.00},
        "capabilities": {"tools": True, "vision": True},
        "context": 200000,
    },
    "openrouter": {
        "label": "OpenRouter",
        "provider_kind": "openai_compat",
        "base_url": "https://openrouter.ai/api/v1",
        "api_key_ref": "openrouter",
        "model_id": "",
        "pricing": {"in": 0.0, "out": 0.0},
        "capabilities": {"tools": True, "vision": False},
        "context": 128000,
    },
    "vllm": {
        "label": "Self-hosted (vLLM)",
        "provider_kind": "openai_compat",
        "base_url": "http://localhost:8000/v1",
        "api_key_ref": "vllm",
        "model_id": "",
        "pricing": {"in": 0.0, "out": 0.0},
        "capabilities": {"tools": True, "vision": False},
        "context": 32768,
    },
}

DEFAULT_CONFIG = {
    "model": "gpt-5-mini",
    # Two-tier model policy: a strong reasoning model drives the solve loop; a cheap model
    # handles bulk/aux text (context summarization). `model` remains the back-compat fallback.
    "solver_model": "gpt-5.1",
    "recon_model": "gpt-5-mini",
    # Provider-agnostic model registry (see providers.py). Seeded by migrate_config() from
    # the legacy fields above so existing installs keep working with zero manual steps.
    "models": [],
    "keys": {},
    "roles": {},
    "auto_open_browser": True,
    "prompt_profile": "compact",
    "tool_context_limit": 4000,
    "strict_auto_submit": True,
    "allow_nonstandard_submit": False,
    "hypothesis_budget": 2,
    # Flag stop policy (Spec B): when the solve loop halts on a flag.
    #   "verified_only" (default) — only stop for a model-submitted or format+deterministic flag;
    #                               scraped/decoy tokens are recorded but the agent keeps solving.
    #   "first_candidate"          — legacy: stop on the first flag-shaped token found.
    #   "never"                    — never auto-stop; run to the step budget.
    "flag_stop_policy": "verified_only",
    "require_flag_approval": True,
    "allow_runtime_installs": False,
    "max_tool_calls_per_turn": 3,
    "checkpoint_interval": 5,
    "self_eval_interval": 10,
    "context_compression_interval": 15,
    "adaptive_tool_ranking": True,
    "family_budget_non_web": 4,
    "family_budget_web": 1,
    "broad_eval_min_total_challenges": 100,
    "broad_eval_min_categories": 5,
    "broad_eval_min_challenges_per_category": 10,
    "broad_eval_min_solve_rate": 0.6,
    "local_lock_enabled": False,
}


def _slug(text: str) -> str:
    import re
    s = re.sub(r"[^a-z0-9]+", "-", (text or "").strip().lower()).strip("-")
    return s or "model"


def migrate_config(cfg: dict) -> dict:
    """Idempotently seed the provider-agnostic registry from legacy config.

    Runs on every load. If `models` is already populated it is a no-op, so existing
    round-trips are safe. Legacy installs (openai_api_key / solver_model / recon_model)
    get a working registry with zero manual steps.
    """
    if cfg.get("models"):
        return cfg

    from pricing import MODEL_COSTS

    keys = dict(cfg.get("keys") or {})
    if cfg.get("openai_api_key") and not keys.get("openai"):
        keys["openai"] = cfg["openai_api_key"]
    if cfg.get("anthropic_api_key") and not keys.get("anthropic"):
        keys["anthropic"] = cfg["anthropic_api_key"]

    models = []
    for choice in LAUNCH_MODEL_CHOICES:
        mid = choice["id"]
        is_anthropic = _is_anthropic_model(mid)
        rates = MODEL_COSTS.get(mid)
        models.append({
            "id": mid,
            "name": mid,
            "provider_kind": "anthropic" if is_anthropic else "openai_compat",
            "base_url": "",
            "api_key_ref": "anthropic" if is_anthropic else "openai",
            "model_id": mid,
            "pricing": {"in": rates[0], "out": rates[1]} if rates else {"in": 0.0, "out": 0.0},
            "capabilities": {"tools": True, "vision": not mid.startswith(("o1", "o3", "o4"))},
            "context": 0,
        })

    # Pre-list the abliterated Kimi-K3 endpoint (keyless) so it is one field away from ready.
    shannon = dict(PROVIDER_PRESETS["shannon"])
    models.append({
        "id": "kimi-k3-abl",
        "name": "Kimi-K3 abliterated",
        "provider_kind": shannon["provider_kind"],
        "base_url": shannon["base_url"],
        "api_key_ref": shannon["api_key_ref"],
        "model_id": shannon["model_id"],
        "pricing": shannon["pricing"],
        "capabilities": shannon["capabilities"],
        "context": shannon["context"],
    })

    solver = _canonical_launch_model(cfg.get("solver_model") or cfg.get("model")) or "gpt-5.1"
    aux = _canonical_launch_model(cfg.get("recon_model") or cfg.get("model")) or "gpt-5-mini"
    roles = dict(cfg.get("roles") or {})
    roles.setdefault("solver", solver)
    roles.setdefault("aux", aux)

    cfg["models"] = models
    cfg["keys"] = keys
    cfg["roles"] = roles
    return cfg


def load_config() -> dict:
    if not CONFIG_PATH.exists():
        return migrate_config(dict(DEFAULT_CONFIG))
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    merged = dict(DEFAULT_CONFIG)
    merged.update(cfg)
    return migrate_config(merged)


def _as_bool(value, default=False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    s = str(value).strip().lower()
    if s in {"1", "true", "yes", "on"}:
        return True
    if s in {"0", "false", "no", "off"}:
        return False
    return default


def _canonical_launch_model(model: str | None) -> str:
    if model is None:
        return ""
    m = str(model).strip()
    if not m:
        return ""
    return LAUNCH_MODEL_ALIASES.get(m, m)


def _is_anthropic_model(model: str | None) -> bool:
    m = (model or "").strip().lower()
    return m.startswith(("claude-", "anthropic:", "anthropic/"))
