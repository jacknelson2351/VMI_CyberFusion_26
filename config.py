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
    {"id": "gpt-5-mini",      "label": "gpt-5-mini (cheap)"},
    {"id": "gpt-5.2",         "label": "gpt-5.2 (mid)"},
    {"id": "claude-opus-4-6", "label": "claude-opus-4-6 (anthropic, expensive)"},
]
LAUNCH_MODEL_IDS = {m["id"] for m in LAUNCH_MODEL_CHOICES}
LAUNCH_MODEL_ALIASES = {
    "gpt5-mini":          "gpt-5-mini",
    "gpt5.2":             "gpt-5.2",
    "opus 4.6":           "claude-opus-4-6",
    "opus-4.6":           "claude-opus-4-6",
    "claude-opus-4.6":    "claude-opus-4-6",
    "claude opus 4.6":    "claude-opus-4-6",
}

DEFAULT_CONFIG = {
    "model": "gpt-5-mini",
    "auto_open_browser": True,
    "prompt_profile": "compact",
    "tool_context_limit": 4000,
    "strict_auto_submit": True,
    "allow_nonstandard_submit": False,
    "hypothesis_budget": 2,
    "allow_runtime_installs": False,
    "max_tool_calls_per_turn": 3,
    "family_budget_non_web": 4,
    "family_budget_web": 1,
    "broad_eval_min_total_challenges": 100,
    "broad_eval_min_categories": 5,
    "broad_eval_min_challenges_per_category": 10,
    "broad_eval_min_solve_rate": 0.6,
    "local_lock_enabled": False,
}


def load_config() -> dict:
    if not CONFIG_PATH.exists():
        return dict(DEFAULT_CONFIG)
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    merged = dict(DEFAULT_CONFIG)
    merged.update(cfg)
    return merged


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
