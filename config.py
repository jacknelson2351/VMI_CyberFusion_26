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
UPLOAD_DIR.mkdir(exist_ok=True)

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


def load_config() -> dict:
    if not CONFIG_PATH.exists():
        return {}
    return json.load(open(CONFIG_PATH))


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
