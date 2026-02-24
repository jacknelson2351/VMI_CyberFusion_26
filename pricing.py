"""
Model pricing tables, rate resolution helpers, and pip package name mapping.
No local imports — safe for everything else to import.
"""
import re

# ── Token prices (per 1 M tokens: input, output) ──────────────────────────────

MODEL_COSTS = {
    # OpenAI
    "gpt-5.2":                        ( 1.75,  14.00),
    "gpt-5.2-chat-latest":            ( 1.75,  14.00),
    "gpt-5.2-pro":                    (21.00, 168.00),
    "gpt-5.1":                        ( 1.25,  10.00),
    "gpt-5.1-chat-latest":            ( 1.25,  10.00),
    "gpt-5-pro":                      (15.00, 120.00),
    "gpt-5-mini":                     ( 0.25,   2.00),
    "gpt-5.1-codex-mini":             ( 0.25,   2.00),
    "gpt-4.1":                        ( 2.00,   8.00),
    "gpt-4.1-mini":                   ( 0.40,   1.60),
    "gpt-4.1-nano":                   ( 0.10,   0.40),
    "gpt-4o":                         ( 2.50,  10.00),
    "gpt-4o-2024-05-13":              ( 5.00,  15.00),
    "gpt-4o-mini":                    ( 0.15,   0.60),
    "gpt-realtime":                   ( 4.00,  16.00),
    "gpt-realtime-mini":              ( 0.60,   2.40),
    "gpt-4o-realtime-preview":        ( 5.00,  20.00),
    "gpt-4o-mini-realtime-preview":   ( 0.60,   2.40),
    "gpt-audio":                      ( 2.50,  10.00),
    "gpt-audio-mini":                 ( 0.60,   2.40),
    "gpt-4o-audio-preview":           ( 2.50,  10.00),
    "gpt-4o-mini-audio-preview":      ( 0.15,   0.60),
    "o1":                             (15.00,  60.00),
    "o1-pro":                         (150.00, 600.00),
    "o3":                             ( 2.00,   8.00),
    "o3-pro":                         (20.00,  80.00),
    "o3-mini":                        ( 1.10,   4.40),
    "o1-mini":                        ( 1.10,   4.40),
    "o4-mini":                        ( 1.10,   4.40),
    "o4-mini-deep-research":          ( 2.00,   8.00),
    "o3-deep-research":               (10.00,  40.00),
    "gpt-5-search-api":               ( 1.25,  10.00),
    "gpt-4o-search-preview":          ( 2.50,  10.00),
    "gpt-4o-mini-search-preview":     ( 0.15,   0.60),
    "computer-use-preview":           ( 3.00,  12.00),
    "codex-mini-latest":              ( 1.50,   6.00),
    # Anthropic / Claude
    "claude-opus-4-6":                (15.00,  75.00),
    "claude-sonnet-4-6":              ( 3.00,  15.00),
    "claude-sonnet-4-5":              ( 3.00,  15.00),
    "claude-haiku-4-5":               ( 0.80,   4.00),
    "claude-haiku-4-5-20251001":      ( 0.80,   4.00),
    "claude-3-5-sonnet-20241022":     ( 3.00,  15.00),
    "claude-3-5-sonnet-20240620":     ( 3.00,  15.00),
    "claude-3-5-haiku-20241022":      ( 0.80,   4.00),
    "claude-3-opus-20240229":         (15.00,  75.00),
    "claude-3-haiku-20240307":        ( 0.25,   1.25),
    "claude-3-sonnet-20240229":       ( 3.00,  15.00),
}

# ── Module → pip package name mapping ────────────────────────────────────────

PIP_NAME_MAP = {
    "Crypto":       "pycryptodome",
    "crypto":       "pycryptodome",
    "Cryptodome":   "pycryptodome",
    "PIL":          "Pillow",
    "yaml":         "PyYAML",
    "sklearn":      "scikit-learn",
    "cv2":          "opencv-python-headless",
    "bs4":          "beautifulsoup4",
    "lxml":         "lxml",
    "requests":     "requests",
    "numpy":        "numpy",
    "pandas":       "pandas",
    "gmpy2":        "gmpy2",
    "z3":           "z3-solver",
    "pwn":          "pwntools",
    "angr":         "angr",
    "scapy":        "scapy",
    "ecdsa":        "ecdsa",
    "sympy":        "sympy",
    "factordb":     "factordb-pycli",
    "hashpumpy":    "hashpumpy",
    "randcrack":    "randcrack",
    "stegoveritas": "stegoveritas",
}


def _infer_pip_package(mod_name: str) -> str:
    if not mod_name:
        return ""
    root = mod_name.split(".")[0]
    return PIP_NAME_MAP.get(root, root)


# ── Rate resolution ───────────────────────────────────────────────────────────

def _normalize_model_key(name: str) -> str:
    return (name or "").strip().lower()


def _get_rates(mapping: dict, key: str):
    if not key:
        return None
    v = mapping.get(key)
    if not v:
        return None
    if isinstance(v, (list, tuple)) and len(v) >= 2:
        return float(v[0]), float(v[1])
    if isinstance(v, dict):
        inp = v.get("input_per_million") or v.get("input") or v.get("in")
        out = v.get("output_per_million") or v.get("output") or v.get("out")
        if inp is None or out is None:
            return None
        return float(inp), float(out)
    return None


def resolve_model_rates(model: str, cfg: dict):
    key       = _normalize_model_key(model)
    overrides = cfg.get("model_pricing") or {}

    # Try config override (exact, normalized, -latest).
    rates = _get_rates(overrides, model) or _get_rates(overrides, key)
    if not rates and key.endswith("-latest"):
        rates = _get_rates(overrides, key[:-7])

    # Fall back to built-in table (exact, -latest, -YYYY-MM-DD).
    if not rates:
        rates = _get_rates(MODEL_COSTS, key)
    if not rates and key.endswith("-latest"):
        rates = _get_rates(MODEL_COSTS, key[:-7])
    if not rates:
        base = re.sub(r"-20\d\d-\d\d-\d\d$", "", key)
        if base != key:
            rates = _get_rates(overrides, base) or _get_rates(MODEL_COSTS, base)

    return key, rates
