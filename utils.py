"""
Small, stateless utility functions with no local dependencies.
"""
import re


def _shell_quote(s: str) -> str:
    return "'" + s.replace("'", "'\"'\"'") + "'"


def _decode_backslash_escapes(s: str) -> str:
    """Decode common backslash escapes used in metadata blobs (e.g. \\075 for '=')."""
    if not s:
        return s
    out = s
    out = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), out)
    out = re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), out)
    return out


def _is_plausible_flag_token(token: str) -> bool:
    """
    Conservative filter to avoid obvious false positives (especially JSON/object blobs)
    while still accepting common CTF formats like picoCTF{...}, flag{...}, HTB{...}.
    """
    m = re.fullmatch(r"([A-Za-z][A-Za-z0-9_]{2,23})\{([^{}\n]{1,220})\}", (token or "").strip())
    if not m:
        return False
    prefix = m.group(1).strip()
    inner  = m.group(2).strip()
    if not inner:
        return False
    p = prefix.lower()
    # Common non-flag interface identifiers in packet captures.
    if p.startswith("npf"):
        return False
    # Reject pure GUID payloads unless prefix strongly suggests CTF flag format.
    if re.fullmatch(r"[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}", inner):
        if not _prefix_looks_ctf_like(prefix):
            return False
    # Reject likely JSON/object payloads.
    if (inner.startswith('"') and ":" in inner) or inner.startswith("{"):
        return False
    if inner.count('"') >= 2 and inner.count(":") >= 1 and inner.count(",") >= 1:
        return False
    return True


def _prefix_looks_ctf_like(prefix: str) -> bool:
    p = (prefix or "").lower()
    hints = (
        "flag", "ctf", "pico", "htb", "hero", "cyber", "seccon",
        "buckeye", "uiuctf", "umass", "lactf", "zer0pts", "dawg",
    )
    return any(h in p for h in hints)


def _is_approval_seeking_text(text: str) -> bool:
    t = (text or "").lower()
    pats = (
        "do you approve", "should i proceed", "which should i run next",
        "if you want me to", "do you want me to proceed", "if you want, i can",
        "if you want me to proceed",
    )
    return any(p in t for p in pats)


def _safe_float(value, default: float) -> float:
    try:
        return float(value)
    except Exception:
        return default
