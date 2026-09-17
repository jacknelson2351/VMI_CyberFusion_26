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
    # Common CSS/JS/control-flow blocks that match WORD{...} syntactically but
    # are not challenge flags.
    if p in {
        "hover", "active", "focus", "visited", "disabled", "before", "after",
        "root", "media", "supports", "keyframes", "from", "to", "function",
        "if", "for", "while", "switch", "class", "try", "catch",
    }:
        return False
    # CSS declaration blocks commonly look like hover{ transform: ...; }.
    if ":" in inner and ";" in inner:
        return False
    if re.search(
        r"\b(?:transform|filter|display|position|margin|padding|background|"
        r"border|color|font|width|height|opacity|animation|transition)\s*:",
        inner,
        re.IGNORECASE,
    ):
        return False
    if re.search(r"\b(?:translate[XYZ]?|brightness|rgba?|calc|var)\s*\(", inner, re.IGNORECASE):
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


# Placeholder/decoy flags planted in challenge source and binaries (e.g. UMDCTF{fake_flag},
# UMDCTF{test_flag}, TRX{fake_flag_for_testing}). These caused false "solved" submissions.
# Conservative on purpose: only match unmistakable placeholder wording, never a bare "test".
_DECOY_INNER_RE = re.compile(
    r"(?i)(?:"
    r"fake[_\- ]?flag|test[_\- ]?flag|flag[_\- ]?here|your[_\- ]?flag|real[_\- ]?flag[_\- ]?here|"
    r"for[_\- ]?testing|placeholder|redacted|changeme|not[_\- ]?the[_\- ]?flag|not[_\- ]?real|"
    r"example[_\- ]?flag|sample[_\- ]?flag|dummy[_\- ]?flag|\bfake\b|\bdummy\b|\bxxxx+\b|\.\.\."
    r")"
)


def _looks_like_decoy_flag(token: str) -> bool:
    """True for obvious planted placeholder flags that must never be submitted."""
    m = re.fullmatch(r"([A-Za-z][A-Za-z0-9_]{2,23})\{([^{}\n]{1,220})\}", (token or "").strip())
    if not m:
        return False
    inner = m.group(2).strip()
    return bool(_DECOY_INNER_RE.search(inner))


def _prefix_looks_ctf_like(prefix: str) -> bool:
    p = (prefix or "").lower()
    hints = (
        "flag", "ctf", "pico", "htb", "hero", "cyber", "seccon",
        "buckeye", "uiuctf", "umass", "lactf", "zer0pts", "dawg",
    )
    return any(h in p for h in hints)


def _is_picoctf_flag(token: str) -> bool:
    return re.fullmatch(r"picoCTF\{[^{}\n]{1,220}\}", (token or "").strip(), re.IGNORECASE) is not None


def _is_high_signal_evidence_text(text: str) -> bool:
    """
    Facts worth preserving across longer runs: file magic, binary protections,
    target/service URLs, and discovered flag-like tokens.
    """
    t = str(text or "")
    if not t:
        return False
    return bool(re.search(
        r"\b(?:https?://|Flag-like token observed:)|"
        r":\s+(?:ELF|PE32|Mach-O|JPEG|PNG|ZIP|PDF|Python|ASCII text|gzip|bzip2|RAR|7-zip)\b|"
        r"(?:NX|PIE|Canary|RELRO)(?:\s+found|:\s+(?:enabled|disabled|partial|full|no)\b)",
        t,
        re.IGNORECASE,
    ))


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
