"""
Agent-Computer Interface (ACI) feedback layer.

SWE-agent's finding: LM agents perform far better when tool output is information-dense and
concise rather than raw/verbose. Instead of blindly truncating to the first N chars (which
buries the flag, the error, or the leaked address that appears late in output), we keep a
head + tail window and pull the *salient* lines from the middle. No LLM call — this is cheap,
deterministic condensation applied uniformly to every tool result.
"""
from __future__ import annotations

import re

# Lines that almost always matter in CTF tool output.
_SALIENT = re.compile(
    r"("
    r"[a-zA-Z0-9_]{2,24}\{[^{}\n]{1,220}\}"          # flag-shaped tokens
    r"|Traceback|Exception|Segmentation fault|core dumped"
    r"|No such file|command not found|Permission denied|No module named"
    r"|error[: ]|failed|FAIL|panic:"                  # generic errors
    r"|0x[0-9a-fA-F]{4,}"                              # addresses / hex
    r"|HTTP/\d|Set-Cookie:|Location:|WWW-Authenticate:" # web signals
    r"|password|passwd|secret|token|api[_-]?key|private key|BEGIN [A-Z ]*KEY"
    r"|root:x:|/bin/bash|uid=\d|gid=\d"               # shell / passwd
    r"|RSP|RIP|RAX|canary|PIE|NX|RELRO|Stack"          # pwn/checksec
    r")",
    re.IGNORECASE,
)


def salient_lines(text: str, max_lines: int = 40) -> list[str]:
    out, seen = [], set()
    for ln in (text or "").splitlines():
        s = ln.strip()
        if not s or s in seen:
            continue
        if _SALIENT.search(s):
            seen.add(s)
            out.append(ln)
            if len(out) >= max_lines:
                break
    return out


def condense(text: str, limit: int = 4000, kind: str = "generic") -> str:
    """Return an information-dense view of `text` within `limit` chars.

    Small output is returned unchanged. Large output becomes: head window +
    extracted salient lines + tail window, so the flag/error/address is never lost to
    naive truncation."""
    text = "" if text is None else str(text)
    if len(text) <= limit:
        return text

    head_take = int(limit * 0.45)
    tail_take = int(limit * 0.30)
    head = text[:head_take]
    tail = text[-tail_take:]

    middle = text[head_take:-tail_take] if len(text) > head_take + tail_take else ""
    sal = salient_lines(middle)
    sal_block = ""
    if sal:
        joined = "\n".join(sal)
        budget = max(0, limit - len(head) - len(tail) - 120)
        if len(joined) > budget:
            joined = joined[:budget]
        sal_block = f"\n…[{len(text)} chars total; salient lines from the middle]…\n{joined}\n"

    result = f"{head}{sal_block}\n…[middle elided]…\n{tail}"
    if len(result) > limit:
        # Final safety clamp — keep head + tail.
        keep_tail = tail[-tail_take:]
        result = f"{head}\n…[truncated {len(text)} chars]…\n{keep_tail}"
    return result


def actionable_error(raw: str) -> str | None:
    """Turn a common failure into an actionable hint, or None if not recognized."""
    t = raw or ""
    if re.search(r"No such file or directory", t):
        return "Path not found — list files first (shell_session `ls -la /ctf`)."
    if re.search(r"command not found", t):
        m = re.search(r"([\w.-]+): command not found", t)
        tool = m.group(1) if m else "the tool"
        return f"{tool} is not installed — install it (apt-get/pip) or use an alternative."
    if re.search(r"No module named ['\"]?([\w.]+)", t):
        m = re.search(r"No module named ['\"]?([\w.]+)", t)
        return f"Missing Python module '{m.group(1)}' — pip install it into /ctf/.venv."
    if re.search(r"Permission denied", t):
        return "Permission denied — chmod +x the target or run via the interpreter."
    return None
