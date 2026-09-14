"""
FlagsMixin — flag candidate extraction and auto-submit logic.
"""
import base64
import re

from utils import (
    _is_plausible_flag_token, _prefix_looks_ctf_like, _decode_backslash_escapes, _is_picoctf_flag,
    _looks_like_decoy_flag,
)


class FlagsMixin:

    def _allows_noncanonical_submit(self, flag: str, how: str) -> bool:
        if self.allow_nonstandard_submit:
            return True
        if self.flag_format:
            return self._flag_matches_format(flag)
        return False

    def _flag_matches_format(self, flag: str) -> bool:
        if _is_picoctf_flag(flag):
            return True
        fmt = self.flag_format
        if not fmt:
            return True
        try:
            if re.search(fmt, flag):
                return True
        except re.error:
            pass
        return flag.startswith(fmt) or flag == fmt

    def _extract_flag_candidates(self, text: str) -> list[str]:
        if not text:
            return []
        candidates = []
        seen = set()
        variants = [text]
        escaped = _decode_backslash_escapes(text)
        if escaped != text:
            variants.append(escaped)

        def add_candidate(v: str):
            vv = (v or "").strip()
            if not vv or vv in seen:
                return
            if not _is_plausible_flag_token(vv):
                return
            if _looks_like_decoy_flag(vv):
                seen.add(vv)  # remember so we don't reconsider, but never offer it
                self.emit("thought", {
                    "text": f"Ignoring planted decoy/placeholder flag: {vv}",
                    "type": "system",
                })
                return
            seen.add(vv)
            candidates.append(vv)

        for blob in variants:
            # Direct flag-like tokens.
            for m in re.finditer(r"\b[a-zA-Z0-9_]{2,24}\{[^{}\n]{1,220}\}", blob):
                add_candidate(m.group(0))

            # Decode base64-like tokens and re-scan for flag-like strings.
            for m in re.finditer(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/])", blob):
                tok = m.group(0)
                try:
                    decoded = base64.b64decode(tok, validate=True).decode("utf-8", errors="ignore")
                except Exception:
                    continue
                for fm in re.finditer(r"\b[a-zA-Z0-9_]{2,24}\{[^{}\n]{1,220}\}", decoded):
                    add_candidate(fm.group(0))

        return candidates

    def _is_likely_system_flag_artifact(self, token: str, text: str) -> bool:
        t = (token or "").strip()
        m = re.fullmatch(r"([A-Za-z][A-Za-z0-9_]{2,23})\{([^{}\n]{1,220})\}", t)
        if not m:
            return False
        prefix = m.group(1).strip().lower()
        inner = m.group(2).strip()
        if prefix.startswith("npf"):
            return True
        if re.fullmatch(r"[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}", inner):
            # If surrounding output looks like capture interface metadata, treat as artifact.
            if re.search(r"(\\device\\npf_|npcap|dumpcap|wireshark|interface|adapter)", (text or ""), re.IGNORECASE):
                return True
            if not _prefix_looks_ctf_like(prefix):
                return True
        return False

    def _is_deterministic_flag_source(self, source: str, src_key: str) -> bool:
        if src_key in {"search_flag", "run_gdb", "extract_artifact", "extract_artifact_scan"}:
            return True
        if src_key != "run_command":
            return False
        cmd = (source or "").split(":", 1)[1].strip().lower() if ":" in (source or "") else ""
        if not cmd:
            return False
        noisy_network = r"\b(?:curl|wget|httpie|sqlmap|ffuf|gobuster|feroxbuster|wfuzz|nc|ncat|socat)\b|https?://"
        if re.search(noisy_network, cmd):
            return False
        deterministic_local = (
            r"^(?:/ctf/\.venv/bin/)?python(?:3(?:\.\d+)?)?\b|"
            r"^(?:sage|node|ruby|perl)\b|"
            r"^(?:\./|/ctf/)[A-Za-z0-9_./+-]+"
        )
        return bool(re.search(deterministic_local, cmd))

    def _has_strong_auto_submit_evidence(self, token: str, text: str, src_key: str, source: str = "") -> bool:
        evidence_sources = self._flag_evidence.get(token, set())
        # Deterministic local tools/scripts don't need corroboration. Broad web and
        # network output still requires repetition or a second source.
        is_deterministic = self._is_deterministic_flag_source(source, src_key)
        return (
            is_deterministic
            or (text or "").count(token) >= 2
            or len(evidence_sources) >= 2
        )

    def _choose_auto_submit_candidate(self, candidates: list[str], text: str, src_key: str, source: str = "") -> str | None:
        if not candidates:
            return None
        if self.flag_format:
            for c in candidates:
                if self._flag_matches_format(c):
                    return c
            return None
        if not self.strict_auto_submit:
            for c in candidates:
                if not self._is_likely_system_flag_artifact(c, text):
                    return c
            return None

        # Strict mode: only auto-submit CTF-like prefixes with corroboration.
        for c in candidates:
            if self._is_likely_system_flag_artifact(c, text):
                continue
            prefix = c.split("{", 1)[0]
            if not _prefix_looks_ctf_like(prefix):
                continue
            if self._has_strong_auto_submit_evidence(c, text, src_key, source=source):
                return c
        return None

    def _recursive_decode_strings(self, text: str, max_rounds: int = 4) -> list[str]:
        """Recursively decode base64 and hex tokens, following encoding chains.
        Returns all intermediate and final decoded strings in order."""
        out = []
        seen = set()
        queue = [text or ""]
        rounds = 0
        while queue and rounds < max_rounds:
            rounds += 1
            cur = queue.pop(0)
            if not cur or cur in seen:
                continue
            seen.add(cur)
            out.append(cur)
            unescaped = _decode_backslash_escapes(cur)
            if unescaped and unescaped not in seen and unescaped != cur:
                queue.append(unescaped)
            # Base64-looking tokens (≥8 chars, valid b64 alphabet).
            # Note: trailing `\b` breaks when the token ends with `=` (non-word char),
            # so we use a negative lookahead instead.
            for m in re.finditer(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{8,}={0,2}(?![A-Za-z0-9+/])", cur):
                tok = m.group(0)
                try:
                    dec = base64.b64decode(tok, validate=True).decode("utf-8", errors="ignore")
                except Exception:
                    continue
                if dec and dec not in seen:
                    queue.append(dec)
            # Also try decoding the entire string as base64 (for when the whole value is encoded).
            stripped = (cur or "").strip()
            if stripped and stripped not in seen and len(stripped) >= 8:
                try:
                    whole = base64.b64decode(stripped + "==", validate=False).decode("utf-8", errors="ignore")
                    if whole and whole.isprintable() and whole not in seen and whole != stripped:
                        queue.append(whole)
                except Exception:
                    pass
            # Hex strings: 0x prefixed or even-length hex sequences.
            for m in re.finditer(r"(?:0x)?([0-9a-fA-F]{16,})", cur):
                tok = m.group(1)
                if len(tok) % 2 == 0:
                    try:
                        dec = bytes.fromhex(tok).decode("utf-8", errors="ignore")
                        if dec and dec.isprintable() and dec not in seen:
                            queue.append(dec)
                    except Exception:
                        pass
        return out

    def _maybe_auto_submit_from_output(self, output: str, source: str = "") -> bool:
        """Regex never DECIDES a flag. It only surfaces a flag-shaped lead to the model, which
        must reason about whether it's the real flag and, if confident, call submit_flag itself.
        This method never auto-submits and never halts the run — it always returns False so the
        tool's real output (which contains the token) is returned to the model to reason over.
        A verification hint is appended to that output via _compact_tool_result_for_context."""
        if not self.running:
            return False
        self._harvest_action_hints(output or "")
        candidates = self._extract_flag_candidates(output or "")
        if not candidates:
            return False

        src_key = (source or "tool").split(":", 1)[0].strip() or "tool"
        for c in candidates:
            self._flag_evidence.setdefault(c, set()).add(src_key)
            self._record_candidate(c, source, "", status="proposed")

        # Prefer format/ctf-like tokens for the visible hint, but never act on them automatically.
        reportable = [
            c for c in candidates
            if (self.flag_format and self._flag_matches_format(c))
            or _prefix_looks_ctf_like(c.split("{", 1)[0])
        ] or candidates
        preview = ", ".join(reportable[:3])
        self._pending_flag_hint = preview
        self.emit("thought", {
            "text": (f"Flag-shaped token(s) detected in {source or 'tool output'}: {preview}. "
                     "NOT auto-submitting — verify by reasoning whether it is the real flag, "
                     "then call submit_flag only if confident."),
            "type": "system",
        })
        for c in reportable[:3]:
            self.emit("flag", {"flag": c, "pending_approval": False,
                               "source": source or "auto-detect", "unverified": True})
        return False
