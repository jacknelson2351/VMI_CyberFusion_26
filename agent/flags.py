"""
FlagsMixin — flag candidate extraction, auto-submit logic, answer-mode helpers.
"""
import base64
import re

from utils import (
    _is_plausible_flag_token, _prefix_looks_ctf_like, _decode_backslash_escapes,
)
from db import update_challenge


class FlagsMixin:

    def _normalize_answer_token(self, token: str) -> str:
        return re.sub(r"\s+", " ", (token or "").strip().lower())

    def _remember_answer_candidate(self, token: str):
        n = self._normalize_answer_token(token)
        if not n:
            return
        self._answer_candidates.add(n)

    def _harvest_answer_candidates(self, text: str):
        if not text:
            return
        blob = _decode_backslash_escapes(text)
        if not blob:
            return

        # IPv4 tokens.
        for m in re.finditer(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", blob):
            tok = m.group(0)
            try:
                octets = [int(x) for x in tok.split(".")]
                if all(0 <= x <= 255 for x in octets):
                    self._remember_answer_candidate(tok)
            except Exception:
                pass

        # Domain-like indicators (exclude obvious PE noise).
        banned = (".dll", ".exe", ".sys", ".pdb", ".obj", ".lib", ".startup", ".part", ".mingw")
        for m in re.finditer(
            r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|xyz|biz|info)\b",
            blob,
            re.IGNORECASE,
        ):
            d = m.group(0).lower().strip(".")
            if d.endswith(banned):
                continue
            self._remember_answer_candidate(d)

        # File type markers from `file` output.
        if re.search(r"\bPE32\+\s+executable\b", blob, re.IGNORECASE):
            self._remember_answer_candidate("PE32+ executable")
            self._remember_answer_candidate("PE32+")
        if re.search(r"\bELF\b", blob):
            self._remember_answer_candidate("ELF")

        # Packer marker.
        if re.search(r"\bUPX[0-9!]*\b", blob, re.IGNORECASE):
            self._remember_answer_candidate("UPX")

    def _allows_noncanonical_submit(self, flag: str, how: str) -> bool:
        if self.allow_nonstandard_submit:
            return True
        if self.flag_format:
            return self._flag_matches_format(flag)
        if not self._answer_mode:
            return False
        f = (flag or "").strip()
        if not f:
            return False
        n = self._normalize_answer_token(f)
        if n in self._answer_candidates:
            return True
        # Accept high-signal direct answers for answer-style challenges.
        if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", f):
            try:
                octets = [int(x) for x in f.split(".")]
                if all(0 <= x <= 255 for x in octets):
                    return True
            except Exception:
                pass
        if re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}", f, re.IGNORECASE):
            return True
        if f.upper() == "UPX":
            return True
        if re.search(r"\bPE32\+\b", f, re.IGNORECASE):
            return True
        return False

    def _flag_matches_format(self, flag: str) -> bool:
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

    def _has_strong_auto_submit_evidence(self, token: str, text: str, src_key: str) -> bool:
        evidence_sources = self._flag_evidence.get(token, set())
        return (
            src_key == "search_flag"
            or (text or "").count(token) >= 2
            or len(evidence_sources) >= 2
        )

    def _choose_auto_submit_candidate(self, candidates: list[str], text: str, src_key: str) -> str | None:
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
            if self._has_strong_auto_submit_evidence(c, text, src_key):
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
        if not self.running:
            return False
        self._harvest_action_hints(output or "")
        candidates = self._extract_flag_candidates(output or "")
        if not candidates:
            return False

        src_key = (source or "tool").split(":", 1)[0].strip() or "tool"
        text = output or ""
        for c in candidates:
            self._flag_evidence.setdefault(c, set()).add(src_key)

        chosen = self._choose_auto_submit_candidate(candidates, text, src_key)
        if not chosen:
            preview = ", ".join(candidates[:3])
            self.emit("thought", {
                "text": f"Low-confidence flag-like token(s) detected, not auto-submitting: {preview}",
                "type": "system",
            })
            return False

        how = f"Auto-detected in {source or 'tool output'}"
        self.emit("thought", {"text": f"Auto-detected flag candidate: {chosen}", "type": "system"})
        return self._finalize_flag_candidate(chosen, how=how, source=source or "auto-detect")
