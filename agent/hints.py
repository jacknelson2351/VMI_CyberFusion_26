"""
HintsMixin — credential/tool-directive harvesting and hint-driven actions.
"""
import re

from utils import _shell_quote
class HintsMixin:

    # Tools whose name appearing as a key in "tool:value" output constitutes an immediate directive.
    _DIRECTIVE_TOOLS = {
        "steghide", "john", "hashcat", "openssl", "gpg", "zip", "unzip",
        "7z", "ssh", "ftp", "mysql", "password", "pass", "passphrase", "key", "secret",
    }

    # Common English words / error-message fragments that should never be treated as credentials.
    _DIRECTIVE_BLOCKLIST = frozenset({
        "could", "not", "error", "failed", "invalid", "none", "null", "true", "false",
        "data", "that", "with", "this", "from", "file", "path", "name", "type",
        "any", "the", "and", "for", "have", "been", "will", "more", "into", "any",
        "extract", "passphrase", "using", "write", "read", "open", "close",
    })

    def _store_hint(self, key: str, value: str):
        k = (key or "").strip().lower()
        v = (value or "").strip()
        if not k or not v:
            return
        bucket = self._hint_map.setdefault(k, set())
        before = len(bucket)
        vals = {v}
        for dec in self._recursive_decode_strings(v, max_rounds=3):
            d = (dec or "").strip()
            if d:
                vals.add(d)
        bucket.update(vals)
        if len(bucket) > before:
            self._hint_map_version = getattr(self, "_hint_map_version", 0) + 1

    def _output_too_noisy_for_hint_decode(self, text: str) -> bool:
        sample = (text or "")[:12000]
        if not sample:
            return False
        if "\x00" in sample:
            return True
        nonprint = sum(1 for ch in sample if ch not in "\n\r\t" and (ord(ch) < 32 or ord(ch) == 127))
        if nonprint / max(1, len(sample)) > 0.08:
            return True
        dense_tokens = re.findall(
            r"\b(?:[0-9A-Fa-f]{32,}|[A-Za-z0-9+/]{64,}={0,2})\b",
            sample,
        )
        if len(dense_tokens) > 80:
            return True
        hex_tokens = re.findall(r"\b[0-9A-Fa-f]{8,}\b", sample)
        if len(sample) > 3000 and (len(dense_tokens) > 25 or len(hex_tokens) > 120):
            hex_chars = sum(1 for ch in sample if ch in "0123456789abcdefABCDEF")
            if hex_chars / max(1, len(sample)) > 0.55:
                return True
        return False

    def _harvest_action_hints(self, output: str):
        text = output or ""
        if not text:
            return
        if self._output_too_noisy_for_hint_decode(text):
            return
        decoded_pool = self._recursive_decode_strings(text, max_rounds=4)
        for blob in decoded_pool:
            # Generic key:value hints (tool/password/token/etc.).
            for m in re.finditer(r"\b([a-zA-Z][a-zA-Z0-9_.-]{1,20})\s*:\s*([^\s]{2,120})", blob):
                key = m.group(1)
                val = m.group(2)
                self._store_hint(key, val)
            # Password-like mentions.
            for m in re.finditer(r"(?i)\b(?:password|pass|pwd|key|passphrase)\b\s*[=:]\s*([^\s]{2,120})", blob):
                self._store_hint("password", m.group(1))

    def _inject_directive(self, tool: str, raw_value: str, source: str = ""):
        # Disabled: metadata/output-derived urgent directives caused false pivots.
        return

    def _try_hint_actions(self) -> bool:
        if self._running_hint_action or not self.running:
            return False
        # Only run expensive hint actions when new credentials were harvested this turn.
        current_version = getattr(self, "_hint_map_version", 0)
        if current_version == getattr(self, "_hint_map_last_version", -1):
            return False
        self._hint_map_last_version = current_version
        passwords = set()
        passwords |= self._hint_map.get("password", set())
        passwords |= self._hint_map.get("pass", set())
        passwords |= self._hint_map.get("pwd", set())
        passwords |= self._hint_map.get("key", set())
        passwords |= self._hint_map.get("passphrase", set())
        if "steghide" in self._hint_map:
            passwords |= self._hint_map.get("steghide", set())
        # Expand with recursively decoded variants for layered encodings.
        expanded = set(passwords)
        for p in list(passwords):
            for dec in self._recursive_decode_strings(p, max_rounds=3):
                d = (dec or "").strip()
                if d and d != p:
                    expanded.add(d)
        passwords = expanded
        # Remove non-password-y tokens.
        passwords = {p for p in passwords if 2 <= len(p) <= 120 and ":" not in p and "\n" not in p}
        if not passwords:
            return False

        self._running_hint_action = True
        try:
            listing = self.container.run("find /ctf -maxdepth 2 -type f | sort")
            files = [ln.strip() for ln in (listing or "").splitlines() if ln.strip()]
            any_progress = False

            # Resolve all passwords: base64-encoded values are fully decoded before use.
            resolved_passwords = set()
            for pw in passwords:
                resolved_passwords.add(pw)  # always keep original
                if re.fullmatch(r'[A-Za-z0-9+/]{8,}={0,2}', pw):
                    # Looks like base64 — fully decode and add the plaintext form.
                    for d in self._recursive_decode_strings(pw, max_rounds=4):
                        d = (d or "").strip()
                        if (d and d != pw and 2 <= len(d) <= 120
                                and ":" not in d and "\n" not in d
                                and d.lower() not in self._DIRECTIVE_BLOCKLIST):
                            try:
                                d.encode("ascii")
                                resolved_passwords.add(d)
                            except Exception:
                                pass
            passwords = resolved_passwords

            def _check_flag(out: str, source: str) -> bool:
                """Flag-only check used inside hint actions.
                Deliberately does NOT call _harvest_action_hints so that tool error
                messages (e.g. 'steghide: could not extract...') don't generate false
                directive injections."""
                if not out or not self.running:
                    return False
                candidates = self._extract_flag_candidates(out)
                if not candidates:
                    return False
                src_key = (source or "tool").split(":", 1)[0].strip() or "tool"
                for c in candidates:
                    self._flag_evidence.setdefault(c, set()).add(src_key)
                    self._record_candidate(c, source, "", status="proposed")
                # Surface only — the model must reason and submit_flag; never auto-halt from a
                # hint-action regex hit. Record the finding as durable evidence so the model sees it.
                preview = ", ".join(candidates[:3])
                self._pending_flag_hint = preview
                if self.memory:
                    self.memory.add_confirmed(f"Hint action ({source}) produced flag-shaped token(s): {preview} — verify before submitting.")
                self.emit("thought", {
                    "text": f"Hint-action flag-shaped token(s): {preview}. Verify and submit_flag only if confident.",
                    "type": "system",
                })
                for c in candidates[:3]:
                    self.emit("flag", {"flag": c, "pending_approval": False,
                                       "source": source, "unverified": True})
                return False

            # ── Steghide: JPG/BMP/WAV/AU carriers ────────────────────────────────
            carriers = [f for f in files if re.search(r"\.(jpg|jpeg|bmp|wav|au)$", f, re.IGNORECASE)]
            for carrier in carriers[:10]:
                for pw in sorted(resolved_passwords)[:30]:
                    key = ("steghide", carrier, pw)
                    if key in self._hint_attempted:
                        continue
                    self._hint_attempted.add(key)
                    self.emit("thought", {"text": f"Hint-driven: steghide on {carrier} credential='{pw[:20]}'.", "type": "system"})
                    out = self.container.run(
                        f"steghide extract -sf {_shell_quote(carrier)} -p {_shell_quote(pw)} -f 2>&1",
                        timeout=60,
                    )
                    self.emit("output", {"text": out})
                    if _check_flag(out, source=f"steghide:{carrier}"):
                        return True
                    if out and re.search(r"wrote extracted data to|extracted", out, re.IGNORECASE):
                        any_progress = True
                        scan = self.container.run(
                            "grep -rE '[A-Za-z0-9_]{2,24}\\{[^{}\\n]{1,220}\\}' /ctf 2>/dev/null | head -40",
                            timeout=60,
                        )
                        self.emit("output", {"text": scan})
                        if _check_flag(scan, source="post-steghide-scan"):
                            return True

            # ── ZIP archives ──────────────────────────────────────────────────────
            zip_files = [f for f in files if re.search(r"\.(zip)$", f, re.IGNORECASE)]
            for zf in zip_files[:5]:
                for pw in sorted(resolved_passwords)[:30]:
                    key = ("zip", zf, pw)
                    if key in self._hint_attempted:
                        continue
                    self._hint_attempted.add(key)
                    self.emit("thought", {"text": f"Hint-driven: unzip {zf} credential='{pw[:20]}'.", "type": "system"})
                    out = self.container.run(
                        f"unzip -P {_shell_quote(pw)} -o {_shell_quote(zf)} -d /ctf/zip_extracted/ 2>&1",
                        timeout=60,
                    )
                    self.emit("output", {"text": out})
                    if _check_flag(out, source=f"zip:{zf}"):
                        return True
                    if out and re.search(r"inflating|extracting", out, re.IGNORECASE):
                        any_progress = True
                        scan = self.container.run(
                            "grep -rE '[A-Za-z0-9_]{2,24}\\{[^{}\\n]{1,220}\\}' /ctf/zip_extracted/ 2>/dev/null | head -40",
                            timeout=60,
                        )
                        self.emit("output", {"text": scan})
                        if _check_flag(scan, source="post-zip-scan"):
                            return True

            # ── OpenSSL encrypted files ───────────────────────────────────────────
            enc_files = [f for f in files if re.search(r"\.(enc|aes|des|crypt)$", f, re.IGNORECASE)]
            for ef in enc_files[:5]:
                for pw in sorted(resolved_passwords)[:15]:
                    key = ("openssl", ef, pw)
                    if key in self._hint_attempted:
                        continue
                    self._hint_attempted.add(key)
                    self.emit("thought", {"text": f"Hint-driven: openssl decrypt {ef}.", "type": "system"})
                    out_path = ef + ".dec"
                    out = self.container.run(
                        f"openssl enc -d -aes-256-cbc -pbkdf2 -pass pass:{_shell_quote(pw)} -in {_shell_quote(ef)} -out {_shell_quote(out_path)} 2>&1 && strings {_shell_quote(out_path)} | head -20",
                        timeout=30,
                    )
                    self.emit("output", {"text": out})
                    if _check_flag(out, source=f"openssl:{ef}"):
                        return True
                    if out and not re.search(r"error|bad decrypt|wrong", out, re.IGNORECASE):
                        any_progress = True

            return any_progress
        finally:
            self._running_hint_action = False
