"""
EvidenceMixin — lightweight evidence tracking derived from observed tool output.
"""
import re

from utils import _is_high_signal_evidence_text


class EvidenceMixin:

    def _add_evidence(self, bucket: str, note: str):
        text = str(note or "").strip()
        if not text:
            return
        target = self._evidence_confirmed if bucket == "confirmed" else self._evidence_ruled_out
        if text in target:
            return
        target.append(text)
        cap = 30
        overflow = len(target) - cap
        if overflow > 0:
            if bucket == "confirmed":
                idx = 0
                while overflow > 0 and idx < len(target):
                    if not _is_high_signal_evidence_text(target[idx]):
                        del target[idx]
                        overflow -= 1
                    else:
                        idx += 1
            if overflow > 0:
                del target[:overflow]
        self._evidence_version += 1

    def _evidence_summary(self) -> str:
        confirmed = "; ".join(self._evidence_confirmed[-5:]) or "none yet"
        ruled_out = "; ".join(self._evidence_ruled_out[-5:]) or "none yet"
        next_h = self._next_hypothesis or "unset"
        return (
            f"[EVIDENCE]\n"
            f"Confirmed: {confirmed}\n"
            f"Ruled out: {ruled_out}\n"
            f"Next hypothesis: {next_h}\n"
        )

    def _forensics_playbook_hint(self, recon: str) -> str:
        if self.category != "forensics":
            return ""
        if not recon:
            return ""
        return (
            "\n[FORENSICS PLAYBOOK]\n"
            "Prioritize decoding, metadata, extraction, and targeted scans before writing custom scripts.\n"
        )

    def _run_forensics_fastpath(self, recon: str) -> bool:
        return False

    def _run_rev_qna_fastpath(self, recon: str, challenge_desc: str) -> str:
        return ""

    def _update_evidence_from_output(self, cmd: str, output: str):
        out = output or ""
        if not out:
            return
        if "command not found" in out.lower():
            miss = self._extract_missing_command(out)
            if miss:
                self._add_evidence("ruled_out", f"Tool missing: {miss}")
        if "No such file or directory" in out:
            self._add_evidence("ruled_out", f"Path failure in command: {cmd[:80]}")
        if re.search(r"Traceback|ModuleNotFoundError|\[tool error\]|\[error\]", out, re.IGNORECASE):
            first = out.strip().splitlines()[0] if out.strip() else "Tool error"
            self._add_evidence("ruled_out", first[:220])
        for line in out.splitlines()[:80]:
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("/ctf/") and ":" in stripped:
                self._add_evidence("confirmed", stripped[:220])
            if re.search(r"\b(?:http|https)://", stripped, re.IGNORECASE):
                self._add_evidence("confirmed", stripped[:220])
            if re.search(r"\b(?:status|header|cookie|saved_to|final_url)\b", stripped, re.IGNORECASE):
                self._add_evidence("confirmed", stripped[:220])
            # File type magic from `file` command
            if re.search(r":\s+(?:ELF|PE32|Mach-O|JPEG|PNG|ZIP|PDF|Python|ASCII text|gzip|bzip2|RAR|7-zip)\b", stripped):
                self._add_evidence("confirmed", stripped[:220])
            # Security properties from checksec / pwndbg
            if re.search(r"(?:NX|PIE|Canary|RELRO)(?:\s+found|:\s+(?:enabled|disabled|partial|full|no)\b)", stripped, re.IGNORECASE):
                self._add_evidence("confirmed", stripped[:220])
            # Crypto / hash algorithm identifiers
            if re.search(r"\b(?:AES|RSA|DES3?|XOR|MD5|SHA-?(?:1|256|512)|bcrypt|ECDSA|Fernet|ChaCha)\b", stripped, re.IGNORECASE) and len(stripped) < 140:
                self._add_evidence("confirmed", stripped[:140])
        for cand in self._extract_flag_candidates(out):
            self._add_evidence("confirmed", f"Flag-like token observed: {cand}")
