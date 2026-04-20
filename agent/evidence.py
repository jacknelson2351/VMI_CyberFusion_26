"""
EvidenceMixin — lightweight evidence tracking derived from observed tool output.
"""
import re


class EvidenceMixin:

    def _add_evidence(self, bucket: str, note: str):
        text = str(note or "").strip()
        if not text:
            return
        target = self._evidence_confirmed if bucket == "confirmed" else self._evidence_ruled_out
        if text in target:
            return
        target.append(text)
        if len(target) > 20:
            del target[:len(target) - 20]
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
        for cand in self._extract_flag_candidates(out):
            self._add_evidence("confirmed", f"Flag-like token observed: {cand}")
