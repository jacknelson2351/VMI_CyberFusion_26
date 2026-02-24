"""
CommandsMixin — command dedup, family classification, tooling install helpers.
"""
import re

from prompts import (
    CATEGORY_TOOL_CHECKS, TOOL_APT_PACKAGES,
    TOOL_INSTALL_COMMANDS, SYSTEM_TOOL_INSTALLERS,
)
from utils import _shell_quote
from pricing import _infer_pip_package


class CommandsMixin:

    def _normalize_command(self, cmd: str) -> str:
        return re.sub(r"\s+", " ", (cmd or "").strip())

    def _is_repeated_command(self, cmd: str) -> bool:
        if not cmd:
            return False
        # Block exact repeats after one prior attempt; keeps turns high-signal.
        if sum(1 for c in self._recent_cmds if c == cmd) < 1:
            return False
        # Allow repeats if the last run errored (likely fix-and-retry).
        status = self._last_cmd_status.get(cmd)
        if status and status.get("error"):
            return False
        return True

    def _effective_shell_segment(self, cmd: str) -> str:
        c = (cmd or "").strip()
        if not c:
            return ""
        segments = re.split(r"\s*(?:&&|;|\n)\s*", c)
        wrappers = {"cd", "export", "set", "source", "true", ":"}
        for seg in segments:
            s = (seg or "").strip()
            if not s:
                continue
            tok = s.split()[0].lower()
            if tok in wrappers:
                continue
            return s
        return c

    def _token_from_segment(self, segment: str) -> str:
        s = (segment or "").strip()
        if not s:
            return ""
        parts = s.split()
        i = 0
        while i < len(parts):
            t = parts[i].lower()
            if t in {"env", "command", "stdbuf", "nohup"}:
                i += 1
                continue
            if t == "timeout":
                i += 1
                if i < len(parts) and re.fullmatch(r"\d+[smhd]?", parts[i], re.IGNORECASE):
                    i += 1
                continue
            break
        return (parts[i].lower() if i < len(parts) else "")

    def _is_family_block_exempt(self, family: str) -> bool:
        if self.category == "web":
            return False
        essential = {
            "cd", "ls", "pwd", "file", "cat", "head", "tail", "grep", "egrep", "sed", "awk",
            "strings", "python", "python3", "perl", "xxd", "objdump", "readelf", "rabin2",
            "upx", "unzip", "7z", "hexdump", "binwalk",
        }
        return family in essential

    def _command_family(self, cmd: str) -> str:
        c = (cmd or "").strip()
        if not c:
            return "unknown"
        first = self._effective_shell_segment(c)
        token = self._token_from_segment(first)
        t = (token or "").lower()
        low = first.lower()

        # Use semantic command families for web work so anti-loop budgets trigger on
        # tactic repetition, not just exact command text.
        if self.category == "web":
            if t in {"ffuf", "gobuster", "feroxbuster", "dirsearch"}:
                return "web:fuzz"
            if t == "sqlmap":
                return "web:sqli-auto"
            if t == "curl":
                if re.search(r"/upload|upload\.php|-f\s+|--form|multipart/form-data|image=@", low):
                    return "web:upload-check"
                if "php://filter" in low or "../" in low or "%2e%2e" in low:
                    return "web:traversal-check"
                if re.search(r"\?(?:file|page|path|include|inc|template|view|img|image|src|doc|name)=", low):
                    return "web:lfi-check"
                if re.search(r"/robots\.txt|/sitemap\.xml|/\.git/|/admin\b|/api\b", low):
                    return "web:recon-endpoints"
                return "web:curl-generic"
            if t in {"python", "python3"} and ("http://" in low or "https://" in low or "requests" in low):
                return "web:http-script"
        return t or "unknown"

    def _hypothesis_key(self, reasoning: str, family: str, cmd: str) -> str:
        # For web, bind hypothesis budgets to tactic families to prevent endpoint/param
        # spray from escaping budget checks via tiny reasoning text changes.
        if self.category == "web":
            return family or self._command_family(cmd)
        r = re.sub(r"\s+", " ", (reasoning or "").strip().lower())
        generic = {
            "",
            "running command",
            "running command.",
            "run command",
            "run command.",
            "executing command",
            "executing command.",
        }
        if r in generic:
            sig = self._normalize_command(cmd).lower()
            sig = re.sub(r"[^a-z0-9 _./:+-]", "", sig)
            sig = sig[:80] or "cmd"
            return f"{family}:{sig}"
        if r:
            r = re.sub(r"[^a-z0-9 _-]", "", r)
            return (r[:80] or family or "unknown")
        return family or self._command_family(cmd)

    def _fingerprint_output(self, text: str) -> str:
        if not text:
            return ""
        s = text
        if self.category == "web":
            # Normalize volatile HTTP headers so repeated default pages collapse to the
            # same fingerprint and are counted as non-progress.
            s = re.sub(r"(?im)^Date:\s+.*$", "Date:<redacted>", s)
            s = re.sub(r"(?im)^ETag:\s+.*$", "ETag:<redacted>", s)
            s = re.sub(r"(?im)^Last-Modified:\s+.*$", "Last-Modified:<redacted>", s)
            s = re.sub(r"(?im)^Content-Length:\s+\d+$", "Content-Length:<n>", s)
        # Normalize whitespace and noise while preserving semantic differences.
        s = re.sub(r"\s+", " ", s.strip())
        return s[:600]

    def _score_progress(self, output: str) -> bool:
        out = output or ""
        if not out.strip():
            return False
        if self._extract_flag_candidates(out):
            return True
        if self._is_error_result(out):
            return False
        fp = self._fingerprint_output(out)
        if not fp:
            return False
        if self.category == "web":
            low_signal_web = bool(re.search(
                r"HTTP/\d(?:\.\d)?\s+404\b|HTTP/\d(?:\.\d)?\s+403\b|"
                r"<title>\s*404\s+Not\s+Found\s*</title>|"
                r"<title>\s*403\s+Forbidden\s*</title>|"
                r"The requested URL was not found on this server|"
                r"You don't have permission to access this resource",
                out,
                re.IGNORECASE,
            ))
            has_high_value_web_signal = bool(re.search(
                r"Successfully uploaded|Access it at:|Set-Cookie:|Location:|"
                r"Content-Disposition:|multipart/form-data|php://filter|"
                r"root:x:|/etc/passwd|flag\{|picoctf\{|include\(",
                out,
                re.IGNORECASE,
            ))
            # Treat default 404/403 style responses as no progress unless they carry
            # a concrete exploit signal.
            if low_signal_web and not has_high_value_web_signal:
                self._seen_output_fingerprints.add(fp)
                return False
        if fp in self._seen_output_fingerprints:
            return False
        self._seen_output_fingerprints.add(fp)
        return True

    def _is_error_result(self, text: str) -> bool:
        if not text:
            return False
        return bool(re.search(
            r"\[tool error\]|\[exec error:|Traceback|ModuleNotFoundError|No such file or directory|command not found|\berror:|\[error\]",
            text,
            re.IGNORECASE,
        ))

    def _extract_missing_command(self, output: str) -> str:
        if not output:
            return ""
        patterns = [
            r"bash:\s*line\s*\d+:\s*([a-zA-Z0-9_.+-]+):\s*command not found",
            r"/bin/sh:\s*\d+:\s*([a-zA-Z0-9_.+-]+):\s*not found",
            r"([a-zA-Z0-9_.+-]+):\s*command not found",
        ]
        for pat in patterns:
            m = re.search(pat, output, re.IGNORECASE)
            if m:
                return (m.group(1) or "").strip()
        return ""

    def _maybe_install_and_retry_missing_tool(self, tool: str, cmd_to_run: str, timeout: int) -> str | None:
        if not self.allow_runtime_installs:
            return None
        tool = (tool or "").strip()
        if not tool or tool in self._install_attempted_tools:
            return None
        self._install_attempted_tools.add(tool)

        installer = SYSTEM_TOOL_INSTALLERS.get(tool)
        if not installer:
            if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9+_.-]{0,63}$", tool):
                return None
            installer = f"DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends {tool}"

        self.emit("thought", {"text": f"Missing tool '{tool}'. Installing from internet and retrying once.", "type": "system"})
        self.container.run("apt-get update -y >/dev/null 2>&1 || true", timeout=120)
        self.container.run(installer + " >/dev/null 2>&1 || true", timeout=180)
        self.emit("command", {"cmd": f"[retry after install] {tool}"})
        return self.container.run(cmd_to_run, timeout=timeout)

    def _ensure_tooling_ready(self):
        if self._tool_preflight_done or not self.running:
            return
        self._tool_preflight_done = True
        checks = CATEGORY_TOOL_CHECKS.get(self.category, [])
        if not checks:
            return

        missing = []
        missing_custom = []
        for tool in checks:
            out = self.container.run(f"command -v {tool} >/dev/null 2>&1 && echo OK || echo MISSING")
            if "MISSING" in out:
                if tool in TOOL_INSTALL_COMMANDS:
                    missing_custom.append(tool)
                else:
                    missing.append(tool)

        if (missing or missing_custom) and not self.allow_runtime_installs:
            all_missing = sorted(set(missing + missing_custom))
            self._preflight_missing_tools = all_missing
            self.emit("thought", {
                "text": "Tool preflight: missing tools detected but runtime installs are disabled by policy: "
                        + ", ".join(all_missing),
                "type": "system",
            })
            return
        self._preflight_missing_tools = []

        if missing:
            pkgs = sorted({TOOL_APT_PACKAGES.get(t, t) for t in missing})
            self.emit("thought", {"text": f"Tool preflight: installing missing tools: {', '.join(pkgs)}", "type": "system"})
            self.container.run("apt-get update -y >/dev/null 2>&1 || true", timeout=120)
            self.container.run(
                "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "
                + " ".join(_shell_quote(p) for p in pkgs)
                + " >/dev/null 2>&1 || true",
                timeout=180,
            )
        for tool in missing_custom:
            self.emit("thought", {"text": f"Tool preflight: installing {tool}", "type": "system"})
            self.container.run(TOOL_INSTALL_COMMANDS[tool] + " >/dev/null 2>&1 || true", timeout=180)

        # Binwalk frequently breaks due to capstone ABI mismatch; self-heal if detected.
        if "binwalk" in checks:
            probe = self.container.run(
                "python3 - <<'PY'\n"
                "import capstone\n"
                "print('OK' if hasattr(capstone, 'CS_ARCH_ARM64') else 'BAD')\n"
                "PY"
            )
            if "BAD" in (probe or ""):
                self.emit("thought", {"text": "Tool preflight: repairing capstone compatibility for binwalk.", "type": "system"})
                self.container.run(
                    "python3 -m pip -q install --break-system-packages --ignore-installed 'capstone<6' || true",
                    timeout=120,
                )
