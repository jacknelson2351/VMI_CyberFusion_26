"""
Web-pentest toolkit (Spec D).

First-class, parsed web tools so the agent stops shelling raw ffuf/sqlmap and drowning in
progress bars. Output is condensed via the ACI layer. Tools default their target to the
challenge target URL and feed results through evidence + flag extraction like other tools.
"""
from __future__ import annotations

import json
import re

from utils import _shell_quote
from agent.aci import condense, actionable_error


# ── pure parsers (unit-tested) ────────────────────────────────────────────────
def parse_ffuf_json(raw: str) -> list[dict]:
    """Parse a ffuf `-of json` document into a sorted list of hits."""
    try:
        doc = json.loads(raw)
    except Exception:
        return []
    results = doc.get("results") or []
    hits = []
    for r in results:
        hits.append({
            "input": (r.get("input") or {}).get("FUZZ") or r.get("input") or "",
            "url": r.get("url") or "",
            "status": r.get("status"),
            "length": r.get("length"),
            "words": r.get("words"),
        })
    # Interesting first: 200s, then 3xx, then 401/403, by descending length.
    def rank(h):
        s = h.get("status") or 0
        pri = 0 if s == 200 else (1 if 300 <= s < 400 else (2 if s in (401, 403) else 3))
        return (pri, -(h.get("length") or 0))
    return sorted(hits, key=rank)


def format_ffuf_hits(hits: list[dict], limit: int = 40) -> str:
    if not hits:
        return "No matches."
    lines = [f"{h['status']:>3}  len={h.get('length')}  words={h.get('words')}  {h['url'] or h['input']}"
             for h in hits[:limit]]
    extra = f"\n(+{len(hits) - limit} more)" if len(hits) > limit else ""
    return "\n".join(lines) + extra


def summarize_headers(raw: str) -> str:
    """Pull the notable lines from a raw HTTP header blob."""
    notable = re.compile(
        r"^(HTTP/|Server:|X-Powered-By:|Set-Cookie:|Location:|Content-Type:|"
        r"WWW-Authenticate:|Content-Security-Policy:|X-Backend|Via:|X-Flag)",
        re.IGNORECASE,
    )
    out = [ln.strip() for ln in (raw or "").splitlines() if notable.match(ln.strip())]
    return "\n".join(out) if out else "(no notable headers)"


def parse_sqlmap(raw: str) -> dict:
    """Distil a sqlmap transcript into a verdict."""
    t = raw or ""
    injectable = bool(re.search(r"is vulnerable|appears to be .*injectable|Parameter: .* \(", t, re.IGNORECASE))
    param = None
    m = re.search(r"Parameter:\s*([^\s(]+)", t)
    if m:
        param = m.group(1)
    techniques = re.findall(r"Type:\s*(.+)", t)
    dbs = []
    mdb = re.search(r"available databases \[\d+\]:(.+?)(?:\n\n|\Z)", t, re.DOTALL)
    if mdb:
        dbs = re.findall(r"\[\*\]\s*(.+)", mdb.group(1))
    return {
        "injectable": injectable,
        "parameter": param,
        "techniques": [x.strip() for x in techniques],
        "databases": [d.strip() for d in dbs],
    }


def format_sqlmap_verdict(v: dict) -> str:
    if not v.get("injectable"):
        return "sqlmap: no injection detected with these settings. Try higher --level/--risk, a different parameter, or POST data."
    parts = ["sqlmap: INJECTABLE"]
    if v.get("parameter"):
        parts.append(f"parameter={v['parameter']}")
    if v.get("techniques"):
        parts.append("techniques=" + " | ".join(v["techniques"][:4]))
    if v.get("databases"):
        parts.append("databases=" + ", ".join(v["databases"]))
    return "; ".join(parts)


_COMMON_PATHS = ["/admin", "/login", "/api", "/flag", "/flag.txt", "/.git/HEAD",
                 "/.env", "/robots.txt", "/backup", "/backup.zip", "/index.php.bak"]


class WebToolsMixin:

    def _web_target_url(self, args: dict) -> str:
        url = str(args.get("url") or "").strip()
        if url:
            return url
        target = self.target if isinstance(self.target, dict) else {}
        u = str(target.get("url") or "").strip()
        if u:
            return u
        host = str(target.get("host") or "").strip()
        port = str(target.get("port") or "").strip()
        if host:
            scheme = "https" if port in ("443", "8443") else "http"
            return f"{scheme}://{host}" + (f":{port}" if port and port not in ("80", "443") else "")
        return ""

    def _tool_web_recon(self, args: dict) -> str:
        url = self._web_target_url(args)
        if not url:
            self._last_tool_progress = False
            return "[tool error] no url and no challenge target set."
        self.emit("command", {"cmd": f"web_recon {url}"})
        base = url.rstrip("/")
        headers = self.container.run(f"curl -sS -m 15 -D - -o /dev/null {_shell_quote(base + '/')} 2>&1", timeout=25)
        whatweb = self.container.run(f"whatweb -a3 --color=never {_shell_quote(base)} 2>&1 | head -40", timeout=40)
        robots = self.container.run(f"curl -sS -m 10 {_shell_quote(base + '/robots.txt')} 2>&1 | head -30", timeout=15)
        # Probe common interesting paths for their status code.
        probe_cmd = "; ".join(
            f"printf '%s ' {_shell_quote(p)}; curl -sS -o /dev/null -m 8 -w '%{{http_code}}\\n' {_shell_quote(base + p)}"
            for p in _COMMON_PATHS
        )
        probes = self.container.run(probe_cmd, timeout=90)
        interesting = [ln for ln in (probes or "").splitlines()
                       if ln.strip() and not ln.strip().endswith(("000", "404"))]
        out = (
            f"# Headers\n{summarize_headers(headers)}\n\n"
            f"# whatweb\n{(whatweb or '').strip()}\n\n"
            f"# robots.txt\n{(robots or '').strip() or '(none)'}\n\n"
            f"# Probe paths (non-404)\n" + ("\n".join(interesting) if interesting else "(none of the common paths existed)")
        )
        self.emit("output", {"text": out})
        self._update_evidence_from_output(f"web_recon: {url}", out)
        if self._maybe_auto_submit_from_output(out, source=f"web_recon: {url}"):
            self._last_tool_progress = True
            return "Flag auto-submitted from web_recon output."
        self._last_tool_progress = True
        return condense(out, limit=self.tool_context_limit)

    def _tool_web_fuzz(self, args: dict) -> str:
        url = self._web_target_url(args)
        if not url:
            self._last_tool_progress = False
            return "[tool error] no url and no challenge target set."
        mode = str(args.get("mode") or "dir").strip().lower()
        wordlist = str(args.get("wordlist") or "").strip() or (
            "/usr/share/seclists/Discovery/Web-Content/common.txt"
            if mode in ("dir", "param") else
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
        )
        codes = str(args.get("match_codes") or "200,204,301,302,307,401,403").strip()
        base = url.rstrip("/")
        if mode == "vhost":
            target = f"-u {_shell_quote(base)} -H {_shell_quote('Host: FUZZ.' + re.sub(r'^https?://', '', base))}"
        elif mode == "param":
            sep = "&" if "?" in base else "?"
            target = f"-u {_shell_quote(base + sep + 'FUZZ=1')}"
        else:  # dir
            target = f"-u {_shell_quote(base + '/FUZZ')}"
        # Fallback wordlist if the preferred one is absent.
        outfile = "/ctf/.artifacts/ffuf.json"
        cmd = (
            f"WL={_shell_quote(wordlist)}; "
            f"[ -f \"$WL\" ] || WL=/usr/share/wordlists/dirb/common.txt; "
            f"mkdir -p /ctf/.artifacts; "
            f"ffuf {target} -w \"$WL\" -mc {_shell_quote(codes)} -ac -t 40 -s "
            f"-of json -o {outfile} >/dev/null 2>&1; cat {outfile} 2>/dev/null"
        )
        self.emit("command", {"cmd": f"web_fuzz[{mode}] {base}"})
        raw = self.container.run(cmd, timeout=int(args.get("timeout") or 120))
        hint = actionable_error(raw)
        hits = parse_ffuf_json(raw)
        out = f"web_fuzz {mode} on {base} — {len(hits)} hits\n" + format_ffuf_hits(hits)
        if hint and not hits:
            out += f"\n[hint] {hint}"
        self.emit("output", {"text": out})
        self._update_evidence_from_output(f"web_fuzz: {base}", out)
        self._last_tool_progress = bool(hits)
        return condense(out, limit=self.tool_context_limit)

    def _tool_sql_test(self, args: dict) -> str:
        url = self._web_target_url(args)
        if not url:
            self._last_tool_progress = False
            return "[tool error] no url and no challenge target set."
        action = str(args.get("action") or "detect").strip().lower()
        level = max(1, min(int(args.get("level") or 2), 5))
        risk = max(1, min(int(args.get("risk") or 2), 3))
        data = str(args.get("data") or "").strip()
        param = str(args.get("param") or "").strip()
        flags = f"--batch --level={level} --risk={risk} -u {_shell_quote(url)}"
        if data:
            flags += f" --data={_shell_quote(data)}"
        if param:
            flags += f" -p {_shell_quote(param)}"
        if action == "dbs":
            flags += " --dbs"
        elif action == "tables":
            flags += " --tables"
        elif action == "dump":
            flags += " --dump --threads=4"
        self.emit("command", {"cmd": f"sql_test[{action}] {url}"})
        raw = self.container.run(f"sqlmap {flags} --flush-session 2>&1", timeout=int(args.get("timeout") or 240))
        verdict = parse_sqlmap(raw)
        summary = format_sqlmap_verdict(verdict)
        out = summary + "\n\n# sqlmap output (condensed)\n" + condense(raw, limit=2000)
        self.emit("output", {"text": out})
        self._update_evidence_from_output(f"sql_test: {url}", out)
        if self._maybe_auto_submit_from_output(raw, source=f"sql_test: {url}"):
            self._last_tool_progress = True
            return "Flag auto-submitted from sql_test output."
        self._last_tool_progress = verdict.get("injectable", False)
        return condense(out, limit=self.tool_context_limit)
