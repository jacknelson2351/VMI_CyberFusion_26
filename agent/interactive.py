"""
Interactive Agent Tools (IATs) — EnIGMA-style persistent sessions.

The container is driven by `docker exec` (one process per call), so shell/gdb/remote state was
lost between calls: `run_gdb` was batch-only, `remote_interact` opened and closed the socket every
time (breaking stateful services), and `run_command` couldn't hold a cd/env or an exploit REPL.

These tools keep a live process alive inside the container using tmux, so state persists across
calls — a real interactive debugger, a held-open remote connection, and a stateful shell. Output
comes back through the ACI condenser so context stays clean.
"""
from __future__ import annotations

import re
import time

from utils import _shell_quote
from agent.aci import condense, actionable_error


class InteractiveMixin:

    # ── low-level tmux plumbing ──────────────────────────────────────────────
    def _im_state(self) -> dict:
        if not hasattr(self, "_sessions"):
            self._sessions = {}
        return self._sessions

    def _im_ensure_tmux(self):
        if getattr(self, "_tmux_ready", False):
            return
        self.container.run(
            "command -v tmux >/dev/null 2>&1 || "
            "(apt-get update -y >/dev/null 2>&1 && "
            "DEBIAN_FRONTEND=noninteractive apt-get install -y tmux >/dev/null 2>&1) || true"
        )
        self.container.run("mkdir -p /ctf/.sessions")
        self._tmux_ready = True

    def _im_new(self, sid: str, launch: str = "") -> str:
        self._im_ensure_tmux()
        self.container.run(f"tmux kill-session -t {sid} 2>/dev/null || true")
        # -x/-y set a generous virtual terminal so wide output isn't wrapped/lost.
        base = f"tmux new-session -d -s {sid} -x 220 -y 60"
        if launch:
            base += " " + _shell_quote(launch)
        out = self.container.run(base)
        self._im_state()[sid] = {"seq": 0, "launch": launch}
        return out

    def _im_capture(self, sid: str, lines: int = 400) -> str:
        return self.container.run(f"tmux capture-pane -p -t {sid} -S -{int(lines)} 2>/dev/null")

    def _im_alive(self, sid: str) -> bool:
        out = self.container.run(f"tmux has-session -t {sid} 2>&1; echo RC=$?")
        return "RC=0" in (out or "")

    def _im_send_raw(self, sid: str, keys: str):
        # Send a literal line then Enter. `keys` must be pre-sanitized (no embedded quotes we
        # can't control); callers use file-sourcing for arbitrary user commands.
        self.container.run(f'tmux send-keys -t {sid} {_shell_quote(keys)} Enter')

    def _im_run_command(self, sid: str, cmd: str, timeout: int = 30) -> str:
        """Run a shell command in the session, preserving cwd/env, and return its output."""
        st = self._im_state()[sid]
        st["seq"] += 1
        n = st["seq"]
        marker = f"__CTF_DONE_{n}__"
        # Write the command to a file and source it, so cd/exports/vars persist in the session
        # and we never fight shell quoting for arbitrary commands.
        script = f"/ctf/.sessions/{sid}_{n}.sh"
        self.container.write_file(script.replace("/ctf/", ""), cmd + "\n")
        self._im_send_raw(sid, f". {script}; echo {marker} rc=$?")
        deadline = time.time() + max(2, int(timeout))
        pane = ""
        while time.time() < deadline:
            time.sleep(0.4)
            pane = self._im_capture(sid)
            if marker in (pane or ""):
                break
        return self._im_extract(pane, script, marker)

    def _im_extract(self, pane: str, script: str, marker: str) -> str:
        pane = pane or ""
        # Output is between the sourced-script echo line and the marker line.
        lines = pane.splitlines()
        # Find the last occurrence of the marker.
        end = None
        rc = ""
        for i in range(len(lines) - 1, -1, -1):
            if marker in lines[i]:
                end = i
                m = re.search(r"rc=(\d+)", lines[i])
                rc = m.group(1) if m else ""
                break
        if end is None:
            return "[no completion marker — session still running or timed out; use op:read to poll]"
        # Find the matching command echo (the ". <script>" line) above the marker.
        start = 0
        for i in range(end - 1, -1, -1):
            if script in lines[i]:
                start = i + 1
                break
        body = "\n".join(lines[start:end]).strip()
        tail = f"\n[exit {rc}]" if rc not in ("", "0") else ""
        return (body or "(no output)") + tail

    # ── tools ────────────────────────────────────────────────────────────────
    def _tool_shell_session(self, args: dict) -> str:
        op = str(args.get("op") or "run").strip().lower()
        sid = re.sub(r"[^A-Za-z0-9_]", "", str(args.get("session") or "sh_main")) or "sh_main"
        if op == "start" or (op == "run" and not self._im_alive(sid)):
            self._im_new(sid)
            if op == "start":
                self.emit("command", {"cmd": f"shell_session[{sid}]: start"})
                self._last_tool_progress = True
                return f"Started persistent shell session '{sid}'. cwd/env persist across calls."
        if op == "read":
            out = self._im_capture(sid)
            self.emit("command", {"cmd": f"shell_session[{sid}]: read"})
            self.emit("output", {"text": out})
            self._last_tool_progress = False
            return self._truncate_for_context(out)
        if op == "close":
            self.container.run(f"tmux kill-session -t {sid} 2>/dev/null || true")
            self._im_state().pop(sid, None)
            return f"Closed shell session '{sid}'."
        cmd = str(args.get("command") or "").strip()
        if not cmd:
            self._last_tool_progress = False
            return "[tool error] command is required for op:run"
        timeout = max(2, min(int(args.get("timeout") or 30), 120))
        self.emit("command", {"cmd": f"shell_session[{sid}]: {cmd}"})
        out = self._im_run_command(sid, cmd, timeout=timeout)
        self.emit("output", {"text": out})
        self._update_evidence_from_output(f"shell_session: {cmd}", out)
        if self._maybe_auto_submit_from_output(out, source=f"shell_session: {cmd}"):
            self._last_tool_progress = True
            return "Flag auto-submitted from shell session output."
        hint = actionable_error(out)
        self._last_tool_progress = self._score_progress(out)
        return self._truncate_for_context(out) + (f"\n[hint] {hint}" if hint else "")

    def _tool_gdb_session(self, args: dict) -> str:
        op = str(args.get("op") or "send").strip().lower()
        sid = re.sub(r"[^A-Za-z0-9_]", "", str(args.get("session") or "gdb_main")) or "gdb_main"
        if op == "start":
            binary = str(args.get("binary") or "").strip()
            pwndbg = ("PWNDBG=$(ls /usr/share/pwndbg/gdbinit.py /opt/pwndbg/gdbinit.py 2>/dev/null | head -1); "
                      "gdb -q -nx " + (f"{_shell_quote(binary)} " if binary else "") +
                      '${PWNDBG:+-ex "source $PWNDBG"}')
            self._im_new(sid, launch=f"bash -lc {_shell_quote(pwndbg)}")
            time.sleep(1.0)
            out = self._im_capture(sid)
            self.emit("command", {"cmd": f"gdb_session[{sid}]: start {binary}"})
            self.emit("output", {"text": out})
            self._last_tool_progress = True
            return self._truncate_for_context(out) or f"Started gdb session '{sid}'."
        if op == "close":
            self.container.run(f"tmux kill-session -t {sid} 2>/dev/null || true")
            self._im_state().pop(sid, None)
            return f"Closed gdb session '{sid}'."
        if op == "read":
            out = self._im_capture(sid)
            self.emit("output", {"text": out})
            return self._truncate_for_context(out)
        # send
        command = str(args.get("command") or "").strip()
        if not command:
            self._last_tool_progress = False
            return "[tool error] command is required for op:send"
        if not self._im_alive(sid):
            self._last_tool_progress = False
            return f"[tool error] gdb session '{sid}' is not running — start it first (op:start, binary:...)."
        self.emit("command", {"cmd": f"gdb_session[{sid}]: {command}", "gdb": True})
        self._im_send_raw(sid, command)
        time.sleep(max(0.6, min(float(args.get("wait") or 1.2), 8.0)))
        out = self._im_capture(sid)
        self.emit("output", {"text": out})
        self._update_evidence_from_output(f"gdb_session: {command}", out)
        if self._maybe_auto_submit_from_output(out, source=f"gdb_session: {command}"):
            self._last_tool_progress = True
            return "Flag auto-submitted from gdb session output."
        self._last_tool_progress = self._score_progress(out)
        return self._truncate_for_context(out)

    def _tool_remote_session(self, args: dict) -> str:
        op = str(args.get("op") or "send").strip().lower()
        sid = re.sub(r"[^A-Za-z0-9_]", "", str(args.get("session") or "rem_main")) or "rem_main"
        if op == "connect":
            host = str(args.get("host") or "").strip()
            port = str(args.get("port") or "").strip()
            url = str(args.get("url") or "").strip()
            target = self.target if isinstance(self.target, dict) else {}
            if not host and not url:
                host = str(target.get("host") or "").strip()
                port = port or str(target.get("port") or "").strip()
                url = str(target.get("url") or "").strip()
            if url.startswith(("ws://", "wss://")):
                launch = ("bash -lc " + _shell_quote(
                    "python3 -c \"import websocket,sys;ws=websocket.create_connection(sys.argv[1]);"
                    "import code;code.interact(local={'ws':ws})\" " + _shell_quote(url)))
            elif host and port:
                # rlwrap keeps line editing; nc holds the socket open across sends.
                launch = f"bash -lc {_shell_quote(f'nc {host} {port}')}"
            else:
                self._last_tool_progress = False
                return "[tool error] connect needs host+port or a ws/wss url (or a challenge target)."
            self._im_new(sid, launch=launch)
            time.sleep(1.2)
            out = self._im_capture(sid)
            self.emit("command", {"cmd": f"remote_session[{sid}]: connect {host}:{port}{url}"})
            self.emit("output", {"text": out})
            self._update_evidence_from_output("remote_session: connect", out)
            self._last_tool_progress = True
            return self._truncate_for_context(out) or f"Connected remote session '{sid}'."
        if op == "close":
            self.container.run(f"tmux kill-session -t {sid} 2>/dev/null || true")
            self._im_state().pop(sid, None)
            return f"Closed remote session '{sid}'."
        if op == "recv":
            out = self._im_capture(sid)
            self.emit("output", {"text": out})
            return self._truncate_for_context(out)
        # send
        data = args.get("data")
        if data is None:
            self._last_tool_progress = False
            return "[tool error] data is required for op:send"
        if not self._im_alive(sid):
            self._last_tool_progress = False
            return f"[tool error] remote session '{sid}' not connected — connect first."
        self.emit("command", {"cmd": f"remote_session[{sid}]: send {str(data)[:80]}"})
        self._im_send_raw(sid, str(data))
        time.sleep(max(0.5, min(float(args.get("wait") or 1.0), 8.0)))
        out = self._im_capture(sid)
        self.emit("output", {"text": out})
        self._update_evidence_from_output(f"remote_session: send", out)
        if self._maybe_auto_submit_from_output(out, source="remote_session"):
            self._last_tool_progress = True
            return "Flag auto-submitted from remote session output."
        self._last_tool_progress = self._score_progress(out)
        return self._truncate_for_context(out)
