"""
All Flask routes and Socket.IO event handlers.
"""
import json
import os
import re
import secrets
import shutil
import subprocess
import threading
import uuid
from datetime import datetime
from threading import RLock

from flask import jsonify, request, render_template, Response, session, redirect, url_for
from flask_socketio import join_room
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

from extensions import app, socketio
from config import (
    load_config, _as_bool, _canonical_launch_model,
    LAUNCH_MODEL_CHOICES, LAUNCH_MODEL_IDS, UPLOAD_DIR, CONFIG_PATH, BASE_DIR,
)
from db import (
    load_challenges, get_challenge, update_challenge, build_capability_report,
    _db_lock, _load_challenges_unlocked, _save_challenges_unlocked,
)
from docker_mgr import (
    get_container, sync_challenge_uploads, image_exists, get_docker,
    _containers, CONTAINER_PREFIX,
)
from agent import _agents, _logs, _log_event, CTFAgent

WRITEUPS_DIR = BASE_DIR / "writeups"
WRITEUPS_DIR.mkdir(exist_ok=True)
_manual_terminal_lock = RLock()
_manual_terminal_sessions: dict[str, "_ManualTerminalSession"] = {}
_manual_mode_cids: set[str] = set()
_docker_build_state_lock = RLock()
_docker_build_ready = False
_docker_build_in_progress = False
_LOCK_SESSION_KEY = "local_lock_unlocked"
_LOCK_BOOT_KEY = secrets.token_hex(16)


def _trim_text(value: str, limit: int = 260) -> str:
    v = (value or "").strip()
    if len(v) <= limit:
        return v
    return v[:limit] + "..."


def _docker_build_gate() -> tuple[bool, str]:
    global _docker_build_ready
    with _docker_build_state_lock:
        if _docker_build_in_progress:
            return False, "Docker image build in progress. Wait for completion."
    # Source of truth is the actual Docker image presence, not process-local memory.
    has_image = image_exists()
    with _docker_build_state_lock:
        _docker_build_ready = bool(has_image)
    if has_image:
        return True, ""
    return False, "Build the Docker image first before launching the agent."


def _build_writeup_markdown(chal: dict, logs: list[dict], approved_flag: str, validator_notes: str = "") -> str:
    now_iso = datetime.utcnow().isoformat() + "Z"
    name = chal.get("name") or "Untitled Challenge"
    category = (chal.get("category") or "misc").upper()
    description = (chal.get("description") or "").strip()
    cid = chal.get("id") or ""
    note_block = validator_notes.strip() or "No additional validation notes provided."

    def _is_noisy_command(cmd: str) -> bool:
        c = (cmd or "").strip().lower()
        if not c:
            return True
        noisy_prefixes = (
            "[uploads verify]",
            "ls -1 /ctf/",
            "ls -la /ctf/",
            "search_flag:",
        )
        return c.startswith(noisy_prefixes)

    def _step_title_for_command(cmd: str) -> str:
        c = (cmd or "").lower()
        if any(k in c for k in ("file ", "strings ", "xxd ", "hexdump ", "binwalk ", "exiftool ")):
            return "Inspect the challenge artifact"
        if any(k in c for k in ("gunzip", "unzip", "tar ", "7z ", "foremost")):
            return "Extract/decompress the provided files"
        if any(k in c for k in ("grep", "find", "search_flag", "awk", "sed")):
            return "Search for high-signal indicators"
        if any(k in c for k in ("python", "ruby", "perl", "./", "bash ")):
            return "Run the solving script or target binary"
        if any(k in c for k in ("curl", "wget", "ffuf", "sqlmap", "nikto", "gobuster")):
            return "Probe the service/application behavior"
        if any(k in c for k in ("gdb", "rizin", "radare", "objdump", "readelf", "ltrace", "strace")):
            return "Reverse engineer or debug the target"
        return "Execute the next verification step"

    step_pairs: list[tuple[str, str]] = []
    current_cmd = ""
    current_out_parts: list[str] = []
    seen_cmd = set()

    for entry in logs or []:
        ev = entry.get("event")
        data = entry.get("data") or {}
        if ev == "command":
            if current_cmd:
                joined = "\n".join(p for p in current_out_parts if p).strip()
                step_pairs.append((current_cmd, joined))
            current_cmd = (data.get("cmd") or "").strip()
            current_out_parts = []
        elif ev == "output" and current_cmd:
            txt = (data.get("text") or "").strip()
            if txt:
                current_out_parts.append(txt)
    if current_cmd:
        joined = "\n".join(p for p in current_out_parts if p).strip()
        step_pairs.append((current_cmd, joined))

    steps_md = []
    for cmd, out in step_pairs:
        cmd_n = cmd.strip()
        if not cmd_n or _is_noisy_command(cmd_n):
            continue
        cmd_key = cmd_n.lower()
        if cmd_key in seen_cmd:
            continue
        seen_cmd.add(cmd_key)
        title = _step_title_for_command(cmd_n)
        out_preview = _trim_text(out, 380) if out else "No notable output was captured for this step."
        step_num = len(steps_md) + 1
        steps_md.append(
            f"### Step {step_num}: {title}\n"
            f"- Run:\n"
            f"```bash\n{_trim_text(cmd_n, 240)}\n```\n"
            f"- What to look for:\n"
            f"  {_trim_text(out_preview, 360)}\n"
        )
        if len(steps_md) >= 8:
            break

    if not steps_md:
        steps_md = [
            "### Step 1: Start with basic artifact inspection\n"
            "- Run:\n"
            "```bash\nls -lah /ctf/\nfile /ctf/*\n```\n"
            "- What to look for:\n"
            "  Identify the main challenge file(s), then extract/decode/analyze based on file type until the flag appears.\n"
        ]

    steps_block = "\n".join(steps_md)

    return (
        f"# Writeup: {name}\n\n"
        f"## Metadata\n"
        f"- Challenge ID: `{cid}`\n"
        f"- Category: `{category}`\n"
        f"- Approved at: `{now_iso}`\n"
        f"- Final flag: `{approved_flag}`\n\n"
        f"## Challenge Description\n"
        f"{description if description else '_No description was provided._'}\n\n"
        f"## Simple Solve Path\n"
        f"Follow these steps in order. Each step tells you what to run and what signal to confirm before moving on.\n\n"
        f"{steps_block}\n"
        f"## Validation Notes\n"
        f"{note_block}\n\n"
        f"## Outcome\n"
        f"Final approved flag: `{approved_flag}`\n"
        f"The flag candidate was manually validated and approved by the user.\n"
    )


def _open_manual_terminal(container_name: str) -> tuple[bool, str]:
    if not re.fullmatch(r"[a-zA-Z0-9_.-]{3,80}", container_name or ""):
        return False, "unsafe container name"
    docker_cmd = f"docker exec -it {container_name} bash"
    try:
        if os.name == "nt":
            subprocess.Popen([
                "powershell",
                "-NoProfile",
                "-Command",
                f"Start-Process powershell -ArgumentList '-NoExit','-Command','{docker_cmd}'",
            ])
            return True, ""

        # macOS Terminal.app
        if shutil.which("osascript"):
            mac_cmd = docker_cmd.replace("\\", "\\\\").replace('"', '\\"')
            subprocess.Popen([
                "osascript",
                "-e",
                f'tell application "Terminal" to do script "{mac_cmd}"',
                "-e",
                'tell application "Terminal" to activate',
            ])
            return True, ""

        # Linux terminal fallbacks
        linux_candidates = [
            ["x-terminal-emulator", "-e", "bash", "-lc", docker_cmd],
            ["gnome-terminal", "--", "bash", "-lc", docker_cmd],
            ["konsole", "-e", "bash", "-lc", docker_cmd],
            ["xterm", "-e", "bash", "-lc", docker_cmd],
        ]
        for cmd in linux_candidates:
            if shutil.which(cmd[0]):
                subprocess.Popen(cmd)
                return True, ""
        return False, "no supported terminal emulator found"
    except Exception as e:
        return False, str(e)


class _ManualTerminalSession:
    def __init__(self, cid: str, sid: str):
        self.cid = cid
        self.sid = sid
        self.exec_id = ""
        self.sock = None
        self.alive = False
        self._reader = None

    def start(self) -> tuple[bool, str]:
        try:
            container_conn = get_container(self.cid)
            sync_challenge_uploads(self.cid, container_conn)
            api = get_docker().api
            exec_info = api.exec_create(
                container=container_conn.container.id,
                cmd=["/bin/bash"],
                tty=True,
                stdin=True,
                stdout=True,
                stderr=True,
                workdir="/ctf",
                environment={"TERM": "xterm-256color"},
            )
            self.exec_id = exec_info.get("Id", "")
            if not self.exec_id:
                return False, "failed to create exec session"
            self.sock = api.exec_start(self.exec_id, tty=True, stream=False, socket=True)
            self.alive = True
            self._reader = threading.Thread(target=self._pump_output, daemon=True)
            self._reader.start()
            return True, ""
        except Exception as e:
            self.alive = False
            return False, str(e)

    def _pump_output(self):
        try:
            while self.alive and self.sock:
                chunk = self.sock.recv(4096)
                if not chunk:
                    break
                text = chunk.decode("utf-8", errors="replace")
                socketio.emit("manual_terminal_output", {"cid": self.cid, "data": text}, room=self.sid)
        except Exception:
            pass
        finally:
            self.alive = False
            socketio.emit("manual_terminal_exit", {"cid": self.cid}, room=self.sid)

    def write(self, data: str):
        if not self.alive or not self.sock:
            return
        try:
            self.sock.send((data or "").encode("utf-8", errors="ignore"))
        except Exception:
            self.alive = False

    def resize(self, cols: int, rows: int):
        if not self.exec_id:
            return
        try:
            cols = max(20, min(int(cols or 120), 600))
            rows = max(5, min(int(rows or 30), 300))
            get_docker().api.exec_resize(self.exec_id, height=rows, width=cols)
        except Exception:
            pass

    def close(self):
        self.alive = False
        try:
            if self.sock:
                self.sock.close()
        except Exception:
            pass


def _close_manual_terminal_for_sid(sid: str):
    with _manual_terminal_lock:
        sess = _manual_terminal_sessions.pop(sid, None)
    if sess:
        sess.close()


def _lock_enabled(cfg: dict | None = None) -> bool:
    cfg = cfg or load_config()
    return _as_bool(cfg.get("local_lock_enabled"), default=False)


def _lock_hash(cfg: dict | None = None) -> str:
    cfg = cfg or load_config()
    # If security is disabled, treat password as absent even if a stale hash exists.
    if not _lock_enabled(cfg):
        return ""
    return str(cfg.get("local_lock_password_hash") or "")


def _is_unlocked(cfg: dict | None = None) -> bool:
    if not _lock_enabled(cfg):
        return True
    return session.get(_LOCK_SESSION_KEY) == _LOCK_BOOT_KEY


def _set_unlocked(value: bool):
    if value:
        session[_LOCK_SESSION_KEY] = _LOCK_BOOT_KEY
    else:
        session.pop(_LOCK_SESSION_KEY, None)


@app.before_request
def _enforce_local_lock():
    path = request.path or "/"
    if path.startswith("/static/") or path.startswith("/socket.io/") or path.startswith("/api/auth/"):
        return None

    cfg = load_config()
    if not _lock_enabled(cfg):
        return None
    if _is_unlocked(cfg):
        return None

    setup_required = not bool(_lock_hash(cfg))
    if path.startswith("/api/"):
        return jsonify({"error": "locked", "setup_required": setup_required}), 401
    if path == "/":
        return render_template("login.html", setup_required=setup_required)
    return redirect(url_for("index"))


def _with_runtime(chal: dict) -> dict:
    if not chal:
        return chal
    running = False
    if chal["id"] in _agents:
        try:
            running = bool(_agents[chal["id"]].running)
        except Exception:
            running = False
    out = dict(chal)
    out["running"] = running
    return out


# ── Index ──────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    cfg = load_config()
    default_model = _canonical_launch_model(cfg.get("model"))
    if default_model not in LAUNCH_MODEL_IDS:
        default_model = LAUNCH_MODEL_CHOICES[0]["id"]
    return render_template(
        "index.html",
        launch_models=LAUNCH_MODEL_CHOICES,
        default_launch_model=default_model,
    )


@app.route("/manual/<cid>")
def manual_terminal_view(cid):
    chal = get_challenge(cid)
    if not chal:
        return render_template("index.html")
    return render_template("manual_terminal.html", cid=cid, challenge=chal)


# ── Challenges CRUD ────────────────────────────────────────────────────────────

@app.route("/api/challenges", methods=["GET"])
def get_challenges():
    return jsonify([_with_runtime(c) for c in load_challenges()])


@app.route("/api/challenges", methods=["POST"])
def create_challenge():
    data = request.json
    chal = {
        "id":            str(uuid.uuid4())[:8],
        "name":          data.get("name", "Untitled"),
        "category":      data.get("category", "misc"),
        "flag_format":   data.get("flag_format", ""),
        "description":   data.get("description", ""),
        "files":         [],
        "status":        "unsolved",
        "flag":          None,
        "flag_candidate": None,
        "flag_how":      None,
        "approved_at":   None,
        "writeup_md":    None,
        "writeup_path":  None,
        "writeup_ready_at": None,
        "retry_summary": None,
        "created_at":    datetime.now().isoformat(),
        "cost_usd":      0.0,
        "tokens_in":     0,
        "tokens_out":    0,
    }
    with _db_lock:
        chals = _load_challenges_unlocked()
        chals.append(chal)
        _save_challenges_unlocked(chals)
    return jsonify(chal)


@app.route("/api/challenges/<cid>", methods=["GET"])
def get_challenge_route(cid):
    chal = get_challenge(cid)
    if not chal:
        return jsonify({"error": "Not found"}), 404
    return jsonify(_with_runtime(chal))


@app.route("/api/challenges/<cid>/logs", methods=["GET"])
def get_challenge_logs(cid):
    if not get_challenge(cid):
        return jsonify({"error": "Not found"}), 404
    return jsonify(_logs.get(cid, []))


@app.route("/api/challenges/<cid>/manual-start", methods=["POST"])
def manual_start_container(cid):
    chal = get_challenge(cid)
    if not chal:
        return jsonify({"error": "Not found"}), 404
    ok, err = _docker_build_gate()
    if not ok:
        return jsonify({"error": err}), 400
    data = request.get_json(silent=True) or {}
    open_terminal = bool(data.get("open_terminal", True))
    try:
        container = get_container(cid)
        sync_challenge_uploads(cid, container)
        listing = container.run("ls -lah /ctf/ 2>/dev/null || true")
        _manual_mode_cids.add(cid)
    except Exception as e:
        return jsonify({"error": f"Container failed: {e}"}), 500

    container_name = f"{CONTAINER_PREFIX}{cid}"
    terminal_opened = False
    terminal_error = ""
    if open_terminal:
        terminal_opened, terminal_error = _open_manual_terminal(container_name)
    payload = {
        "cid": cid,
        "container_name": container_name,
        "running": True,
        "terminal_opened": terminal_opened,
        "terminal_error": terminal_error,
        "shell_cmd": f"docker exec -it {container_name} bash",
        "watch_cmd": f"docker exec -i {container_name} bash -lc \"tail -n 120 -f /ctf/.agent_live.log\"",
        "combined_hint": "Inside the shell, run: tail -n 120 -f /ctf/.agent_live.log",
        "listing": listing,
        "message": "Manual container session is ready. Agent launch is optional.",
        "challenge": {
            "name": chal.get("name", ""),
            "category": chal.get("category", ""),
            "description": chal.get("description", ""),
            "files": chal.get("files", []) or [],
        },
    }
    return jsonify(payload)


@app.route("/api/challenges/<cid>/manual-cli/run", methods=["POST"])
def manual_cli_run(cid):
    chal = get_challenge(cid)
    if not chal:
        return jsonify({"error": "Not found"}), 404
    ok, err = _docker_build_gate()
    if not ok:
        return jsonify({"error": err}), 400
    data = request.get_json(force=True) or {}
    command = str(data.get("command") or "").strip()
    timeout = int(data.get("timeout") or 90)
    timeout = max(1, min(timeout, 300))
    if not command:
        return jsonify({"error": "Command is required."}), 400

    try:
        container = get_container(cid)
        sync_challenge_uploads(cid, container)
        out = container.run(command, timeout=timeout)
    except Exception as e:
        return jsonify({"error": f"Execution failed: {e}"}), 500

    return jsonify({
        "ok": True,
        "cid": cid,
        "command": command,
        "timeout": timeout,
        "output": out,
    })


@app.route("/api/challenges/<cid>", methods=["PUT"])
def update_challenge_route(cid):
    data = request.json
    update_challenge(cid, **data)
    return jsonify(get_challenge(cid))


@app.route("/api/challenges/<cid>/approve-flag", methods=["POST"])
def approve_flag_route(cid):
    chal = get_challenge(cid)
    if not chal:
        return jsonify({"error": "Not found"}), 404

    data = request.get_json(force=True) or {}
    approved = bool(data.get("approved"))
    candidate = (data.get("flag") or chal.get("flag_candidate") or "").strip()
    notes = (data.get("notes") or "").strip()

    if not candidate:
        return jsonify({"error": "No candidate flag available for approval."}), 400

    if not approved:
        update_challenge(
            cid,
            status="unsolved",
            flag=None,
            flag_candidate=None,
            flag_how=None,
            approved_at=None,
            writeup_md=None,
            writeup_path=None,
            writeup_ready_at=None,
        )
        payload = {
            "cid": cid,
            "status": "unsolved",
            "message": "Flag candidate rejected. Challenge reverted to unsolved.",
        }
        socketio.emit("flag_rejected", payload, room=cid)
        socketio.emit("done", payload, room=cid)
        _log_event(cid, "flag_rejected", payload)
        _log_event(cid, "done", payload)
        return jsonify(get_challenge(cid))

    logs = _logs.get(cid, [])
    writeup_md = _build_writeup_markdown(chal, logs, candidate, validator_notes=notes)
    writeup_file = WRITEUPS_DIR / f"{cid}.md"
    writeup_file.write_text(writeup_md, encoding="utf-8")
    rel_path = str(writeup_file.relative_to(BASE_DIR)).replace("\\", "/")
    approved_at = datetime.utcnow().isoformat() + "Z"

    update_challenge(
        cid,
        status="solved",
        flag=candidate,
        flag_candidate=candidate,
        approved_at=approved_at,
        writeup_md=writeup_md,
        writeup_path=rel_path,
        writeup_ready_at=approved_at,
    )
    payload = {
        "cid": cid,
        "status": "solved",
        "flag": candidate,
        "writeup_path": rel_path,
        "message": "Flag approved. Markdown writeup generated.",
    }

    # Challenge is complete; stop any live agent/container to free resources.
    try:
        if cid in _agents:
            try:
                _agents[cid].stop()
            except Exception:
                pass
            _agents.pop(cid, None)
        if cid in _containers:
            try:
                _containers[cid].stop()
            except Exception:
                pass
            _containers.pop(cid, None)
        _manual_mode_cids.discard(cid)
    except Exception:
        pass

    socketio.emit("flag_approved", payload, room=cid)
    socketio.emit("done", payload, room=cid)
    _log_event(cid, "flag_approved", payload)
    _log_event(cid, "done", payload)
    return jsonify(get_challenge(cid))


@app.route("/api/challenges/<cid>/writeup", methods=["GET"])
def get_writeup_route(cid):
    chal = get_challenge(cid)
    if not chal:
        return jsonify({"error": "Not found"}), 404
    writeup_md = chal.get("writeup_md") or ""
    return jsonify({
        "cid": cid,
        "ready": bool(writeup_md),
        "markdown": writeup_md,
        "path": chal.get("writeup_path"),
    })


@app.route("/api/challenges/<cid>/writeup.md", methods=["GET"])
def download_writeup_route(cid):
    chal = get_challenge(cid)
    if not chal:
        return jsonify({"error": "Not found"}), 404
    writeup_md = chal.get("writeup_md") or ""
    if not writeup_md.strip():
        return jsonify({"error": "Writeup not generated yet."}), 404
    return Response(
        writeup_md,
        mimetype="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{cid}_writeup.md"'},
    )


@app.route("/api/challenges/<cid>", methods=["DELETE"])
def delete_challenge(cid):
    chal = get_challenge(cid)
    if cid in _containers:
        threading.Thread(target=_containers[cid].stop, daemon=True).start()
        del _containers[cid]
    if cid in _agents:
        _agents[cid].stop()
        del _agents[cid]
    _manual_mode_cids.discard(cid)
    with _db_lock:
        chals = [c for c in _load_challenges_unlocked() if c["id"] != cid]
        _save_challenges_unlocked(chals)
    try:
        if chal and chal.get("writeup_path"):
            wp = BASE_DIR / str(chal.get("writeup_path")).replace("/", os.sep)
            if wp.exists():
                wp.unlink()
    except Exception:
        pass
    return jsonify({"ok": True})


# ── File upload ────────────────────────────────────────────────────────────────

@app.route("/api/challenges/<cid>/upload", methods=["POST"])
def upload_file(cid):
    chal = get_challenge(cid)
    if not chal:
        return jsonify({"error": "Challenge not found"}), 404

    if "file" not in request.files:
        return jsonify({"error": "No file"}), 400

    f     = request.files["file"]
    fname = secure_filename(f.filename)
    if not fname:
        return jsonify({"error": "Invalid filename"}), 400

    # Use per-challenge subdirectory to prevent filename collisions across challenges
    chal_upload_dir = UPLOAD_DIR / cid
    chal_upload_dir.mkdir(exist_ok=True)
    local = chal_upload_dir / fname
    f.save(str(local))

    files = chal.get("files", [])
    if fname not in files:
        files.append(fname)
    update_challenge(cid, files=files)

    # Do not auto-start containers on upload. Only sync if a challenge container is already running.
    try:
        if cid in _containers and _containers[cid].running:
            container = _containers[cid]
            remote = container.upload_file(str(local))
            listing = container.run("ls -lh /ctf/")
            socketio.emit("file_uploaded", {"name": fname, "listing": listing}, room=cid)
            return jsonify({"ok": True, "name": fname, "remote": remote, "listing": listing})
        return jsonify({"ok": True, "name": fname, "stored": True, "synced": False})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Agent control ──────────────────────────────────────────────────────────────

@app.route("/api/challenges/<cid>/launch", methods=["POST"])
def launch_agent(cid):
    data  = request.json or {}
    retry = data.get("retry", False)
    model = _canonical_launch_model(data.get("model"))
    if model and model not in LAUNCH_MODEL_IDS:
        return jsonify({
            "error": f"Unsupported model: {model}. Choose one of: {', '.join(m['label'] for m in LAUNCH_MODEL_CHOICES)}"
        }), 400
    chal  = get_challenge(cid)
    if not chal:
        return jsonify({"error": "Not found"}), 404
    ok, err = _docker_build_gate()
    if not ok:
        return jsonify({"error": err}), 400

    if cid in _agents and _agents[cid].running:
        return jsonify({"error": "Agent already running"}), 400

    try:
        container = get_container(cid)
        sync_challenge_uploads(cid, container)
        _manual_mode_cids.discard(cid)
    except Exception as e:
        return jsonify({"error": f"Container failed: {e}"}), 500

    flag_fmt  = chal.get("flag_format", "")
    extra     = data.get("extra_context", "")
    full_desc = (
        f"Challenge: {chal['name']}\n"
        f"Category: {chal['category'].upper()}\n"
        f"Working directory: /ctf/\n"
        + (f"Flag format: {flag_fmt}\n" if flag_fmt else "")
        + (f"\n{chal.get('description', '')}\n" if chal.get("description") else "")
        + (f"\nAdditional context: {extra}\n" if extra else "")
    )

    prior = chal.get("retry_summary") if retry else None
    update_challenge(
        cid,
        status="solving",
        flag_candidate=None,
        flag_how=None,
        approved_at=None,
        writeup_md=None,
        writeup_path=None,
        writeup_ready_at=None,
    )

    synced_files = []
    chal_upload_dir = UPLOAD_DIR / cid
    if chal_upload_dir.exists():
        synced_files = sorted([p.name for p in chal_upload_dir.iterdir() if p.is_file()])
    if not synced_files:
        synced_files = list(chal.get("files") or [])

    container_listing = container.run("ls -1 /ctf/ 2>/dev/null || true")
    container_entries = [ln.strip() for ln in (container_listing or "").splitlines() if ln.strip()]
    container_set = set(container_entries)

    if synced_files:
        present = [f for f in synced_files if f in container_set]
        missing = [f for f in synced_files if f not in container_set]
        present_preview = ", ".join(present[:8]) if present else "none"
        if len(present) > 8:
            present_preview += ", ..."
        if missing:
            missing_preview = ", ".join(missing[:8])
            if len(missing) > 8:
                missing_preview += ", ..."
            upload_msg = (
                f"[uploads verify] /ctf visibility FAIL ({len(present)}/{len(synced_files)} visible). "
                f"present: {present_preview}; missing: {missing_preview}"
            )
        else:
            upload_msg = (
                f"[uploads verify] /ctf visibility OK ({len(present)}/{len(synced_files)} visible): "
                f"{present_preview}"
            )
        if container_entries:
            sample = ", ".join(container_entries[:8])
            if len(container_entries) > 8:
                sample += ", ..."
            upload_msg += f" | /ctf sample: {sample}"
    else:
        upload_msg = "[uploads verify] no uploaded files yet."
    upload_payload = {"cid": cid, "cmd": upload_msg, "notice": True}
    socketio.emit("command", upload_payload, room=cid)
    _log_event(cid, "command", upload_payload)

    agent = CTFAgent(
        cid,
        chal.get("category", "misc"),
        container,
        room=cid,
        flag_format=chal.get("flag_format", ""),
        model=model or None,
        challenge_name=chal.get("name", ""),
        challenge_description=chal.get("description", ""),
        base_tokens_in=chal.get("tokens_in", 0),
        base_tokens_out=chal.get("tokens_out", 0),
        base_cost_usd=chal.get("cost_usd", 0.0),
    )
    _agents[cid] = agent
    agent.start(full_desc, prior_summary=prior)

    return jsonify({"ok": True})


@app.route("/api/challenges/<cid>/stop", methods=["POST"])
def stop_agent(cid):
    if cid in _agents:
        _agents[cid].stop()
        del _agents[cid]
    if cid in _containers:
        threading.Thread(target=_containers[cid].stop, daemon=True).start()
        del _containers[cid]
    _manual_mode_cids.discard(cid)
    update_challenge(
        cid,
        status="unsolved",
        flag_candidate=None,
        flag_how=None,
    )
    socketio.emit("done", {"cid": cid, "status": "unsolved", "message": "Stopped by user."}, room=cid)
    return jsonify({"ok": True})


@app.route("/api/challenges/<cid>/reset", methods=["POST"])
def reset_container(cid):
    if cid in _agents:
        _agents[cid].stop()
    if cid in _containers:
        _containers[cid].stop()
        del _containers[cid]
    _manual_mode_cids.discard(cid)
    update_challenge(
        cid,
        status="unsolved",
        flag=None,
        flag_candidate=None,
        flag_how=None,
        approved_at=None,
        writeup_md=None,
        writeup_path=None,
        writeup_ready_at=None,
        retry_summary=None,
    )
    try:
        wp = WRITEUPS_DIR / f"{cid}.md"
        if wp.exists():
            wp.unlink()
    except Exception:
        pass
    return jsonify({"ok": True})


@app.route("/api/reset-all", methods=["POST"])
def reset_all():
    # Stop all tracked agents.
    for cid, agent in list(_agents.items()):
        try:
            agent.stop()
        except Exception:
            pass
        _agents.pop(cid, None)

    # Stop all tracked containers.
    for cid, container in list(_containers.items()):
        try:
            container.stop()
        except Exception:
            pass
        _containers.pop(cid, None)

    # Best-effort cleanup for any leftover containers from prior runs.
    try:
        client = get_docker()
        leftovers = client.containers.list(all=True, filters={"name": CONTAINER_PREFIX})
        for c in leftovers:
            try:
                c.remove(force=True)
            except Exception:
                pass
    except Exception:
        pass

    # Clear in-memory logs and persisted challenges.
    _logs.clear()
    _manual_mode_cids.clear()
    with _db_lock:
        _save_challenges_unlocked([])

    # Remove all uploaded files for all challenges.
    try:
        for p in UPLOAD_DIR.iterdir():
            if p.is_dir():
                shutil.rmtree(p, ignore_errors=True)
            else:
                try:
                    p.unlink()
                except FileNotFoundError:
                    pass
    except FileNotFoundError:
        pass
    UPLOAD_DIR.mkdir(exist_ok=True)
    try:
        if WRITEUPS_DIR.exists():
            for p in WRITEUPS_DIR.iterdir():
                if p.is_file():
                    p.unlink()
    except Exception:
        pass

    return jsonify({"ok": True})


@app.route("/api/evaluation/summary", methods=["GET"])
def evaluation_summary():
    return jsonify(build_capability_report())


# ── Config API ─────────────────────────────────────────────────────────────────

@app.route("/api/auth/status", methods=["GET"])
def auth_status():
    cfg = load_config()
    enabled = _lock_enabled(cfg)
    has_password = bool(_lock_hash(cfg))
    return jsonify({
        "enabled": enabled,
        "unlocked": _is_unlocked(cfg),
        "setup_required": bool(enabled and not has_password),
    })


@app.route("/api/auth/setup", methods=["POST"])
def auth_setup():
    data = request.get_json(force=True) or {}
    password = (data.get("password") or "").strip()
    confirm = (data.get("confirm_password") or "").strip()
    if len(password) < 4:
        return jsonify({"error": "Password must be at least 4 characters."}), 400
    if password != confirm:
        return jsonify({"error": "Passwords do not match."}), 400

    with _db_lock:
        cfg = load_config() if CONFIG_PATH.exists() else {}
        if not _lock_enabled(cfg):
            return jsonify({"error": "Local lock is disabled."}), 400
        if _lock_hash(cfg):
            return jsonify({"error": "Password already configured."}), 400
        cfg["local_lock_password_hash"] = generate_password_hash(password)
        tmp = CONFIG_PATH.with_name(CONFIG_PATH.name + ".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
        os.replace(tmp, CONFIG_PATH)

    _set_unlocked(True)
    return jsonify({"ok": True})


@app.route("/api/auth/unlock", methods=["POST"])
def auth_unlock():
    cfg = load_config()
    if not _lock_enabled(cfg):
        _set_unlocked(True)
        return jsonify({"ok": True, "enabled": False})

    pw_hash = _lock_hash(cfg)
    if not pw_hash:
        return jsonify({"error": "Password setup required.", "setup_required": True}), 400

    data = request.get_json(force=True) or {}
    password = (data.get("password") or "").strip()
    if not password or not check_password_hash(pw_hash, password):
        return jsonify({"error": "Invalid password."}), 401

    _set_unlocked(True)
    return jsonify({"ok": True, "enabled": True})


@app.route("/api/auth/lock", methods=["POST"])
def auth_lock():
    _set_unlocked(False)
    return jsonify({"ok": True})


def _mask_key(key: str) -> str:
    """Return a safe display version of an API key."""
    if not key:
        return ""
    if len(key) <= 12:
        return "•" * len(key)
    return key[:10] + "…" + key[-4:]


@app.route("/api/config", methods=["GET"])
def get_config_api():
    cfg = load_config()
    oai = cfg.get("openai_api_key") or ""
    ant = cfg.get("anthropic_api_key") or ""
    return jsonify({
        "openai_api_key_set":       bool(oai),
        "openai_api_key_masked":    _mask_key(oai),
        "anthropic_api_key_set":    bool(ant),
        "anthropic_api_key_masked": _mask_key(ant),
        "model":                    cfg.get("model") or "gpt-5-mini",
        "local_lock_enabled":       _lock_enabled(cfg),
        "local_lock_password_set":  bool(_lock_hash(cfg)),
    })


@app.route("/api/config", methods=["POST"])
def save_config_api():
    data = request.get_json(force=True) or {}
    with _db_lock:
        cfg = load_config() if CONFIG_PATH.exists() else {}
        new_oai = (data.get("openai_api_key") or "").strip()
        new_ant = (data.get("anthropic_api_key") or "").strip()
        if data.get("clear_openai"):
            cfg.pop("openai_api_key", None)
        elif new_oai:
            cfg["openai_api_key"] = new_oai
        if data.get("clear_anthropic"):
            cfg.pop("anthropic_api_key", None)
        elif new_ant:
            cfg["anthropic_api_key"] = new_ant
        new_model = (data.get("model") or "").strip()
        if new_model:
            cfg["model"] = new_model

        current_pw = (data.get("current_password") or "").strip()
        new_pw = (data.get("new_password") or "").strip()
        confirm_pw = (data.get("confirm_password") or "").strip()
        has_existing = bool(_lock_hash(cfg))

        requested_enabled = data.get("local_lock_enabled", None)
        if requested_enabled is None:
            lock_enabled = _lock_enabled(cfg)
        else:
            lock_enabled = _as_bool(requested_enabled, default=False)

        wants_pw_change = bool(new_pw or confirm_pw)
        if wants_pw_change:
            if new_pw != confirm_pw:
                return jsonify({"error": "New password and confirmation do not match."}), 400
            if len(new_pw) < 4:
                return jsonify({"error": "New password must be at least 4 characters."}), 400

        if has_existing and (wants_pw_change or (requested_enabled is not None and not lock_enabled)):
            if not current_pw or not check_password_hash(_lock_hash(cfg), current_pw):
                return jsonify({"error": "Current password is incorrect."}), 403

        if lock_enabled and (not has_existing) and (not wants_pw_change):
            return jsonify({"error": "Set a password before enabling local lock."}), 400

        if wants_pw_change:
            cfg["local_lock_password_hash"] = generate_password_hash(new_pw)

        if requested_enabled is not None:
            cfg["local_lock_enabled"] = bool(lock_enabled)
            if not lock_enabled:
                # Easier reset flow: disabling security clears the stored lock password.
                cfg.pop("local_lock_password_hash", None)

        tmp = CONFIG_PATH.with_name(CONFIG_PATH.name + ".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
        os.replace(tmp, CONFIG_PATH)
    # Keep this session usable after a successful settings/security update.
    # Otherwise enabling security can immediately lock subsequent UI API calls.
    _set_unlocked(True)
    return jsonify({"ok": True})


# ── Docker management ──────────────────────────────────────────────────────────

@app.route("/api/docker/status", methods=["GET"])
def docker_status():
    try:
        get_docker().ping()
        has_image = image_exists()
        with _docker_build_state_lock:
            build_ready = bool(_docker_build_ready)
            build_in_progress = bool(_docker_build_in_progress)
        running_agents = sum(1 for a in _agents.values() if getattr(a, "running", False))
        docker_cids: set[str] = set()
        try:
            for c in get_docker().containers.list(all=False, filters={"name": CONTAINER_PREFIX}):
                name = getattr(c, "name", "") or ""
                if name.startswith(CONTAINER_PREFIX):
                    docker_cids.add(name[len(CONTAINER_PREFIX):])
        except Exception:
            pass
        tracked_cids = {cid for cid, conn in _containers.items() if getattr(conn, "running", False)}
        running_containers = len(docker_cids | tracked_cids)
        return jsonify({
            "running": True,
            "image": has_image,
            "build_ready": build_ready,
            "build_in_progress": build_in_progress,
            "active_agents": running_agents,
            "active_containers": running_containers,
        })
    except Exception as e:
        return jsonify({
            "running": False,
            "error": str(e),
            "build_ready": False,
            "build_in_progress": False,
            "active_agents": 0,
            "active_containers": 0,
        })


@app.route("/api/docker/containers", methods=["GET"])
def docker_containers():
    try:
        get_docker().ping()
        all_challenges = {c["id"]: c for c in load_challenges()}
        rows = []
        for c in get_docker().containers.list(all=False, filters={"name": CONTAINER_PREFIX}):
            name = getattr(c, "name", "") or ""
            if not name.startswith(CONTAINER_PREFIX):
                continue
            cid = name[len(CONTAINER_PREFIX):]
            chal = all_challenges.get(cid, {})
            agent_running = bool(cid in _agents and getattr(_agents[cid], "running", False))
            rows.append({
                "cid": cid,
                "container_name": name,
                "status": getattr(c, "status", "unknown"),
                "challenge_name": chal.get("name") or "(deleted challenge)",
                "category": (chal.get("category") or "").upper(),
                "challenge_status": chal.get("status") or "unknown",
                "agent_running": agent_running,
                "manual_session": cid in _manual_mode_cids,
            })
        rows.sort(key=lambda r: (0 if r["status"] == "running" else 1, r["challenge_name"].lower(), r["cid"]))
        return jsonify({"containers": rows})
    except Exception as e:
        return jsonify({"error": str(e), "containers": []}), 500


@app.route("/api/challenges/<cid>/kill-container", methods=["POST"])
def kill_challenge_container(cid):
    chal = get_challenge(cid)
    if not chal:
        return jsonify({"error": "Challenge not found"}), 404

    _manual_mode_cids.discard(cid)
    if cid in _agents:
        try:
            _agents[cid].stop()
        except Exception:
            pass
        _agents.pop(cid, None)

    killed = False
    if cid in _containers:
        try:
            _containers[cid].stop()
            killed = True
        except Exception:
            pass
        _containers.pop(cid, None)

    if not killed:
        try:
            name = f"{CONTAINER_PREFIX}{cid}"
            cont = get_docker().containers.get(name)
            cont.remove(force=True)
            killed = True
        except Exception:
            pass

    if chal.get("status") == "solving":
        update_challenge(cid, status="unsolved")
        socketio.emit("done", {"cid": cid, "status": "unsolved", "message": "Container killed from Settings."}, room=cid)
    else:
        socketio.emit("command", {"cid": cid, "cmd": "[manual] Container killed from Settings.", "notice": True}, room=cid)

    return jsonify({"ok": True, "killed": killed, "cid": cid})


@app.route("/api/docker/build", methods=["POST"])
def build_image():
    from docker_mgr import IMAGE_NAME
    def _build():
        global _docker_build_ready, _docker_build_in_progress
        try:
            socketio.emit("build_log", {"line": "Starting build...", "done": False})
            client = get_docker()
            for log in client.api.build(
                path=str(BASE_DIR),
                tag=IMAGE_NAME,
                rm=True,
                platform="linux/amd64",
                decode=True,
            ):
                if "stream" in log:
                    line = log["stream"].strip()
                    if line:
                        socketio.emit("build_log", {"line": line, "done": False})
                elif "error" in log:
                    with _docker_build_state_lock:
                        _docker_build_ready = False
                        _docker_build_in_progress = False
                    socketio.emit("build_log", {"line": f"ERROR: {log['error']}", "done": True, "error": True})
                    return
            with _docker_build_state_lock:
                _docker_build_ready = True
                _docker_build_in_progress = False
            socketio.emit("build_log", {"line": "Image built successfully.", "done": True, "error": False})
        except Exception as e:
            with _docker_build_state_lock:
                _docker_build_ready = False
                _docker_build_in_progress = False
            socketio.emit("build_log", {"line": f"Build failed: {e}", "done": True, "error": True})

    global _docker_build_ready, _docker_build_in_progress
    with _docker_build_state_lock:
        _docker_build_ready = False
        _docker_build_in_progress = True
    threading.Thread(target=_build, daemon=True).start()
    return jsonify({"ok": True})

# ── Socket.IO — join challenge room for real-time updates ──────────────────────

@socketio.on("join")
def on_join(data):
    cid = data.get("cid")
    if cid:
        join_room(cid)


@socketio.on("manual_terminal_open")
def on_manual_terminal_open(data):
    cid = (data or {}).get("cid")
    if not cid:
        socketio.emit("manual_terminal_error", {"error": "missing challenge id"}, room=request.sid)
        return
    if not get_challenge(cid):
        socketio.emit("manual_terminal_error", {"error": "challenge not found"}, room=request.sid)
        return

    _close_manual_terminal_for_sid(request.sid)
    sess = _ManualTerminalSession(cid=cid, sid=request.sid)
    ok, err = sess.start()
    if not ok:
        socketio.emit("manual_terminal_error", {"cid": cid, "error": err or "failed to open terminal"}, room=request.sid)
        return

    cols = int((data or {}).get("cols") or 120)
    rows = int((data or {}).get("rows") or 32)
    sess.resize(cols, rows)
    with _manual_terminal_lock:
        _manual_terminal_sessions[request.sid] = sess
    socketio.emit("manual_terminal_ready", {"cid": cid}, room=request.sid)


@socketio.on("manual_terminal_input")
def on_manual_terminal_input(data):
    payload = data or {}
    text = payload.get("data")
    if text is None:
        return
    with _manual_terminal_lock:
        sess = _manual_terminal_sessions.get(request.sid)
    if not sess:
        return
    sess.write(str(text))


@socketio.on("manual_terminal_resize")
def on_manual_terminal_resize(data):
    payload = data or {}
    cols = int(payload.get("cols") or 120)
    rows = int(payload.get("rows") or 32)
    with _manual_terminal_lock:
        sess = _manual_terminal_sessions.get(request.sid)
    if not sess:
        return
    sess.resize(cols, rows)


@socketio.on("manual_terminal_close")
def on_manual_terminal_close(_data=None):
    _close_manual_terminal_for_sid(request.sid)


@socketio.on("disconnect")
def on_disconnect():
    _close_manual_terminal_for_sid(request.sid)
