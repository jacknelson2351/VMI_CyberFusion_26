"""
All Flask routes and Socket.IO event handlers.
"""
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import threading
import uuid
import importlib.util
from datetime import datetime
from threading import RLock

from flask import jsonify, request, render_template, Response, session, redirect, url_for, send_file
from flask_socketio import join_room
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

from extensions import app, socketio
from config import (
    load_config, _as_bool, _canonical_launch_model, _is_anthropic_model,
    LAUNCH_MODEL_CHOICES, LAUNCH_MODEL_IDS, CONFIG_PATH, BASE_DIR,
    PROVIDER_PRESETS,
)
import providers
from prompts import CATEGORY_TOOL_CHECKS
from agent.graph import StateGraph
from db import (
    load_challenges, get_challenge, update_challenge, build_capability_report,
    save_challenges, _db_lock, _load_challenges_unlocked, _save_challenges_unlocked,
    list_challenge_sets, activate_challenge_set, create_challenge_set,
    rename_challenge_set, delete_challenge_set,
)
from docker_mgr import (
    get_container, sync_challenge_uploads, image_exists, get_docker,
    force_remove_container, _containers, CONTAINER_PREFIX,
)
from agent import _agents, _logs, _log_event, _load_log_events, CTFAgent
from storage import (
    apply_challenge_defaults,
    append_note,
    clear_memory_files,
    challenge_events_path,
    challenge_memory_dir,
    challenge_memory_file_path,
    challenge_notes_path,
    challenge_workspace_dir,
    enrich_target,
    delete_memory_file,
    ensure_memory_files,
    list_memory_files,
    normalize_import_payload,
    read_memory_file,
    read_notes,
    remove_challenge_artifacts,
    utc_now_iso,
    workspace_listing,
    write_memory_file,
    write_workspace_manifest,
)

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


def _provider_slug(spec) -> str:
    """Short provider slug for UI logos (openai / anthropic / shannon / openrouter / google / other)."""
    ref = (getattr(spec, "api_key_ref", "") or "").lower()
    url = (getattr(spec, "base_url", "") or "").lower()
    mid = (getattr(spec, "model_id", "") or "").lower()
    name = (getattr(spec, "name", "") or "").lower()
    hay = f"{ref} {url} {mid} {name}"
    if spec.provider_kind == "anthropic" or "anthropic" in hay or mid.startswith("claude"):
        return "anthropic"
    for slug in ("shannon", "openrouter", "deepinfra", "together", "groq", "mistral", "google", "gemini"):
        if slug in hay:
            return "gemini" if slug == "gemini" else slug
    if "openai" in hay or mid.startswith(("gpt", "o1", "o3", "o4", "chatgpt")):
        return "openai"
    return "other"


def _registry_launch_models(cfg: dict | None = None) -> list[dict]:
    """Launch-dropdown choices sourced from the provider registry. Falls back to the
    static LAUNCH_MODEL_CHOICES only if the registry is somehow empty."""
    cfg = cfg or load_config()
    specs = providers.list_models(cfg)
    if not specs:
        return list(LAUNCH_MODEL_CHOICES)
    out = []
    for s in specs:
        price = f" · ${s.pricing[0]:g}/${s.pricing[1]:g}" if s.pricing else ""
        key_note = "" if s.has_key else " · no key"
        out.append({
            "id": s.id,
            "label": f"{s.name}{price}{key_note}",
            "name": s.name,
            "provider": _provider_slug(s),
            "price_in": s.pricing[0] if s.pricing else None,
            "price_out": s.pricing[1] if s.pricing else None,
            "has_key": s.has_key,
            "vision": bool((s.caps or {}).get("vision", False)),
        })
    return out


def _default_launch_model() -> str:
    cfg = load_config()
    roles = cfg.get("roles") or {}
    solver = providers.resolve_role(cfg, "solver")
    if solver:
        return solver.id
    default_model = _canonical_launch_model(cfg.get("solver_model") or cfg.get("model"))
    if default_model not in LAUNCH_MODEL_IDS:
        default_model = LAUNCH_MODEL_CHOICES[0]["id"]
    return default_model


def _challenge_payload(chal: dict | None) -> dict | None:
    if not chal:
        return None
    out = _with_runtime(apply_challenge_defaults(chal))
    out["workspace_path"] = str(challenge_workspace_dir(out["id"]))
    out["notes_path"] = str(challenge_notes_path(out["id"]))
    out["memory_path"] = str(challenge_memory_dir(out["id"]))
    out["memory_files"] = list_memory_files(out["id"])
    out["workspace_files"] = workspace_listing(out["id"], max_depth=3)
    return out


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


def _agent_readiness_report(model: str, category: str = "misc", container=None) -> dict:
    cfg = load_config()
    resolved_model = _canonical_launch_model(model) or cfg.get("model") or "gpt-5-mini"
    provider = "anthropic" if _is_anthropic_model(resolved_model) else "openai"
    checks = []
    errors = []
    warnings = []

    def add_check(name: str, ok: bool, message: str, level: str = "error"):
        row = {"name": name, "ok": bool(ok), "message": message, "level": level}
        checks.append(row)
        if not ok and level == "error":
            errors.append(message)
        elif not ok:
            warnings.append(message)

    add_check("langgraph", StateGraph is not None, "LangGraph is installed." if StateGraph is not None else "LangGraph is missing. Run pip install -r requirements.txt.")

    if provider == "anthropic":
        has_key = bool(cfg.get("anthropic_api_key") or os.environ.get("ANTHROPIC_API_KEY"))
        has_pkg = importlib.util.find_spec("anthropic") is not None
        add_check("anthropic_key", has_key, "Anthropic key configured." if has_key else "Anthropic model selected but no Anthropic key is configured.")
        add_check("anthropic_package", has_pkg, "Anthropic package installed." if has_pkg else "Anthropic package missing. Run pip install -r requirements.txt.")
    else:
        has_key = bool(cfg.get("openai_api_key") or os.environ.get("OPENAI_API_KEY"))
        has_pkg = importlib.util.find_spec("openai") is not None
        add_check("openai_key", has_key, "OpenAI key configured." if has_key else "OpenAI model selected but no OpenAI key is configured.")
        add_check("openai_package", has_pkg, "OpenAI package installed." if has_pkg else "OpenAI package missing. Run pip install -r requirements.txt.")

    missing_tools = []
    if container is not None:
        for tool in CATEGORY_TOOL_CHECKS.get((category or "misc").lower(), []):
            try:
                out = container.run(f"command -v {tool} >/dev/null 2>&1 && echo OK || echo MISSING", timeout=10)
            except Exception:
                out = "MISSING"
            if "MISSING" in (out or ""):
                missing_tools.append(tool)
        if missing_tools:
            install_policy = _as_bool(cfg.get("allow_runtime_installs"), default=False)
            msg = "Missing container tools: " + ", ".join(sorted(set(missing_tools)))
            if install_policy:
                msg += " (runtime installs enabled)."
            else:
                msg += " (runtime installs disabled)."
            add_check("container_tools", False, msg, level="warning")
        else:
            add_check("container_tools", True, "Required category tools are available.", level="warning")

    return {
        "ok": not errors,
        "model": resolved_model,
        "provider": provider,
        "checks": checks,
        "errors": errors,
        "warnings": warnings,
        "missing_tools": missing_tools,
    }


def _emit_readiness_trace(cid: str, readiness: dict, broadcast: bool = True):
    summary = "Ready"
    if readiness.get("errors"):
        summary = "; ".join(readiness.get("errors") or [])
    elif readiness.get("warnings"):
        summary = "; ".join(readiness.get("warnings") or [])
    payload = {
        "cid": cid,
        "step": 0,
        "phase": "readiness",
        "agent_phase": "preflight",
        "phase_label": "Preflight",
        "checkpoint_summary": summary,
        "next_best_action": "Resolve readiness errors before launch." if readiness.get("errors") else "Launch checks complete.",
        "readiness": readiness,
        "no_progress_streak": 0,
    }
    if broadcast:
        socketio.emit("loop_trace", payload, room=cid)
    _log_event(cid, "loop_trace", payload)


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
    paused = False
    agent = _agents.get(chal["id"])
    if agent is not None:
        try:
            running = bool(agent.running)
            paused = not running
        except Exception:
            running = False
            paused = False
    out = dict(chal)
    out["running"] = running
    # Reconcile a stale "solving" with reality: a challenge is only "solving" if an agent is
    # actually running for it in THIS process. After a restart, a crash, or an out-of-process
    # eval, the DB can say "solving" while nothing runs here — show it as unsolved instead of a
    # stuck spinner. (pending_approval/solved/error are terminal and left untouched.)
    if out.get("status") == "solving" and not running:
        out["status"] = "unsolved"
        paused = False
    out["agent_paused"] = paused
    return out


def _reconcile_orphaned_solving() -> int:
    """One-time cleanup: reset any persisted 'solving' with no live agent to 'unsolved'.
    Called at web-server startup, when no agents are running yet."""
    n = 0
    try:
        for chal in load_challenges():
            if chal.get("status") == "solving" and chal.get("id") not in _agents:
                update_challenge(chal["id"], status="unsolved")
                n += 1
    except Exception:
        pass
    return n


# ── Index ──────────────────────────────────────────────────────────────────────

@app.after_request
def _no_cache_html(resp):
    # The UI is a single server-rendered page; never let the browser serve a stale copy.
    ct = resp.headers.get("Content-Type", "")
    if ct.startswith("text/html"):
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
    return resp


@app.route("/")
def index():
    return render_template(
        "index.html",
        launch_models=_registry_launch_models(),
        default_launch_model=_default_launch_model(),
    )


@app.route("/api/bootstrap", methods=["GET"])
def bootstrap_api():
    return jsonify({
        "launch_models": _registry_launch_models(),
        "default_launch_model": _default_launch_model(),
        "config": _public_config_payload(),
        "docker": _docker_status_payload(),
        "challenges": [_challenge_payload(c) for c in load_challenges()],
    })


@app.route("/api/challenge-sets", methods=["GET"])
def challenge_sets_api():
    return jsonify({"sets": list_challenge_sets()})


@app.route("/api/challenge-sets", methods=["POST"])
def create_challenge_set_api():
    data = request.get_json(force=True) or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "name is required"}), 400
    sid = create_challenge_set(name, (data.get("competition") or "").strip(),
                               data.get("challenges") or [])
    if data.get("activate"):
        activate_challenge_set(sid)
    return jsonify({"ok": True, "id": sid, "sets": list_challenge_sets()})


@app.route("/api/challenge-sets/<sid>/activate", methods=["POST"])
def activate_challenge_set_api(sid):
    if not activate_challenge_set(sid):
        return jsonify({"error": "set not found"}), 404
    return jsonify({"ok": True, "sets": list_challenge_sets(),
                    "challenges": [_challenge_payload(c) for c in load_challenges()]})


@app.route("/api/challenge-sets/<sid>", methods=["PUT"])
def rename_challenge_set_api(sid):
    data = request.get_json(force=True) or {}
    if not rename_challenge_set(sid, data.get("name"), data.get("competition")):
        return jsonify({"error": "set not found"}), 404
    return jsonify({"ok": True, "sets": list_challenge_sets()})


@app.route("/api/challenge-sets/<sid>", methods=["DELETE"])
def delete_challenge_set_api(sid):
    ok, info = delete_challenge_set(sid)
    if not ok:
        return jsonify({"error": info}), 400
    return jsonify({"ok": True, "active": info, "sets": list_challenge_sets()})


@app.route("/manual/<cid>")
def manual_terminal_view(cid):
    chal = get_challenge(cid)
    if not chal:
        return render_template("index.html")
    return render_template("manual_terminal.html", cid=cid, challenge=chal)


# ── Challenges CRUD ────────────────────────────────────────────────────────────

@app.route("/api/challenges", methods=["GET"])
def get_challenges():
    return jsonify([_challenge_payload(c) for c in load_challenges()])


@app.route("/api/challenges", methods=["POST"])
def create_challenge():
    data = request.json or {}
    chal = apply_challenge_defaults({
        "id": str(uuid.uuid4())[:8],
        "name": data.get("name", "Untitled"),
        "category": data.get("category", "misc"),
        "flag_format": data.get("flag_format", ""),
        "description": data.get("description", ""),
        "tags": data.get("tags", []),
        "notes": data.get("notes", ""),
        "credentials": data.get("credentials", []),
        "target": data.get("target", {}),
        "source_meta": data.get("source_meta", {}),
        "created_at": utc_now_iso(),
        "last_activity_at": utc_now_iso(),
    })
    with _db_lock:
        chals = _load_challenges_unlocked()
        chals.append(chal)
        _save_challenges_unlocked(chals)
    challenge_workspace_dir(chal["id"])
    write_workspace_manifest(chal)
    _broadcast_challenge(chal)
    return jsonify(_challenge_payload(chal))


# ── CTF platform importer ─────────────────────────────────────────────────────
@app.route("/api/import/connect", methods=["POST"])
def import_connect():
    import importer
    data = request.get_json(force=True) or {}
    try:
        return jsonify(importer.connect(data.get("url", ""), data.get("cookie", ""), data.get("token", "")))
    except PermissionError as e:
        return jsonify({"error": str(e)}), 401
    except Exception as e:
        return jsonify({"error": str(e)}), 400


def _import_create_challenge(ch: dict):
    """Persist one imported challenge into the active set, de-duplicating on the source's remote
    id + platform URL so re-importing the same challenge returns the existing id instead of a copy.
    Returns (cid, is_new)."""
    src = ch.get("source_meta") or {}
    rid, surl = str(src.get("remote_id", "")), str(src.get("source_url", ""))
    furl = str(ch.get("flag_url", ""))
    with _db_lock:
        chals = _load_challenges_unlocked()
        for existing in chals:
            es = existing.get("source_meta") or {}
            same_meta = rid and str(es.get("remote_id", "")) == rid and str(es.get("source_url", "")) == surl
            same_flag = furl and str(existing.get("flag_url", "")) == furl
            if same_meta or same_flag:
                return existing["id"], False
        ch = dict(ch)
        ch["id"] = str(uuid.uuid4())[:8]
        ch.setdefault("created_at", utc_now_iso())
        ch["last_activity_at"] = utc_now_iso()
        chal = apply_challenge_defaults(ch)
        chals.append(chal)
        _save_challenges_unlocked(chals)
    return chal["id"], True


def _run_import(url, ids, cookie="", token="", listing=None):
    """Import ids, broadcast new challenges, return the importer summary dict. Prefers reading
    through the live login browser (Cloudflare-proof); falls back to cookie/token over HTTP."""
    import importer, browser_session
    created_new = []

    def _create(ch: dict) -> str:
        cid, is_new = _import_create_challenge(ch)
        if is_new:
            created_new.append(cid)
        return cid

    sess = browser_session.get_session()
    if sess:
        result = importer.import_via_fetch(url, ids, listing or [], sess.fetch_json, sess.fetch_bytes,
                                           create_fn=_create)
    else:
        result = importer.import_challenges(url, ids, cookie, token, create_fn=_create)
    # Record downloaded files on each challenge so the challenge view shows them.
    for c in result.get("created", []):
        cid, files = c.get("cid"), c.get("files") or []
        if cid and files:
            try:
                existing = (get_challenge(cid) or {}).get("files") or []
                update_challenge(cid, files=list(dict.fromkeys([*existing, *files])))
            except Exception:
                pass
    for cid in created_new:
        ch = get_challenge(cid)
        if ch:
            _broadcast_challenge(ch)
    result["created_new"] = created_new
    return result


@app.route("/api/import/run", methods=["POST"])
def import_run():
    data = request.get_json(force=True) or {}
    ids = data.get("ids") or []
    if not ids:
        return jsonify({"error": "No challenges selected."}), 400
    try:
        result = _run_import(data.get("url", ""), ids, data.get("cookie", ""), data.get("token", ""))
    except PermissionError as e:
        return jsonify({"error": str(e)}), 401
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    return jsonify(result)


def _import_agent_complete(messages, model_ref=""):
    """One provider-agnostic chat completion for the import agent. Returns (text, error)."""
    cfg = load_config()
    spec = providers.resolve_model(cfg, model_ref) if model_ref else None
    if spec is None:
        spec = providers.resolve_role(cfg, "aux") or providers.resolve_role(cfg, "solver")
    client, kind = providers.build_client(spec, timeout=60, max_retries=1)
    if client is None:
        return None, "No model configured (add an API key in Settings)."
    try:
        if kind == "anthropic":
            sys = "\n".join(m["content"] for m in messages if m["role"] == "system")
            conv = [{"role": m["role"], "content": m["content"]} for m in messages if m["role"] != "system"]
            resp = client.messages.create(model=spec.model_id, max_tokens=1600, system=sys, messages=conv)
            text = "".join(getattr(b, "text", "") for b in resp.content if getattr(b, "type", None) == "text")
        else:
            # Newer OpenAI models want `max_completion_tokens` and only default temperature; older /
            # self-hosted OpenAI-compatible endpoints want `max_tokens`. Try modern, fall back.
            def _call(token_param):
                return client.chat.completions.create(
                    model=spec.model_id, messages=messages, **{token_param: 1600})
            try:
                resp = _call("max_completion_tokens")
            except Exception as e:
                if "max_completion_tokens" in str(e) or "max_tokens" in str(e):
                    resp = _call("max_tokens")
                else:
                    raise
            text = resp.choices[0].message.content or ""
        return text, None
    except Exception as e:
        return None, str(e)


_IMPORT_AGENT_SYSTEM = """You are a web import agent for a CTF/challenge workspace. The operator has \
logged into a website in a real browser and wants you to import challenges (or tasks/exercises/labs) \
from it into their workspace. You browse the LOGGED-IN site yourself to discover what's there, then \
save each challenge with its description and any downloadable files.

Work in a loop. Each step, reply with EXACTLY ONE JSON object and nothing else:
  {"thought":"...", "action":"open",  "url":"<absolute url>"}          — read a page (returns its text + links)
  {"thought":"...", "action":"save",  "challenge":{"name":"...", "category":"web|pwn|crypto|rev|forensics|osint|network|misc", "description":"...", "source_url":"<page url>", "file_urls":["<absolute file url>", ...]}}
  {"thought":"...", "action":"say",   "message":"<message to the operator>"}   — finish this turn

Rules:
- Start by opening the page the operator is on (given below) or a listing/challenges page, and follow \
links to find individual challenges. Prefer absolute URLs from the links you're given.
- category must be one of the allowed values; infer it, default "misc".
- Put the challenge's real prompt/description in description. Include any connection info (nc host port, \
URLs) in the description.
- file_urls: ALWAYS include every downloadable file link visible on the challenge page — \
attachments, handouts, and artifact links (e.g. .zip/.tar/.key/.enc/.bin/.pcap or anything under an \
artifacts/download host). Copy the full absolute URLs from the page's links. Only omit if there are none.
- Only save real challenges the operator asked for. Don't save nav pages or duplicates.
- Use "say" when you've imported what was asked, need clarification, or can't find anything. Keep it short.
- Budget: at most %(max_steps)d steps. Save challenges as you find them rather than all at the end."""


def _import_agent_step(msgs, model_ref):
    text, err = _import_agent_complete(msgs, model_ref)
    if err:
        return None, err
    raw = text or ""
    if "{" in raw and "}" in raw:
        candidate = raw[raw.index("{"):raw.rindex("}") + 1]
        for attempt in (candidate, re.search(r"\{.*?\}", raw, re.DOTALL) and re.search(r"\{.*?\}", raw, re.DOTALL).group(0)):
            if not attempt:
                continue
            try:
                return json.loads(attempt), None
            except Exception:
                continue
        # Unparseable JSON (often a description overflowed the token budget) — don't end the run;
        # signal invalid so the loop asks the model to resend a smaller, valid action.
        return {"action": "invalid", "raw": raw[:400]}, None
    # No JSON at all → treat as a plain message to the operator.
    return {"action": "say", "message": raw.strip() or "(no response)"}, None


_import_agent_cancel = set()   # sids that asked the running import agent to stop


def _run_import_agent(sid, base, start_url, user_msg, history, model_ref, max_steps=16):
    import browser_session, importer
    _import_agent_cancel.discard(sid)
    sess = browser_session.get_session()
    if not sess:
        socketio.emit("import_agent_reply", {"reply": "The login browser closed — reopen it and log in again."}, room=sid)
        return

    def emit_step(text, kind="think"):
        socketio.emit("import_agent_step", {"text": text, "kind": kind}, room=sid)

    system = _IMPORT_AGENT_SYSTEM % {"max_steps": max_steps}
    msgs = [{"role": "system", "content": system}]
    for m in (history or [])[-8:]:
        msgs.append({"role": "assistant" if m.get("role") == "assistant" else "user",
                     "content": str(m.get("content", ""))})
    msgs.append({"role": "user", "content":
                 f"You are logged in at: {start_url or base}\nBase site: {base}\n\nInstruction: {user_msg}"})

    saved = []
    for _ in range(max_steps):
        if sid in _import_agent_cancel:
            _import_agent_cancel.discard(sid)
            socketio.emit("import_agent_reply",
                          {"reply": f"Stopped. Imported {len(saved)} so far.", "saved": saved}, room=sid)
            return
        act, err = _import_agent_step(msgs, model_ref)
        if err:
            socketio.emit("import_agent_reply", {"reply": f"Model error: {err}"}, room=sid)
            return
        action = (act.get("action") or "").lower()
        thought = (act.get("thought") or "").strip()

        if action == "invalid":
            # Keep the run alive; nudge the model to resend one compact, valid JSON action.
            msgs.append({"role": "user", "content":
                         "OBSERVATION: your previous message was not valid JSON. Resend EXACTLY ONE "
                         "JSON action. If saving, keep the description under ~1500 characters."})
            continue

        msgs.append({"role": "assistant", "content": json.dumps(act)})

        if action == "open":
            url = (act.get("url") or "").strip()
            if thought:
                emit_step(thought)
            emit_step(f"Reading {url}", "open")
            try:
                page = sess.read_page(url)
            except Exception as e:
                msgs.append({"role": "user", "content": f"OBSERVATION: failed to open {url}: {e}"})
                continue
            links = page.get("links") or []
            link_txt = "\n".join(f"- {l.get('t','')} -> {l.get('href','')}" for l in links[:80])
            obs = (f"OBSERVATION of {page.get('url')} (title: {page.get('title')}):\n"
                   f"TEXT:\n{page.get('text','')[:5000]}\n\nLINKS:\n{link_txt[:3000]}")
            msgs.append({"role": "user", "content": obs})

        elif action == "save":
            ch = act.get("challenge") or {}
            name = (ch.get("name") or "").strip()
            if not name:
                msgs.append({"role": "user", "content": "OBSERVATION: save failed — missing name."})
                continue
            emit_step(f"Saving “{name}”", "save")
            challenge = {
                "name": name,
                "category": importer._norm_category(ch.get("category")),
                "description": (ch.get("description") or "").strip(),
                "flag_url": (ch.get("source_url") or start_url or base),
                "target": {"url": ch.get("source_url") or ""} if (ch.get("source_url") or "").startswith("http") else {},
                "source_meta": {"platform": "web", "source_url": base, "remote_id": (ch.get("source_url") or name)},
                "tags": [],
            }
            cid, is_new = _import_create_challenge(challenge)
            import base64 as _b64
            files, file_fails = [], []
            for furl in (ch.get("file_urls") or [])[:20]:
                full = furl if furl.startswith("http") else base + furl
                try:
                    fres = sess.fetch_bytes(full)
                except Exception as e:
                    file_fails.append((furl, f"error {e}"))
                    continue
                status = fres.get("status")
                raw = _b64.b64decode(fres.get("b64") or "") if fres.get("b64") else b""
                head = raw[:64].lstrip().lower()
                is_html = head.startswith(b"<!doctype") or head.startswith(b"<html")
                if status == 200 and raw and not is_html:
                    fname = importer._safe_name(full.split("?")[0].rsplit("/", 1)[-1])
                    dest = challenge_workspace_dir(cid) / fname
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_bytes(raw)
                    files.append(fname)
                else:
                    why = "not logged-in / redirected to HTML" if is_html else f"HTTP {status}"
                    file_fails.append((full.rsplit("/", 1)[-1][:40], why))
            # Record the downloaded files on the challenge so the challenge view shows them.
            if files:
                try:
                    existing = (get_challenge(cid) or {}).get("files") or []
                    merged = list(dict.fromkeys([*existing, *files]))
                    update_challenge(cid, files=merged)
                except Exception:
                    pass
            chd = get_challenge(cid)
            if chd:
                _broadcast_challenge(chd)
            if is_new:
                saved.append({"name": name, "files": files})
                msg = f"✓ Imported “{name}”" + (f" ({len(files)} file{'s' if len(files) != 1 else ''})" if files else "")
                emit_step(msg, "done")
            else:
                emit_step(f"“{name}” already imported — skipped", "skip")
            for fn, why in file_fails:
                emit_step(f"⚠ couldn’t download {fn} — {why}", "warn")
            msgs.append({"role": "user", "content":
                         f"OBSERVATION: saved '{name}' ({'new' if is_new else 'duplicate'}), files={files}, "
                         f"failed_files={[f for f,_ in file_fails]}. If a file failed, its link may be wrong or need "
                         f"a click — look for the real download link on the page. Continue or say()."})

        else:  # say / finish
            socketio.emit("import_agent_reply",
                          {"reply": (act.get("message") or thought or "Done.").strip(), "saved": saved}, room=sid)
            return

    socketio.emit("import_agent_reply",
                  {"reply": f"Stopped after {max_steps} steps. Imported {len(saved)} so far — tell me to continue if there's more.",
                   "saved": saved}, room=sid)


@socketio.on("import_agent")
def on_import_agent(data):
    import importer  # noqa: F401 (used by _run_import_agent)
    data = data or {}
    base = _import_base_from(data.get("base") or "")
    start_url = (data.get("url") or "").strip()
    user_msg = str(data.get("message") or "").strip()
    history = data.get("history") or []
    model_ref = data.get("model", "")
    sid = request.sid
    if not base or not user_msg:
        socketio.emit("import_agent_reply", {"reply": "Log into a site first, then tell me what to import."}, room=sid)
        return
    socketio.start_background_task(_run_import_agent, sid, base, start_url, user_msg, history, model_ref)


@socketio.on("import_agent_stop")
def on_import_agent_stop(_data=None):
    _import_agent_cancel.add(request.sid)


@app.route("/api/challenges/<cid>", methods=["GET"])
def get_challenge_route(cid):
    chal = get_challenge(cid)
    if not chal:
        return jsonify({"error": "Not found"}), 404
    return jsonify(_challenge_payload(chal))


@app.route("/api/challenges/<cid>/logs", methods=["GET"])
def get_challenge_logs(cid):
    if not get_challenge(cid):
        return jsonify({"error": "Not found"}), 404
    return jsonify(_load_log_events(cid))


@app.route("/api/challenges/export", methods=["GET"])
def export_challenges():
    return jsonify({"challenges": load_challenges()})


@app.route("/api/challenges/import", methods=["POST"])
def import_challenges():
    data = request.get_json(force=True) or {}
    imported = normalize_import_payload(data.get("payload"))
    if not imported:
        return jsonify({"error": "No importable challenge records found."}), 400
    existing = load_challenges()
    for item in imported:
        item["id"] = str(uuid.uuid4())[:8]
        item["created_at"] = utc_now_iso()
        item["last_activity_at"] = item["created_at"]
        existing.append(item)
        challenge_workspace_dir(item["id"])
        write_workspace_manifest(item)
    save_challenges(existing)
    return jsonify({
        "ok": True,
        "imported": len(imported),
        "challenges": [_challenge_payload(c) for c in existing],
    })


@app.route("/api/challenges/<cid>/workspace", methods=["GET"])
def challenge_workspace(cid):
    chal = get_challenge(cid)
    if not chal:
        return jsonify({"error": "Not found"}), 404
    max_depth = max(1, min(int(request.args.get("depth") or 4), 8))
    include_hidden = bool(request.args.get("include_hidden"))
    return jsonify({
        "cid": cid,
        "path": str(challenge_workspace_dir(cid)),
        "entries": workspace_listing(cid, max_depth=max_depth, include_hidden=include_hidden),
    })


def _safe_workspace_file(cid: str, rel: str):
    """Resolve a workspace-relative path safely (no traversal). Returns (base, target) or None."""
    base = challenge_workspace_dir(cid).resolve()
    rel = (rel or "").lstrip("/")
    try:
        target = (base / rel).resolve()
        if target == base or target.is_relative_to(base):
            return base, target
    except Exception:
        pass
    return None


_VIEW_MAX_BYTES = 512 * 1024  # inline-view/edit size cap


@app.route("/api/challenges/<cid>/file", methods=["GET"])
def get_challenge_file(cid):
    if not get_challenge(cid):
        return jsonify({"error": "Not found"}), 404
    resolved = _safe_workspace_file(cid, request.args.get("path", ""))
    if not resolved or not resolved[1].is_file():
        return jsonify({"error": "File not found"}), 404
    target = resolved[1]
    if request.args.get("download"):
        return send_file(target, as_attachment=True, download_name=target.name)
    size = target.stat().st_size
    if size > _VIEW_MAX_BYTES:
        return jsonify({"error": "File too large to view — download instead.", "size": size, "download": True}), 413
    try:
        text = target.read_text(encoding="utf-8")
    except (UnicodeDecodeError, ValueError):
        return jsonify({"error": "Binary file — download to view.", "size": size, "binary": True, "download": True}), 415
    return jsonify({"path": request.args.get("path", ""), "content": text, "size": size})


@app.route("/api/challenges/<cid>/file", methods=["POST"])
def write_challenge_file(cid):
    if not get_challenge(cid):
        return jsonify({"error": "Not found"}), 404
    data = request.get_json(force=True) or {}
    resolved = _safe_workspace_file(cid, data.get("path", ""))
    if not resolved or resolved[1] == resolved[0]:
        return jsonify({"error": "Invalid path"}), 400
    target = resolved[1]
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(data.get("content") or "", encoding="utf-8")
    return jsonify({"ok": True, "path": data.get("path", ""), "size": target.stat().st_size})


@app.route("/api/challenges/<cid>/notes", methods=["GET"])
def challenge_notes(cid):
    chal = get_challenge(cid)
    if not chal:
        return jsonify({"error": "Not found"}), 404
    return jsonify({
        "cid": cid,
        "notes": read_notes(cid),
        "path": str(challenge_notes_path(cid)),
    })


@app.route("/api/challenges/<cid>/notes", methods=["POST"])
def challenge_notes_append(cid):
    chal = get_challenge(cid)
    if not chal:
        return jsonify({"error": "Not found"}), 404
    data = request.get_json(force=True) or {}
    path = append_note(
        cid,
        title=data.get("title") or "Manual Note",
        content=data.get("content") or "",
        kind=data.get("kind") or "manual",
    )
    update_challenge(cid, last_activity_at=utc_now_iso())
    return jsonify({"ok": True, "path": path, "notes": read_notes(cid)})


@app.route("/api/challenges/<cid>/memory", methods=["GET"])
def challenge_memory_index(cid):
    chal = get_challenge(cid)
    if not chal:
        return jsonify({"error": "Not found"}), 404
    ensure_memory_files(cid)
    return jsonify({
        "cid": cid,
        "path": str(challenge_memory_dir(cid)),
        "files": list_memory_files(cid),
    })


@app.route("/api/challenges/<cid>/memory/clear", methods=["POST"])
def challenge_memory_clear(cid):
    chal = get_challenge(cid)
    if not chal:
        return jsonify({"error": "Not found"}), 404
    clear_memory_files(cid)
    ensure_memory_files(cid)
    update_challenge(cid, last_activity_at=utc_now_iso())
    _broadcast_challenge(get_challenge(cid))
    return jsonify({
        "ok": True,
        "files": list_memory_files(cid),
        "path": str(challenge_memory_dir(cid)),
    })


@app.route("/api/challenges/<cid>/memory/<name>", methods=["GET"])
def challenge_memory_read(cid, name):
    chal = get_challenge(cid)
    if not chal:
        return jsonify({"error": "Not found"}), 404
    try:
        ensure_memory_files(cid)
        path = challenge_memory_file_path(cid, name)
        content = read_memory_file(cid, name)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({
        "cid": cid,
        "name": name,
        "path": str(path),
        "content": content,
    })


@app.route("/api/challenges/<cid>/memory/<name>", methods=["PUT"])
def challenge_memory_write(cid, name):
    chal = get_challenge(cid)
    if not chal:
        return jsonify({"error": "Not found"}), 404
    data = request.get_json(force=True) or {}
    try:
        path = write_memory_file(cid, name, data.get("content") or "")
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    update_challenge(cid, last_activity_at=utc_now_iso())
    _broadcast_challenge(get_challenge(cid))
    return jsonify({
        "ok": True,
        "name": name,
        "path": path,
        "content": read_memory_file(cid, name),
        "files": list_memory_files(cid),
    })


@app.route("/api/challenges/<cid>/memory/<name>", methods=["DELETE"])
def challenge_memory_delete(cid, name):
    chal = get_challenge(cid)
    if not chal:
        return jsonify({"error": "Not found"}), 404
    try:
        delete_memory_file(cid, name)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    update_challenge(cid, last_activity_at=utc_now_iso())
    _broadcast_challenge(get_challenge(cid))
    return jsonify({"ok": True, "files": list_memory_files(cid)})


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
        "workspace_path": str(challenge_workspace_dir(cid)),
        "challenge": {
            "name": chal.get("name", ""),
            "category": chal.get("category", ""),
            "description": chal.get("description", ""),
            "files": chal.get("files", []) or [],
            "tags": chal.get("tags", []) or [],
            "target": chal.get("target", {}) or {},
            "source_meta": chal.get("source_meta", {}) or {},
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
    chal = get_challenge(cid)
    if not chal:
        return jsonify({"error": "Not found"}), 404
    data = request.json or {}
    if "files" not in data:
        workspace_files = [
            entry["path"]
            for entry in workspace_listing(cid, max_depth=1)
            if entry["kind"] == "file" and "/" not in entry["path"]
        ]
        data["files"] = workspace_files
    update_challenge(cid, **data)
    updated = get_challenge(cid)
    _broadcast_challenge(updated)
    return jsonify(_challenge_payload(updated))


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
        # Spec B: rejecting a candidate resumes the solve instead of killing it. Tell the agent
        # the token was wrong (so it never resubmits it) and let it keep working from current
        # state. If no live agent exists, fall back to the old revert-to-unsolved behavior.
        agent = _agents.get(cid)
        reject_msg = (
            f"The flag candidate `{candidate}` was REJECTED — it is wrong. Do NOT submit it "
            "again. It may be a planted decoy. Keep solving toward the real flag using a "
            "different approach."
        )
        resumed = False
        if agent is not None:
            update_challenge(cid, status="solving", flag=None, flag_candidate=None,
                             flag_how=None, approved_at=None, writeup_md=None,
                             writeup_path=None, writeup_ready_at=None)
            try:
                mode = agent.submit_user_input(reject_msg)  # queues + resumes if stopped
                resumed = mode in ("resumed", "queued")
            except Exception:
                resumed = False
        if not resumed:
            update_challenge(
                cid, status="unsolved", flag=None, flag_candidate=None, flag_how=None,
                approved_at=None, writeup_md=None, writeup_path=None, writeup_ready_at=None,
            )
        payload = {
            "cid": cid,
            "status": "solving" if resumed else "unsolved",
            "message": ("Candidate rejected — agent is continuing to solve."
                        if resumed else "Flag candidate rejected. Challenge reverted to unsolved."),
        }
        socketio.emit("flag_rejected", payload, room=cid)
        if not resumed:
            socketio.emit("done", payload, room=cid)
            _log_event(cid, "done", payload)
        _log_event(cid, "flag_rejected", payload)
        updated = get_challenge(cid)
        _broadcast_challenge(updated)
        return jsonify(_challenge_payload(updated))

    logs = _load_log_events(cid)
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
    updated = get_challenge(cid)
    _broadcast_challenge(updated)
    return jsonify(_challenge_payload(updated))


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
    remove_challenge_artifacts(cid)
    _broadcast_challenge_deleted(cid)
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

    workspace_dir = challenge_workspace_dir(cid)
    local = workspace_dir / fname
    f.save(str(local))

    files = list(chal.get("files", []))
    if fname not in files:
        files.append(fname)
    update_challenge(cid, files=files)
    write_workspace_manifest(get_challenge(cid) or chal)

    _broadcast_challenge(get_challenge(cid))
    try:
        if cid in _containers and _containers[cid].running:
            container = _containers[cid]
            listing = container.run("ls -lh /ctf/")
            socketio.emit("file_uploaded", {"name": fname, "listing": listing}, room=cid)
            return jsonify({"ok": True, "name": fname, "remote": f"/ctf/{fname}", "listing": listing})
        return jsonify({"ok": True, "name": fname, "stored": True, "synced": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Agent control ──────────────────────────────────────────────────────────────

def _spawn_agent_for(cid, model_arg=None, retry=False, extra_context=""):
    """Fresh-launch the solver agent for a challenge. Returns (ok, error, http_status).
    Shared by the interactive /launch route and the batch /launch-all runner."""
    model = _canonical_launch_model(model_arg)
    chal  = get_challenge(cid)
    if not chal:
        return False, "Not found", 404

    _cfg = load_config()
    resolved_model = model or _cfg.get("solver_model") or _cfg.get("model") or "gpt-5-mini"
    readiness = _agent_readiness_report(resolved_model, chal.get("category", "misc"))
    if not readiness["ok"]:
        _emit_readiness_trace(cid, readiness)
        return False, "; ".join(readiness["errors"]), 400
    ok, err = _docker_build_gate()
    if not ok:
        return False, err, 400

    try:
        container = get_container(cid)
        sync_challenge_uploads(cid, container)
        _manual_mode_cids.discard(cid)
        ensure_memory_files(cid)
        readiness = _agent_readiness_report(resolved_model, chal.get("category", "misc"), container=container)
        _emit_readiness_trace(cid, readiness, broadcast=bool(readiness.get("errors") or readiness.get("warnings")))
    except Exception as e:
        return False, f"Container failed: {e}", 500

    flag_fmt  = chal.get("flag_format", "")
    extra     = extra_context or ""
    tags      = ", ".join(chal.get("tags") or [])
    target    = enrich_target(chal.get("target"), chal.get("description"), chal.get("notes"))
    source_meta = chal.get("source_meta") or {}
    creds = chal.get("credentials") or []
    target_block = ""
    non_empty_target = {k: v for k, v in target.items() if str(v or "").strip()}
    if non_empty_target:
        lines = "\n".join(f"  {k}: {v}" for k, v in non_empty_target.items() if str(v or "").strip())
        target_block = f"\nTarget:\n{lines}\n"
    source_block = ""
    non_empty_source = {k: v for k, v in source_meta.items() if str(v or "").strip()}
    if non_empty_source:
        source_block = "\nSource metadata:\n" + json.dumps(non_empty_source, indent=2) + "\n"
    credential_block = ""
    if creds:
        credential_block = "\nCredentials:\n" + json.dumps(creds, indent=2) + "\n"
    full_desc = (
        f"Challenge: {chal['name']}\n"
        f"Category: {chal['category'].upper()}\n"
        f"Working directory: /ctf/\n"
        f"Workspace path: {challenge_workspace_dir(cid)}\n"
        + (f"Flag format: {flag_fmt}\n" if flag_fmt else "")
        + (f"Tags: {tags}\n" if tags else "")
        + (f"\n{chal.get('description', '')}\n" if chal.get("description") else "")
        + target_block
        + source_block
        + credential_block
        + (f"\nOperator notes:\n{chal.get('notes', '').strip()}\n" if chal.get("notes") else "")
        + (f"\nAdditional context: {extra}\n" if extra else "")
    )

    prior = chal.get("retry_summary") if retry else None
    update_challenge(
        cid,
        status="solving",
        last_model=resolved_model,
        flag_candidate=None,
        flag_how=None,
        approved_at=None,
        writeup_md=None,
        writeup_path=None,
        writeup_ready_at=None,
    )

    workspace_dir = challenge_workspace_dir(cid)
    synced_files = sorted([p.name for p in workspace_dir.iterdir() if p.is_file() and not p.name.startswith(".")])
    if not synced_files:
        synced_files = list(chal.get("files") or [])

    container_listing = container.run("ls -1 /ctf/ 2>/dev/null || true")
    container_entries = [ln.strip() for ln in (container_listing or "").splitlines() if ln.strip()]
    container_set = set(container_entries)

    upload_payload = {
        "cid": cid,
        "total": len(synced_files),
        "present": [],
        "missing": [],
        "sample": container_entries[:12],
        "ok": True,
    }
    if synced_files:
        present = [f for f in synced_files if f in container_set]
        missing = [f for f in synced_files if f not in container_set]
        upload_payload.update({
            "present": present,
            "missing": missing,
            "ok": not bool(missing),
        })
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
    _log_event(cid, "upload_verify", upload_payload)
    if synced_files and upload_payload["missing"]:
        visible_payload = {"cid": cid, "cmd": upload_msg, "notice": True}
        socketio.emit("command", visible_payload, room=cid)
        _log_event(cid, "command", visible_payload)

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

    return True, None, 200


@app.route("/api/challenges/<cid>/launch", methods=["POST"])
def launch_agent(cid):
    data  = request.json or {}
    retry = data.get("retry", False)
    model = _canonical_launch_model(data.get("model"))
    if model:
        registry_ids = {m["id"] for m in _registry_launch_models()}
        if model not in LAUNCH_MODEL_IDS and model not in registry_ids:
            choices = ", ".join(m["id"] for m in _registry_launch_models())
            return jsonify({"error": f"Unknown model: {model}. Registered: {choices}"}), 400
    chal  = get_challenge(cid)
    if not chal:
        return jsonify({"error": "Not found"}), 404
    existing_agent = _agents.get(cid)
    if existing_agent is not None and not retry:
        extra = str(data.get("extra_context") or "").strip()
        if existing_agent.running:
            if extra:
                mode = existing_agent.submit_user_input(extra)
                update_challenge(cid, status="solving")
                return jsonify({"ok": True, "mode": mode})
            return jsonify({"error": "Agent already running"}), 400
        if extra:
            mode = existing_agent.submit_user_input(extra)
        else:
            mode = existing_agent.resume_from_current_state()
        update_challenge(cid, status="solving")
        return jsonify({"ok": True, "mode": mode, "resumed": True})

    ok, err, status = _spawn_agent_for(cid, data.get("model"), retry=retry,
                                       extra_context=data.get("extra_context", ""))
    if not ok:
        return jsonify({"error": err, "code": "launch_failed"}), status
    return jsonify({"ok": True})


# ── Batch launcher: run every eligible challenge unattended, one at a time ────────
_batch_state = {"running": False, "queue": [], "current": None, "done": [], "started_at": None}
_batch_lock = threading.Lock()


def _batch_runner(cids: list[str], model_arg=None):
    for cid in cids:
        with _batch_lock:
            if not _batch_state["running"]:
                break
            _batch_state["current"] = cid
        try:
            ok, err, _status = _spawn_agent_for(cid, model_arg)
            socketio.emit("batch_progress", {"cid": cid, "ok": ok, "error": err,
                                             "remaining": len(_batch_state["queue"])})
            if ok:
                # Wait for this challenge's solver thread to finish before starting the next,
                # so we never run multiple heavy containers at once.
                agent = _agents.get(cid)
                worker = getattr(agent, "_worker_thread", None) if agent else None
                if worker is not None:
                    worker.join()
        except Exception as e:
            socketio.emit("batch_progress", {"cid": cid, "ok": False, "error": str(e)})
        with _batch_lock:
            _batch_state["done"].append(cid)
            if cid in _batch_state["queue"]:
                _batch_state["queue"].remove(cid)
    with _batch_lock:
        _batch_state["running"] = False
        _batch_state["current"] = None
    socketio.emit("batch_done", {"done": list(_batch_state["done"])})


@app.route("/api/challenges/launch-all", methods=["POST"])
def launch_all():
    data = request.json or {}
    model = _canonical_launch_model(data.get("model"))
    if model and model not in LAUNCH_MODEL_IDS:
        return jsonify({"error": f"Unsupported model: {model}"}), 400
    categories = data.get("categories") or []
    include_solved = bool(data.get("include_solved"))
    only_never_run = bool(data.get("only_never_run"))
    ok, err = _docker_build_gate()
    if not ok:
        return jsonify({"error": err}), 400
    with _batch_lock:
        if _batch_state["running"]:
            return jsonify({"error": "Batch already running", "current": _batch_state["current"]}), 409
        cids = []
        for c in load_challenges():
            cid = c.get("id")
            if not cid:
                continue
            if not include_solved and c.get("status") == "solved":
                continue
            if categories and (c.get("category") or "").lower() not in categories:
                continue
            if only_never_run and challenge_events_path(cid).exists():
                continue
            if cid in _agents and getattr(_agents[cid], "running", False):
                continue
            cids.append(cid)
        if not cids:
            return jsonify({"error": "No eligible challenges to launch"}), 400
        _batch_state.update({"running": True, "queue": list(cids), "current": None,
                             "done": [], "started_at": utc_now_iso()})
    threading.Thread(target=_batch_runner, args=(cids, data.get("model")), daemon=True).start()
    return jsonify({"ok": True, "queued": cids, "count": len(cids)})


@app.route("/api/challenges/launch-all/status", methods=["GET"])
def launch_all_status():
    with _batch_lock:
        return jsonify(dict(_batch_state))


@app.route("/api/challenges/launch-all/stop", methods=["POST"])
def launch_all_stop():
    with _batch_lock:
        _batch_state["running"] = False
        cur = _batch_state["current"]
    if cur and cur in _agents:
        try:
            _agents[cur].stop()
        except Exception:
            pass
    return jsonify({"ok": True})


@app.route("/api/challenges/<cid>/input", methods=["POST"])
def agent_input(cid):
    data = request.json or {}
    text = str(data.get("text") or "").strip()
    if not text:
        return jsonify({"error": "Input text is required."}), 400
    chal = get_challenge(cid)
    if not chal:
        return jsonify({"error": "Not found"}), 404
    agent = _agents.get(cid)
    if agent is None:
        return jsonify({"error": "No running or paused agent exists for this challenge.", "code": "no_agent"}), 409
    mode = agent.submit_user_input(text)
    update_challenge(cid, status="solving")
    return jsonify({"ok": True, "mode": mode})


@app.route("/api/challenges/<cid>/stop", methods=["POST"])
def stop_agent(cid):
    if cid in _agents:
        try:
            _agents[cid]._checkpoint_state("stopped", "stop", "Run stopped by user.")
        except Exception:
            pass
        _agents[cid].stop()
    _manual_mode_cids.discard(cid)
    update_challenge(
        cid,
        status="unsolved",
        flag_candidate=None,
        flag_how=None,
    )
    payload = {
        "cid": cid,
        "status": "unsolved",
        "message": "Agent paused. Type guidance and press Enter to continue.",
        "paused": True,
    }
    socketio.emit("done", payload, room=cid)
    _log_event(cid, "done", payload)
    return jsonify({"ok": True, "paused": True})


@app.route("/api/challenges/<cid>/reset", methods=["POST"])
def reset_container(cid):
    if cid in _agents:
        _agents[cid].stop()
    # Authoritatively remove the real container (by name) — not just one this process happens
    # to track — so a stale/dead container can't linger after reset.
    force_remove_container(cid)
    _manual_mode_cids.discard(cid)
    _logs.pop(cid, None)
    try:
        events_path = challenge_events_path(cid)
        if events_path.exists():
            events_path.unlink()
    except Exception:
        pass
    try:
        clear_memory_files(cid)
        ensure_memory_files(cid)
    except Exception:
        pass
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
    write_workspace_manifest(get_challenge(cid) or {"id": cid})
    _broadcast_challenge(get_challenge(cid))
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

    _manual_mode_cids.clear()
    _logs.clear()
    with _db_lock:
        _save_challenges_unlocked([])
    socketio.emit("challenges_reset", {})

    for root in ("workspaces", "runs"):
        base = BASE_DIR / root
        if base.exists():
            for p in base.iterdir():
                if p.is_dir():
                    shutil.rmtree(p, ignore_errors=True)
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


def _broadcast_challenge(chal: dict | None) -> None:
    if not chal:
        return
    socketio.emit("challenge_updated", _challenge_payload(chal))


def _broadcast_challenge_deleted(cid: str) -> None:
    socketio.emit("challenge_deleted", {"cid": cid})


def _safe_float(v):
    try:
        return float(v) if v is not None and str(v).strip() != "" else 0.0
    except (TypeError, ValueError):
        return 0.0


def _mask_key(key: str) -> str:
    """Return a safe display version of an API key."""
    if not key:
        return ""
    if len(key) <= 12:
        return "•" * len(key)
    return key[:10] + "…" + key[-4:]


def _get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def _public_config_payload() -> dict:
    cfg = load_config()
    oai = cfg.get("openai_api_key") or ""
    ant = cfg.get("anthropic_api_key") or ""
    return {
        "openai_api_key_set": bool(oai),
        "openai_api_key_masked": _mask_key(oai),
        "anthropic_api_key_set": bool(ant),
        "anthropic_api_key_masked": _mask_key(ant),
        "model": cfg.get("model") or "gpt-5-mini",
        "prompt_profile": cfg.get("prompt_profile") or "compact",
        "allow_runtime_installs": _as_bool(cfg.get("allow_runtime_installs"), default=False),
        "max_tool_calls_per_turn": int(cfg.get("max_tool_calls_per_turn") or 3),
        "checkpoint_interval": int(cfg.get("checkpoint_interval") or 5),
        "self_eval_interval": int(cfg.get("self_eval_interval") or 10),
        "context_compression_interval": int(cfg.get("context_compression_interval") or 15),
        "adaptive_tool_ranking": _as_bool(cfg.get("adaptive_tool_ranking"), default=True),
        "local_lock_enabled": _lock_enabled(cfg),
        "local_lock_password_set": bool(_lock_hash(cfg)),
        "local_ip": _get_local_ip(),
        "port": 7331,
        "models": _public_models_payload(cfg),
        "roles": cfg.get("roles") or {},
        "presets": {k: {kk: vv for kk, vv in v.items() if kk != "api_key_ref"} | {"key": k}
                    for k, v in PROVIDER_PRESETS.items()},
    }


def _public_models_payload(cfg: dict) -> list[dict]:
    """Registry for the UI: capabilities/pricing shown, key material redacted to set/last-4."""
    out = []
    for spec in providers.list_models(cfg):
        out.append({
            "id": spec.id,
            "name": spec.name,
            "provider_kind": spec.provider_kind,
            "base_url": spec.base_url,
            "model_id": spec.model_id,
            "api_key_ref": spec.api_key_ref,
            "key_set": spec.has_key,
            "key_masked": _mask_key(spec.api_key) if spec.has_key else "",
            "pricing": {"in": spec.pricing_in, "out": spec.pricing_out},
            "capabilities": spec.caps,
            "context": spec.context,
        })
    return out


@app.route("/api/config", methods=["GET"])
def get_config_api():
    return jsonify(_public_config_payload())


@app.route("/api/agent/readiness", methods=["GET"])
def agent_readiness_api():
    model = _canonical_launch_model(request.args.get("model")) or _default_launch_model()
    category = (request.args.get("category") or "misc").strip().lower()
    readiness = _agent_readiness_report(model, category)
    ok, err = _docker_build_gate()
    readiness["docker"] = {"ok": ok, "message": err or "Docker image is built."}
    if not ok:
        readiness["warnings"].append(err)
    return jsonify(readiness)


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
        prompt_profile = (data.get("prompt_profile") or "").strip().lower()
        if prompt_profile in {"compact", "full"}:
            cfg["prompt_profile"] = prompt_profile
        if "allow_runtime_installs" in data:
            cfg["allow_runtime_installs"] = bool(data.get("allow_runtime_installs"))
        max_tool_calls = data.get("max_tool_calls_per_turn")
        if max_tool_calls is not None:
            try:
                cfg["max_tool_calls_per_turn"] = max(1, min(int(max_tool_calls), 6))
            except Exception:
                pass
        for key, default, lo, hi in (
            ("checkpoint_interval", 5, 1, 50),
            ("self_eval_interval", 10, 1, 80),
            ("context_compression_interval", 15, 3, 120),
        ):
            if key in data:
                try:
                    cfg[key] = max(lo, min(int(data.get(key) or default), hi))
                except Exception:
                    cfg[key] = default
        if "adaptive_tool_ranking" in data:
            cfg["adaptive_tool_ranking"] = bool(data.get("adaptive_tool_ranking"))

        # Provider registry: models (full replace), keys (merge + clear), roles (merge).
        if "models" in data and isinstance(data["models"], list):
            cleaned = []
            for m in data["models"]:
                if not isinstance(m, dict):
                    continue
                mid = (m.get("id") or "").strip()
                model_id = (m.get("model_id") or "").strip()
                if not mid or not model_id:
                    continue
                kind = (m.get("provider_kind") or "openai_compat").strip()
                if kind not in providers.VALID_PROVIDER_KINDS:
                    kind = "openai_compat"
                pricing = m.get("pricing") or {}
                caps = m.get("capabilities") or {}
                cleaned.append({
                    "id": mid,
                    "name": (m.get("name") or mid).strip(),
                    "provider_kind": kind,
                    "base_url": (m.get("base_url") or "").strip(),
                    "api_key_ref": (m.get("api_key_ref") or mid).strip(),
                    "model_id": model_id,
                    "pricing": {"in": _safe_float(pricing.get("in")), "out": _safe_float(pricing.get("out"))},
                    "capabilities": {"tools": bool(caps.get("tools", True)), "vision": bool(caps.get("vision", False))},
                    "context": int(m.get("context") or 0),
                })
            cfg["models"] = cleaned
        if isinstance(data.get("keys"), dict):
            keys = dict(cfg.get("keys") or {})
            for ref, val in data["keys"].items():
                ref = (ref or "").strip()
                if not ref:
                    continue
                val = (val or "").strip()
                if val:
                    keys[ref] = val  # blank value leaves the existing key untouched
            for ref in (data.get("clear_keys") or []):
                keys.pop((ref or "").strip(), None)
            cfg["keys"] = keys
        if isinstance(data.get("roles"), dict):
            roles = dict(cfg.get("roles") or {})
            for role in ("solver", "aux"):
                if role in data["roles"]:
                    roles[role] = (data["roles"][role] or "").strip()
            cfg["roles"] = roles

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


@app.route("/api/models/test", methods=["POST"])
def test_model_endpoint():
    """Fire one tiny probe at an endpoint to confirm it works and detect tool support,
    before the user saves it. Never persists anything."""
    import time as _time
    data = request.get_json(force=True) or {}
    kind = (data.get("provider_kind") or "openai_compat").strip()
    base_url = (data.get("base_url") or "").strip()
    model_id = (data.get("model_id") or "").strip()
    api_key = (data.get("api_key") or "").strip()
    if not api_key and data.get("api_key_ref"):
        api_key = providers.key_for(load_config(), data["api_key_ref"])
    if not model_id:
        return jsonify({"ok": False, "error": "model_id is required"}), 400
    if not api_key:
        return jsonify({"ok": False, "error": "no API key provided or on file for this endpoint"}), 400

    spec = providers.ModelSpec(id="probe", name="probe", provider_kind=kind,
                               model_id=model_id, base_url=base_url, api_key=api_key)
    client, _ = providers.build_client(spec)
    if client is None:
        return jsonify({"ok": False, "error": "could not build client (missing key or package)"}), 400

    probe_tool = {
        "type": "function",
        "function": {"name": "noop", "description": "probe", "parameters": {"type": "object", "properties": {}}},
    }
    t0 = _time.time()
    try:
        if kind == "anthropic":
            client.messages.create(
                model=model_id, max_tokens=1, messages=[{"role": "user", "content": "hi"}],
                tools=[{"name": "noop", "description": "probe", "input_schema": {"type": "object", "properties": {}}}],
            )
        else:
            tok = ({"max_completion_tokens": 1}
                   if model_id.lower().startswith(("o1", "o3", "gpt-5")) else {"max_tokens": 1})
            client.chat.completions.create(
                model=model_id, messages=[{"role": "user", "content": "hi"}],
                tools=[probe_tool], tool_choice="auto", **tok,
            )
        latency = int((_time.time() - t0) * 1000)
        return jsonify({"ok": True, "status": 200, "tools": True,
                        "latency_ms": latency, "error": ""})
    except Exception as e:
        # Retry once without tools — distinguishes "endpoint down" from "no tool support".
        try:
            if kind == "anthropic":
                client.messages.create(model=model_id, max_tokens=1,
                                       messages=[{"role": "user", "content": "hi"}])
            else:
                client.chat.completions.create(model=model_id, max_tokens=1,
                                               messages=[{"role": "user", "content": "hi"}])
            latency = int((_time.time() - t0) * 1000)
            return jsonify({"ok": True, "status": 200, "tools": False,
                            "latency_ms": latency, "error": "endpoint works but rejected tool calling"})
        except Exception as e2:
            return jsonify({"ok": False, "status": 0, "tools": False, "error": str(e2)[:400]})


# ── Docker management ──────────────────────────────────────────────────────────

def _docker_status_payload() -> dict:
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
        # Single source of truth for the UI. The image's actual presence — not stale
        # process-local memory — decides "ready" vs "required", so a fresh start never
        # falsely says "Build required" when ctf-kali is already built.
        if build_in_progress:
            build_state = "building"
        elif has_image:
            build_state = "ready"
        else:
            build_state = "required"
        return {
            "running": True,
            "image": has_image,
            "build_state": build_state,
            "build_ready": has_image,          # back-compat: ready == image present
            "build_in_progress": build_in_progress,
            "active_agents": running_agents,
            "active_containers": running_containers,
        }
    except Exception as e:
        return {
            "running": False,
            "error": str(e),
            "build_state": "down",
            "build_ready": False,
            "build_in_progress": False,
            "active_agents": 0,
            "active_containers": 0,
        }

@app.route("/api/docker/status", methods=["GET"])
def docker_status():
    return jsonify(_docker_status_payload())


@app.route("/api/system/stats", methods=["GET"])
def system_stats():
    """Fast host resource snapshot: CPU %, RAM, and running ctf-agent container count.
    Kept cheap (no per-container docker stats stream) so the dashboard can poll it often."""
    out = {"ok": True}
    try:
        import psutil
        out["cpu_percent"] = round(psutil.cpu_percent(interval=None), 1)
        out["cpu_count"] = psutil.cpu_count() or 0
        vm = psutil.virtual_memory()
        out["mem_percent"] = round(vm.percent, 1)
        # Use (total - available) so the GB shown matches the percent (psutil.percent is
        # available-based on macOS; vm.used excludes cache/inactive and looked contradictory).
        out["mem_used"] = int(vm.total - vm.available)
        out["mem_total"] = int(vm.total)
        try:
            out["load1"] = round(psutil.getloadavg()[0], 2)
        except Exception:
            out["load1"] = None
    except Exception as e:
        out["ok"] = False
        out["error"] = str(e)
    # Container count is cheap via the docker client.
    count = 0
    try:
        for c in get_docker().containers.list(all=False, filters={"name": CONTAINER_PREFIX}):
            if (getattr(c, "name", "") or "").startswith(CONTAINER_PREFIX):
                count += 1
    except Exception:
        pass
    out["containers"] = count
    return jsonify(out)


def _container_live_stats(c) -> dict:
    """One-shot CPU% + memory for a container (docker stats). Best-effort; may return Nones."""
    try:
        s = c.stats(stream=False)
        cpu = s.get("cpu_stats", {}) or {}
        pre = s.get("precpu_stats", {}) or {}
        cd = (cpu.get("cpu_usage", {}) or {}).get("total_usage", 0) - (pre.get("cpu_usage", {}) or {}).get("total_usage", 0)
        sd = cpu.get("system_cpu_usage", 0) - pre.get("system_cpu_usage", 0)
        ncpu = cpu.get("online_cpus") or len((cpu.get("cpu_usage", {}) or {}).get("percpu_usage") or []) or 1
        cpu_pct = round((cd / sd) * ncpu * 100, 1) if sd > 0 and cd > 0 else 0.0
        mem = s.get("memory_stats", {}) or {}
        usage = mem.get("usage", 0) or 0
        mstats = mem.get("stats", {}) or {}
        cache = mstats.get("inactive_file", 0) or mstats.get("cache", 0) or 0
        mem_used = max(0, usage - cache)
        return {
            "cpu_pct": cpu_pct,
            "mem_mb": round(mem_used / 1048576, 1),
            "mem_limit_mb": round((mem.get("limit", 0) or 0) / 1048576),
        }
    except Exception:
        return {"cpu_pct": None, "mem_mb": None, "mem_limit_mb": None}


@app.route("/api/docker/containers", methods=["GET"])
def docker_containers():
    try:
        get_docker().ping()
        all_challenges = {c["id"]: c for c in load_challenges()}
        conts = [
            c for c in get_docker().containers.list(all=False, filters={"name": CONTAINER_PREFIX})
            if (getattr(c, "name", "") or "").startswith(CONTAINER_PREFIX)
        ]
        # Per-container docker stats are slow (~1s each), so only compute them when asked
        # (?stats=1). The menu loads the list instantly, then fetches stats in a second call.
        stats_by_name = {}
        if conts and request.args.get("stats"):
            from concurrent.futures import ThreadPoolExecutor
            with ThreadPoolExecutor(max_workers=min(8, len(conts))) as ex:
                for c, st in zip(conts, ex.map(_container_live_stats, conts)):
                    stats_by_name[c.name] = st
        rows = []
        for c in conts:
            name = c.name
            cid = name[len(CONTAINER_PREFIX):]
            chal = all_challenges.get(cid, {})
            agent_running = bool(cid in _agents and getattr(_agents[cid], "running", False))
            st = stats_by_name.get(name, {})
            rows.append({
                "cid": cid,
                "container_name": name,
                "status": getattr(c, "status", "unknown"),
                "challenge_name": chal.get("name") or "(deleted challenge)",
                "category": (chal.get("category") or "").upper(),
                "challenge_status": chal.get("status") or "unknown",
                "agent_running": agent_running,
                "manual_session": cid in _manual_mode_cids,
                "cpu_pct": st.get("cpu_pct"),
                "mem_mb": st.get("mem_mb"),
                "mem_limit_mb": st.get("mem_limit_mb"),
            })
        # Heaviest (by memory) first so hogs are obvious.
        rows.sort(key=lambda r: (0 if r["status"] == "running" else 1, -(r.get("mem_mb") or 0), r["challenge_name"].lower()))
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


# ── Login browser (real Chromium window) for the challenge importer ───────────
def _import_base_from(url: str) -> str:
    from urllib.parse import urlparse
    raw = (url or "").strip()
    parsed = urlparse(raw if raw.startswith(("http://", "https://")) else "https://" + raw)
    return f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else raw


# Captured session, kept for the whole app session so imports never reopen the login browser.
_import_captured = {"base": "", "url": "", "cookie": ""}


@app.route("/api/import/session", methods=["GET"])
def import_session_state():
    """What the modal shows on open: is a session already captured (→ straight to chat), or not
    (→ show the Log-in button)?"""
    import browser_session
    cap = bool(_import_captured.get("cookie") or (browser_session.get_session() and _import_captured.get("base")))
    return jsonify({"captured": cap, "base": _import_captured.get("base", ""),
                    "url": _import_captured.get("url", "")})


@app.route("/api/import/browser/open", methods=["POST"])
def import_browser_open():
    """Open the streamed login browser. `sid` is the caller's socket id — frames are streamed to it."""
    import browser_session
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    sid = data.get("sid") or ""
    if not url:
        return jsonify({"error": "Enter a platform URL."}), 400
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    _sess, ok, err = browser_session.open_session(url, sid=sid)
    if not ok:
        return jsonify({"error": err or "Failed to open browser."}), 500
    return jsonify({"ok": True})


@app.route("/api/import/browser/grab", methods=["POST"])
def import_browser_grab():
    """Operator is logged in. Capture the session (all cookies), STOP streaming (the login view
    closes), and keep the context alive so imports reuse it with no further browser window."""
    import browser_session, importer
    data = request.get_json(silent=True) or {}
    sess = browser_session.get_session()
    if not sess:
        return jsonify({"error": "The login browser isn't open."}), 400
    cur = sess.current_url()
    base = _import_base_from(data.get("base") or data.get("url") or cur)
    cookie = sess.cookie_header(base)
    sess.stop_streaming()
    _import_captured.update({"base": base, "url": cur, "cookie": cookie})
    out = {"ok": True, "base": base, "url": cur, "cookie": cookie, "challenges": []}
    try:
        conn = importer.connect_via_fetch(base, sess.fetch_json)
        out["platform"] = conn.get("platform")
        out["challenges"] = conn.get("challenges", [])
    except Exception:
        out["platform"] = ""
    return jsonify(out)


@app.route("/api/import/browser/close", methods=["POST"])
def import_browser_close():
    """Fully close the browser context (e.g. 'switch site'). Clears the captured session."""
    import browser_session
    browser_session.close_session()
    _import_captured.update({"base": "", "url": "", "cookie": ""})
    return jsonify({"ok": True})


@socketio.on("import_browser_input")
def on_import_browser_input(data):
    import browser_session
    sess = browser_session.get_session()
    if not sess:
        return
    p = data or {}
    t = p.get("type")
    try:
        if t == "click":     sess.click(p.get("x", 0), p.get("y", 0))
        elif t == "move":    sess.move(p.get("x", 0), p.get("y", 0))
        elif t == "scroll":  sess.scroll(p.get("dy", 0))
        elif t == "type":    sess.type_text(p.get("text", ""))
        elif t == "insert":  sess.insert(p.get("text", ""))
        elif t == "key":     sess.key(p.get("key", ""))
        elif t == "nav":     sess.navigate(p.get("url", ""))
        elif t == "back":    sess.back()
        elif t == "frame":   sess.refresh_frame()
    except Exception:
        pass


@socketio.on("import_browser_setsid")
def on_import_browser_setsid(_data=None):
    """Bind the live browser session's frame stream to this socket (after a reconnect)."""
    import browser_session
    sess = browser_session.get_session()
    if sess:
        sess.set_sid(request.sid)


@socketio.on("disconnect")
def on_disconnect():
    _close_manual_terminal_for_sid(request.sid)
