"""
Persistent challenge storage helpers: workspace paths, run logs, notes, and schema normalization.
"""
from __future__ import annotations

import json
import shutil
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from config import RUNS_DIR, WORKSPACES_DIR


DEFAULT_TARGET = {
    "url": "",
    "host": "",
    "port": "",
    "protocol": "http",
    "entrypoint": "",
    "instance_label": "",
    "username": "",
    "password": "",
    "access_code": "",
    "proxy": "",
    "http_proxy": "",
    "https_proxy": "",
    "socks_proxy": "",
    "no_proxy": "",
    "cookies": "",
    "headers": "",
    "extra_env": "",
    "notes": "",
}

DEFAULT_SOURCE = {
    "platform": "",
    "event": "",
    "challenge_id": "",
    "points": "",
}

DEFAULT_CHALLENGE_FIELDS = {
    "files": [],
    "status": "unsolved",
    "flag": None,
    "flag_candidate": None,
    "flag_how": None,
    "approved_at": None,
    "writeup_md": None,
    "writeup_path": None,
    "writeup_ready_at": None,
    "retry_summary": None,
    "cost_usd": 0.0,
    "tokens_in": 0,
    "tokens_out": 0,
    "last_model": "",
    "notes": "",
    "tags": [],
    "credentials": [],
    "target": deepcopy(DEFAULT_TARGET),
    "source_meta": deepcopy(DEFAULT_SOURCE),
    "last_activity_at": None,
}

MEMORY_FILE_DEFAULTS = {
    "overview.md": "# Agent Overview\n\nNo agent memory saved yet.\n",
    "state.json": json.dumps({
        "status": "idle",
        "phase": "idle",
        "step": 0,
        "run_id": None,
        "active_hypothesis_id": None,
        "last_updated_at": None,
    }, indent=2) + "\n",
    "hypotheses.json": "[]\n",
    "facts.json": json.dumps({
        "confirmed": [],
        "ruled_out": [],
        "flag_candidates": [],
        "updated_at": None,
    }, indent=2) + "\n",
    "artifacts.json": "[]\n",
    "dead_ends.json": "[]\n",
    "candidates.json": json.dumps({
        "flags": [],
        "other": [],
        "updated_at": None,
    }, indent=2) + "\n",
}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def challenge_workspace_dir(cid: str) -> Path:
    p = WORKSPACES_DIR / str(cid)
    p.mkdir(parents=True, exist_ok=True)
    return p


def challenge_runs_dir(cid: str) -> Path:
    p = RUNS_DIR / str(cid)
    p.mkdir(parents=True, exist_ok=True)
    return p


def challenge_events_path(cid: str) -> Path:
    return challenge_runs_dir(cid) / "events.jsonl"


def challenge_notes_path(cid: str) -> Path:
    return challenge_runs_dir(cid) / "notes.md"


def challenge_workspace_manifest_path(cid: str) -> Path:
    return challenge_workspace_dir(cid) / ".challenge.json"


def challenge_memory_dir(cid: str) -> Path:
    p = challenge_runs_dir(cid) / "memory"
    p.mkdir(parents=True, exist_ok=True)
    return p


def challenge_memory_file_path(cid: str, name: str) -> Path:
    raw = str(name or "").strip()
    if raw not in MEMORY_FILE_DEFAULTS:
        raise ValueError(f"Unsupported memory file: {raw}")
    return challenge_memory_dir(cid) / raw


def normalize_string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        parts = [p.strip() for p in value.replace("\n", ",").split(",")]
        return [p for p in parts if p]
    if isinstance(value, list):
        out = []
        for item in value:
            s = str(item or "").strip()
            if s:
                out.append(s)
        return out
    return []


def normalize_credentials(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list):
        return []
    out = []
    for row in value:
        if not isinstance(row, dict):
            continue
        entry = {
            "label": str(row.get("label") or "").strip(),
            "username": str(row.get("username") or "").strip(),
            "password": str(row.get("password") or "").strip(),
            "notes": str(row.get("notes") or "").strip(),
        }
        if any(entry.values()):
            out.append(entry)
    return out


def normalize_target(value: Any) -> dict[str, str]:
    target = deepcopy(DEFAULT_TARGET)
    if isinstance(value, dict):
        for key in target:
            target[key] = str(value.get(key) or "").strip()
    return target


def normalize_source_meta(value: Any) -> dict[str, str]:
    source = deepcopy(DEFAULT_SOURCE)
    if isinstance(value, dict):
        for key in source:
            source[key] = str(value.get(key) or "").strip()
    return source


def apply_challenge_defaults(raw: dict[str, Any]) -> dict[str, Any]:
    chal = dict(raw or {})
    for key, default in DEFAULT_CHALLENGE_FIELDS.items():
        if key not in chal:
            chal[key] = deepcopy(default)
    chal["files"] = normalize_string_list(chal.get("files"))
    chal["tags"] = normalize_string_list(chal.get("tags"))
    chal["credentials"] = normalize_credentials(chal.get("credentials"))
    chal["target"] = normalize_target(chal.get("target"))
    chal["source_meta"] = normalize_source_meta(chal.get("source_meta"))
    chal["name"] = str(chal.get("name") or "Untitled").strip() or "Untitled"
    chal["category"] = str(chal.get("category") or "misc").strip().lower() or "misc"
    chal["flag_format"] = str(chal.get("flag_format") or "").strip()
    chal["description"] = str(chal.get("description") or "").strip()
    chal["notes"] = str(chal.get("notes") or "").strip()
    chal["id"] = str(chal.get("id") or "").strip()
    chal["created_at"] = str(chal.get("created_at") or utc_now_iso())
    chal["last_activity_at"] = str(chal.get("last_activity_at") or chal["created_at"])
    return chal


def write_workspace_manifest(chal: dict[str, Any]):
    cid = str(chal.get("id") or "").strip()
    if not cid:
        return
    manifest_path = challenge_workspace_manifest_path(cid)
    payload = {
        "id": cid,
        "name": chal.get("name") or "",
        "category": chal.get("category") or "",
        "flag_format": chal.get("flag_format") or "",
        "description": chal.get("description") or "",
        "tags": chal.get("tags") or [],
        "target": chal.get("target") or {},
        "source_meta": chal.get("source_meta") or {},
        "credentials": chal.get("credentials") or [],
        "notes": chal.get("notes") or "",
        "updated_at": utc_now_iso(),
    }
    manifest_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def append_event_log(cid: str, event: str, data: dict[str, Any]):
    entry = {"ts": utc_now_iso(), "event": event, "data": data}
    path = challenge_events_path(cid)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=True) + "\n")


def load_event_log(cid: str) -> list[dict[str, Any]]:
    path = challenge_events_path(cid)
    if not path.exists():
        return []
    out = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def append_note(cid: str, title: str, content: str, kind: str = "note") -> str:
    title = str(title or "").strip() or "Untitled Note"
    content = str(content or "").strip()
    stamp = utc_now_iso()
    path = challenge_notes_path(cid)
    block = (
        f"## {title}\n\n"
        f"- Kind: `{kind}`\n"
        f"- Captured: `{stamp}`\n\n"
        f"{content or '_No content provided._'}\n\n"
    )
    with path.open("a", encoding="utf-8") as f:
        f.write(block)
    return str(path)


def read_notes(cid: str) -> str:
    path = challenge_notes_path(cid)
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8")


def ensure_memory_files(cid: str):
    root = challenge_memory_dir(cid)
    for name, default_content in MEMORY_FILE_DEFAULTS.items():
        path = root / name
        if not path.exists():
            path.write_text(default_content, encoding="utf-8")


def list_memory_files(cid: str) -> list[dict[str, Any]]:
    root = challenge_memory_dir(cid)
    out = []
    for name in MEMORY_FILE_DEFAULTS:
        path = root / name
        if not path.exists():
            continue
        stat = path.stat()
        out.append({
            "name": name,
            "path": str(path),
            "size": stat.st_size,
            "updated_at": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat().replace("+00:00", "Z"),
        })
    return out


def read_memory_file(cid: str, name: str) -> str:
    path = challenge_memory_file_path(cid, name)
    if not path.exists():
        default_content = MEMORY_FILE_DEFAULTS.get(name, "")
        if default_content:
            path.write_text(default_content, encoding="utf-8")
        else:
            return ""
    return path.read_text(encoding="utf-8")


def write_memory_file(cid: str, name: str, content: str) -> str:
    path = challenge_memory_file_path(cid, name)
    path.write_text(str(content or ""), encoding="utf-8")
    return str(path)


def delete_memory_file(cid: str, name: str):
    path = challenge_memory_file_path(cid, name)
    if path.exists():
        path.unlink()


def clear_memory_files(cid: str):
    root = challenge_memory_dir(cid)
    if root.exists():
        shutil.rmtree(root, ignore_errors=True)


def build_challenge_environment(chal: dict[str, Any]) -> dict[str, str]:
    target = normalize_target(chal.get("target"))
    env = {}
    field_map = {
        "url": "CTF_TARGET_URL",
        "host": "CTF_TARGET_HOST",
        "port": "CTF_TARGET_PORT",
        "protocol": "CTF_TARGET_PROTOCOL",
        "entrypoint": "CTF_TARGET_ENTRYPOINT",
        "instance_label": "CTF_TARGET_INSTANCE",
        "username": "CTF_TARGET_USERNAME",
        "password": "CTF_TARGET_PASSWORD",
        "access_code": "CTF_TARGET_ACCESS_CODE",
    }
    for src_key, env_key in field_map.items():
        value = target.get(src_key, "")
        if value:
            env[env_key] = value
    proxy_candidates = {
        "http_proxy": target.get("http_proxy") or target.get("proxy"),
        "https_proxy": target.get("https_proxy") or target.get("proxy"),
        "all_proxy": target.get("socks_proxy"),
        "no_proxy": target.get("no_proxy"),
    }
    for key, value in proxy_candidates.items():
        if value:
            env[key] = value
            env[key.upper()] = value
    for line in str(target.get("extra_env") or "").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if key:
            env[key] = value
    return env


def workspace_listing(cid: str, max_depth: int = 4, include_hidden: bool = False) -> list[dict[str, Any]]:
    root = challenge_workspace_dir(cid)
    out = []
    for path in sorted(root.rglob("*")):
        if path == root:
            continue
        rel = path.relative_to(root)
        if rel.parts and len(rel.parts) > max_depth:
            continue
        if not include_hidden and any(part.startswith(".") for part in rel.parts):
            continue
        kind = "dir" if path.is_dir() else "file"
        size = path.stat().st_size if path.is_file() else 0
        out.append({
            "path": rel.as_posix(),
            "kind": kind,
            "size": size,
        })
    return out


def remove_challenge_artifacts(cid: str):
    for path in (WORKSPACES_DIR / str(cid), RUNS_DIR / str(cid)):
        if path.exists():
            shutil.rmtree(path, ignore_errors=True)


def normalize_import_payload(payload: Any) -> list[dict[str, Any]]:
    raw_items: list[Any]
    if isinstance(payload, list):
        raw_items = payload
    elif isinstance(payload, dict):
        if isinstance(payload.get("challenges"), list):
            raw_items = payload["challenges"]
        elif isinstance(payload.get("results"), list):
            raw_items = payload["results"]
        elif isinstance(payload.get("data"), list):
            raw_items = payload["data"]
        else:
            raw_items = [payload]
    else:
        raw_items = []

    out = []
    for item in raw_items:
        if not isinstance(item, dict):
            continue
        target = {
            "url": item.get("url") or item.get("connection") or item.get("instance_url") or "",
            "host": item.get("host") or "",
            "port": item.get("port") or "",
            "protocol": item.get("protocol") or "",
            "entrypoint": item.get("entrypoint") or "",
            "instance_label": item.get("instance_label") or item.get("instance") or "",
            "username": item.get("username") or "",
            "password": item.get("password") or "",
            "access_code": item.get("access_code") or "",
            "proxy": item.get("proxy") or "",
            "http_proxy": item.get("http_proxy") or "",
            "https_proxy": item.get("https_proxy") or "",
            "socks_proxy": item.get("socks_proxy") or "",
            "no_proxy": item.get("no_proxy") or "",
            "cookies": item.get("cookies") or "",
            "headers": item.get("headers") or "",
            "extra_env": item.get("extra_env") or "",
            "notes": item.get("target_notes") or "",
        }
        source_meta = {
            "platform": item.get("platform") or item.get("source_platform") or "",
            "event": item.get("event") or item.get("ctf") or "",
            "challenge_id": item.get("challenge_id") or item.get("source_id") or "",
            "points": item.get("points") or "",
        }
        normalized = apply_challenge_defaults({
            "name": item.get("name") or item.get("title") or "Untitled",
            "category": item.get("category") or "misc",
            "flag_format": item.get("flag_format") or "",
            "description": item.get("description") or item.get("prompt") or "",
            "tags": item.get("tags") or item.get("labels") or [],
            "notes": item.get("notes") or "",
            "target": target,
            "source_meta": source_meta,
            "credentials": item.get("credentials") or [],
        })
        out.append(normalized)
    return out
