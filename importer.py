"""
CTF platform importer — pull challenges (name, category, description, files, target, and a
flag-submission link) from a live CTF site into the active challenge set, so you don't hand-enter
every challenge.

Supports CTFd (by far the most common) with a shape that rCTF/others can slot into. Auth is a
session cookie (grab it after logging in) or an API/access token. No browser proxy needed.
"""
from __future__ import annotations

import base64
import json
import re
import uuid
from pathlib import Path

import requests

from storage import challenge_workspace_dir

# Match the login browser's UA — Cloudflare binds cf_clearance to the UA, so the grabbed token
# only keeps working if server-side requests present the same User-Agent.
_UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")
_TIMEOUT = 20


def _session(cookie: str = "", token: str = "") -> requests.Session:
    s = requests.Session()
    s.headers["User-Agent"] = _UA
    token = (token or "").strip()
    if token:
        # CTFd access tokens: "Authorization: Token <t>"; also try bare for rCTF Bearer later.
        s.headers["Authorization"] = token if token.lower().startswith(("token ", "bearer ")) else f"Token {token}"
    cookie = (cookie or "").strip()
    if cookie:
        for part in cookie.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                if k.strip():
                    s.cookies.set(k.strip(), v.strip())
    return s


def _norm_category(cat: str) -> str:
    c = (cat or "").strip().lower()
    aliases = {
        "pwn": "pwn", "binary": "pwn", "binary exploitation": "pwn", "exploitation": "pwn",
        "web": "web", "web exploitation": "web",
        "crypto": "crypto", "cryptography": "crypto",
        "rev": "rev", "reverse": "rev", "reversing": "rev", "reverse engineering": "rev",
        "forensics": "forensics", "forensic": "forensics",
        "osint": "osint",
        "network": "network", "networking": "network",
        "misc": "misc", "miscellaneous": "misc", "general": "misc", "general skills": "misc",
    }
    return aliases.get(c, c if c in ("pwn", "web", "crypto", "rev", "forensics", "osint", "network", "misc") else "misc")


def _norm_base(url: str) -> str:
    base = (url or "").strip().rstrip("/")
    if not base.startswith(("http://", "https://")):
        base = "https://" + base
    return base


def _parse_ctfd_listing(base: str, data: list) -> dict:
    chals = []
    for c in data:
        chals.append({
            "id": c.get("id"),
            "name": c.get("name") or "Untitled",
            "category": _norm_category(c.get("category")),
            "raw_category": c.get("category") or "",
            "value": c.get("value"),
            "solved": bool(c.get("solved_by_me")),
        })
    return {"platform": "ctfd", "base": base, "challenges": chals}


def connect_via_fetch(url: str, fetch_json) -> dict:
    """Same as connect(), but reads the CTFd API through a caller-supplied fetch (the login browser).
    `fetch_json(abs_url) -> {status, ct, body}`. This uses the real logged-in session, so it works
    behind Cloudflare where a replayed cookie would not."""
    base = _norm_base(url)
    res = fetch_json(f"{base}/api/v1/challenges")
    status, ct, body = res.get("status"), res.get("ct", ""), res.get("body", "")
    if status == 200 and ("application/json" in ct or (body or "").lstrip().startswith("{")):
        try:
            j = json.loads(body)
        except Exception:
            j = None
        if isinstance(j, dict) and isinstance(j.get("data"), list):
            return _parse_ctfd_listing(base, j["data"])
    # Not JSON (usually a login/redirect page) or an auth error → treat as not-logged-in yet.
    raise PermissionError("Not logged in yet — finish signing in, then this will detect the session.")


def connect(url: str, cookie: str = "", token: str = "") -> dict:
    """Detect the platform + list challenges. Returns {platform, base, challenges:[...]}."""
    base = _norm_base(url)
    s = _session(cookie, token)
    # ── CTFd ──────────────────────────────────────────────────────────────────
    r = s.get(f"{base}/api/v1/challenges", timeout=_TIMEOUT)
    if r.status_code == 200 and "application/json" in r.headers.get("content-type", ""):
        j = r.json()
        if isinstance(j, dict) and isinstance(j.get("data"), list):
            return _parse_ctfd_listing(base, j["data"])
    if r.status_code in (401, 403):
        raise PermissionError("Authentication failed — check your session cookie or token.")
    raise RuntimeError(
        f"Couldn't read challenges from {base} (HTTP {r.status_code}). "
        "Is this a CTFd site, and are you logged in / is the token correct?"
    )


def _ctfd_detail(s: requests.Session, base: str, cid) -> dict:
    r = s.get(f"{base}/api/v1/challenges/{cid}", timeout=_TIMEOUT)
    r.raise_for_status()
    return (r.json() or {}).get("data") or {}


def _safe_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", (name or "file")).strip("_") or "file"


def _build_challenge(base: str, raw_id, detail: dict, meta: dict) -> dict:
    name = detail.get("name") or (meta or {}).get("name") or "Untitled"
    category = _norm_category(detail.get("category") or (meta or {}).get("raw_category"))
    description = (detail.get("description") or "").strip()
    conn_info = (detail.get("connection_info") or "").strip()
    target_url = conn_info if conn_info.startswith(("http://", "https://", "nc ", "ws://", "wss://")) else ""
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    flag_url = f"{base}/challenges#{slug}-{raw_id}"
    return {
        "name": name,
        "category": category,
        "description": description + (f"\n\nConnection: {conn_info}" if conn_info and not target_url else ""),
        "flag_url": flag_url,
        "target": {"url": target_url} if target_url else {},
        "source_meta": {"platform": "ctfd", "source_url": base, "remote_id": raw_id,
                        "value": detail.get("value")},
        "tags": [t.get("value") for t in (detail.get("tags") or []) if isinstance(t, dict) and t.get("value")],
    }


def import_via_fetch(url: str, ids: list, listing: list, fetch_json, fetch_bytes,
                     create_fn=None) -> dict:
    """Import CTFd challenge ids by reading detail + files through the login browser's fetch
    (Cloudflare-proof). `fetch_json(abs_url)->{status,ct,body}`, `fetch_bytes(abs_url)->{status,b64}`."""
    base = _norm_base(url)
    by_id = {str(c["id"]): c for c in (listing or [])}
    created, failed = [], []
    for raw_id in ids:
        meta = by_id.get(str(raw_id)) or {}
        try:
            res = fetch_json(f"{base}/api/v1/challenges/{raw_id}")
            detail = (json.loads(res.get("body") or "{}") or {}).get("data") or {}
        except Exception as e:
            failed.append({"id": raw_id, "name": meta.get("name"), "error": f"detail: {e}"})
            continue
        challenge = _build_challenge(base, raw_id, detail, meta)
        cid = create_fn(challenge) if create_fn else None
        dl = []
        for fpath in (detail.get("files") or []):
            try:
                furl = fpath if fpath.startswith("http") else base + fpath
                fres = fetch_bytes(furl)
                if fres.get("status") == 200 and fres.get("b64"):
                    fname = _safe_name(furl.split("?")[0].rsplit("/", 1)[-1])
                    if cid:
                        dest = challenge_workspace_dir(cid) / fname
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        dest.write_bytes(base64.b64decode(fres["b64"]))
                    dl.append(fname)
            except Exception:
                pass
        created.append({"cid": cid, "name": challenge["name"], "category": challenge["category"],
                        "files": dl, "flag_url": challenge["flag_url"]})
    return {"platform": "ctfd", "base": base, "created": created, "failed": failed}


def import_challenges(url: str, ids: list, cookie: str = "", token: str = "",
                      create_fn=None) -> dict:
    """Import the given CTFd challenge ids. `create_fn(challenge_dict) -> cid` persists one and
    returns its new id (so we can download files into its workspace). Returns a summary."""
    conn = connect(url, cookie, token)
    base = conn["base"]
    s = _session(cookie, token)
    by_id = {str(c["id"]): c for c in conn["challenges"]}
    created, failed = [], []
    for raw_id in ids:
        key = str(raw_id)
        meta = by_id.get(key)
        if not meta:
            failed.append({"id": raw_id, "error": "not in listing"})
            continue
        try:
            detail = _ctfd_detail(s, base, raw_id)
        except Exception as e:
            failed.append({"id": raw_id, "name": meta.get("name"), "error": f"detail: {e}"})
            continue
        name = detail.get("name") or meta.get("name") or "Untitled"
        category = _norm_category(detail.get("category") or meta.get("raw_category"))
        description = (detail.get("description") or "").strip()
        conn_info = (detail.get("connection_info") or "").strip()
        target_url = conn_info if conn_info.startswith(("http://", "https://", "nc ", "ws://", "wss://")) else ""
        # CTFd deep-link to the challenge (where the flag is submitted).
        slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
        flag_url = f"{base}/challenges#{slug}-{raw_id}"

        challenge = {
            "name": name,
            "category": category,
            "description": description + (f"\n\nConnection: {conn_info}" if conn_info and not target_url else ""),
            "flag_url": flag_url,
            "target": {"url": target_url} if target_url else {},
            "source_meta": {"platform": "ctfd", "source_url": base, "remote_id": raw_id,
                            "value": detail.get("value")},
            "tags": [t.get("value") for t in (detail.get("tags") or []) if isinstance(t, dict) and t.get("value")],
        }
        cid = create_fn(challenge) if create_fn else None
        # Download files into the challenge workspace.
        dl = []
        for fpath in (detail.get("files") or []):
            try:
                furl = fpath if fpath.startswith("http") else base + fpath
                fr = s.get(furl, timeout=_TIMEOUT * 2)
                fr.raise_for_status()
                fname = _safe_name(furl.split("?")[0].rsplit("/", 1)[-1])
                if cid:
                    dest = challenge_workspace_dir(cid) / fname
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_bytes(fr.content)
                dl.append(fname)
            except Exception:
                pass
        created.append({"cid": cid, "name": name, "category": category, "files": dl,
                        "flag_url": flag_url})
    return {"platform": "ctfd", "base": base, "created": created, "failed": failed}
