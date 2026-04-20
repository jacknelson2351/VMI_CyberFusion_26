"""
High-level structured tools for the CTF agent.
"""
from __future__ import annotations

import json
from pathlib import Path

from db import update_challenge
from storage import append_note, challenge_workspace_dir, workspace_listing
from utils import _shell_quote


class StructuredToolsMixin:

    def _tool_list_files(self, args: dict) -> str:
        rel_path = str(args.get("path") or ".").strip() or "."
        max_depth = max(1, min(int(args.get("depth") or 3), 8))
        include_hidden = bool(args.get("include_hidden"))
        root = challenge_workspace_dir(self.cid)
        target = (root / rel_path.lstrip("/")).resolve() if rel_path != "." else root.resolve()
        if root.resolve() not in [target, *target.parents]:
            self._last_tool_progress = False
            return "[tool error] path escapes workspace"
        if not target.exists():
            self._last_tool_progress = False
            return f"[tool error] path not found: {rel_path}"

        entries = []
        if target.is_file():
            stat = target.stat()
            entries.append({
                "path": target.relative_to(root).as_posix(),
                "kind": "file",
                "size": stat.st_size,
            })
        else:
            base_rel = target.relative_to(root) if target != root else Path(".")
            for entry in workspace_listing(self.cid, max_depth=max_depth, include_hidden=include_hidden):
                ep = Path(entry["path"])
                if base_rel != Path(".") and base_rel not in ep.parents and ep != base_rel:
                    continue
                entries.append(entry)
        preview = []
        for item in entries[:120]:
            prefix = "d" if item["kind"] == "dir" else "f"
            size = item["size"]
            preview.append(f"{prefix} {size:>8} {item['path']}")
        out = "\n".join(preview) if preview else "(empty)"
        self.emit("command", {"cmd": f"list_files: {rel_path}"})
        self.emit("output", {"text": out})
        self._last_tool_progress = bool(entries)
        return self._truncate_for_context(out)

    def _tool_save_note(self, args: dict) -> str:
        title = str(args.get("title") or "Solver Note").strip() or "Solver Note"
        content = str(args.get("content") or "").strip()
        kind = str(args.get("kind") or "agent").strip() or "agent"
        path = append_note(self.cid, title=title, content=content, kind=kind)
        update_challenge(self.cid, last_activity_at=None)
        out = f"Saved note to {path}"
        self.emit("command", {"cmd": f"save_note: {title}"})
        self.emit("output", {"text": out})
        self._last_tool_progress = True
        return out

    def _tool_extract_artifact(self, args: dict) -> str:
        rel_path = str(args.get("path") or "").strip()
        destination = str(args.get("destination") or "").strip()
        password = str(args.get("password") or "").strip()
        tool = str(args.get("tool") or "auto").strip().lower() or "auto"
        if not rel_path:
            self._last_tool_progress = False
            return "[tool error] path is required"
        src = f"/ctf/{rel_path.lstrip('/')}"
        if not destination:
            destination = f"{Path(rel_path).stem}_extracted"
        dest = f"/ctf/{destination.lstrip('/')}"
        qsrc = _shell_quote(src)
        qdest = _shell_quote(dest)
        qpw = _shell_quote(password)
        suffix = Path(rel_path).suffix.lower()
        if tool == "auto":
            if suffix == ".zip":
                tool = "unzip"
            elif suffix in {".tgz", ".gz", ".bz2", ".xz", ".tar"} or rel_path.endswith(".tar.gz"):
                tool = "tar"
            elif suffix in {".7z", ".rar"}:
                tool = "7z"
            else:
                tool = "binwalk"
        if tool == "unzip":
            cmd = (
                f"mkdir -p {qdest} && "
                f"unzip -o {'-P ' + qpw if password else ''} {qsrc} -d {qdest} 2>&1 && "
                f"find {qdest} -maxdepth 3 -type f | sed 's#^/ctf/##' | sort | head -80"
            )
        elif tool == "tar":
            cmd = (
                f"mkdir -p {qdest} && "
                f"tar -xf {qsrc} -C {qdest} 2>&1 && "
                f"find {qdest} -maxdepth 3 -type f | sed 's#^/ctf/##' | sort | head -80"
            )
        elif tool == "7z":
            cmd = (
                f"mkdir -p {qdest} && "
                f"7z x {'-p' + password if password else ''} -y -o{qdest} {qsrc} 2>&1 && "
                f"find {qdest} -maxdepth 3 -type f | sed 's#^/ctf/##' | sort | head -80"
            )
        else:
            cmd = (
                f"mkdir -p {qdest} && "
                f"binwalk --run-as=root -e -C {qdest} {qsrc} 2>&1 && "
                f"find {qdest} -maxdepth 4 -type f | sed 's#^/ctf/##' | sort | head -80"
            )
        self.emit("command", {"cmd": f"extract_artifact: {rel_path} -> {destination} ({tool})"})
        out = self.container.run(cmd, timeout=120)
        self.emit("output", {"text": out})
        self._update_evidence_from_output(f"extract_artifact: {rel_path}", out)
        if self._maybe_auto_submit_from_output(out, source=f"extract_artifact: {rel_path}"):
            self._last_tool_progress = True
            return "Flag auto-submitted from extraction output."
        self._last_tool_progress = self._score_progress(out)
        return self._truncate_for_context(out)

    def _tool_http_request(self, args: dict) -> str:
        url = str(args.get("url") or "").strip()
        if not url:
            self._last_tool_progress = False
            return "[tool error] url is required"
        payload = {
            "url": url,
            "method": str(args.get("method") or "GET").strip().upper(),
            "headers": args.get("headers") if isinstance(args.get("headers"), dict) else {},
            "body": args.get("body"),
            "json_body": args.get("json_body"),
            "form": args.get("form") if isinstance(args.get("form"), dict) else {},
            "save_to": str(args.get("save_to") or "").strip(),
            "session_name": str(args.get("session_name") or "default").strip() or "default",
            "follow_redirects": bool(args.get("follow_redirects", True)),
            "timeout": max(5, min(int(args.get("timeout") or 20), 120)),
        }
        spec = _shell_quote(json.dumps(payload))
        cmd = (
            "python3 - "
            + spec
            + " <<'PY'\n"
            "import json, sys\n"
            "from pathlib import Path\n"
            "from http.cookiejar import MozillaCookieJar\n"
            "import requests\n"
            "spec = json.loads(sys.argv[1])\n"
            "session_name = spec.get('session_name') or 'default'\n"
            "session_dir = Path('/ctf/.sessions')\n"
            "session_dir.mkdir(parents=True, exist_ok=True)\n"
            "cookie_path = session_dir / f\"{session_name}.cookies.txt\"\n"
            "jar = MozillaCookieJar(str(cookie_path))\n"
            "if cookie_path.exists():\n"
            "    try:\n"
            "        jar.load(ignore_discard=True, ignore_expires=True)\n"
            "    except Exception:\n"
            "        pass\n"
            "sess = requests.Session()\n"
            "sess.cookies = jar\n"
            "resp = sess.request(\n"
            "    spec.get('method', 'GET').upper(),\n"
            "    spec['url'],\n"
            "    headers=spec.get('headers') or None,\n"
            "    data=spec.get('body') if spec.get('body') is not None else (spec.get('form') or None),\n"
            "    json=spec.get('json_body'),\n"
            "    allow_redirects=bool(spec.get('follow_redirects', True)),\n"
            "    timeout=int(spec.get('timeout') or 20),\n"
            ")\n"
            "sess.cookies.save(ignore_discard=True, ignore_expires=True)\n"
            "save_to = (spec.get('save_to') or '').lstrip('/')\n"
            "saved_path = ''\n"
            "if save_to:\n"
            "    dest = Path('/ctf') / save_to\n"
            "    dest.parent.mkdir(parents=True, exist_ok=True)\n"
            "    dest.write_bytes(resp.content)\n"
            "    saved_path = str(dest)\n"
            "print(f'STATUS {resp.status_code}')\n"
            "print(f'FINAL_URL {resp.url}')\n"
            "print(f'COOKIE_JAR {cookie_path}')\n"
            "if saved_path:\n"
            "    print(f'SAVED_TO {saved_path}')\n"
            "for key, value in list(resp.headers.items())[:20]:\n"
            "    print(f'HEADER {key}: {value}')\n"
            "print('')\n"
            "print('BODY_PREVIEW')\n"
            "text = resp.text[:4000]\n"
            "print(text)\n"
            "PY"
        )
        label = f"http_request: {payload['method']} {url}"
        self.emit("command", {"cmd": label})
        out = self.container.run(cmd, timeout=payload["timeout"] + 10)
        self.emit("output", {"text": out})
        self._update_evidence_from_output(label, out)
        if self._maybe_auto_submit_from_output(out, source=f"http_request: {url}"):
            self._last_tool_progress = True
            return "Flag auto-submitted from HTTP response."
        self._last_tool_progress = self._score_progress(out)
        return self._truncate_for_context(out)
