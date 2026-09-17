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
        self._last_tool_progress = False  # bookkeeping only, not evidence of forward progress
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
        # Auto-scan extracted contents for flag patterns
        had_progress = self._score_progress(out)
        if had_progress and self.running:
            scan = self.container.run(
                f"grep -rE '[A-Za-z0-9_]{{2,24}}\\{{[^{{}}\\n]{{1,220}}\\}}' {qdest} 2>/dev/null | head -30",
                timeout=20,
            )
            if scan and scan.strip():
                self.emit("output", {"text": f"[flag scan]\n{scan}"})
                if self._maybe_auto_submit_from_output(scan, source=f"extract_artifact_scan: {rel_path}"):
                    self._last_tool_progress = True
                    return "Flag auto-submitted from extraction scan."
        self._last_tool_progress = had_progress
        return self._truncate_for_context(out)

    def _tool_analyze_image(self, args: dict) -> str:
        """Send an image to a vision model and return what it depicts. The harness otherwise
        only sends text, so image challenges (OSINT geolocation, stego carriers, screenshots)
        were being solved blind through OCR. Uses the solver model (modern GPT/Claude are
        multimodal)."""
        import base64 as _b64
        rel = str(args.get("path") or "").strip()
        question = str(args.get("question") or "Describe this image in detail. Transcribe all "
                       "visible text exactly. Note any landmarks, signs, or identifying features.").strip()
        if not rel:
            self._last_tool_progress = False
            return "[tool error] path is required"
        root = challenge_workspace_dir(self.cid)
        target = (root / rel.lstrip("/")).resolve()
        if root.resolve() not in [target, *target.parents] or not target.is_file():
            self._last_tool_progress = False
            return f"[tool error] image not found in workspace: {rel}"
        raw = target.read_bytes()
        if len(raw) > 5 * 1024 * 1024:
            self._last_tool_progress = False
            return ("[tool error] image >5MB; downscale it first, e.g. run_command "
                    f"\"convert /ctf/{rel} -resize 1600x1600 /ctf/small.png\" then analyze small.png")
        ext = target.suffix.lower().lstrip(".")
        mime = {"jpg": "jpeg", "jpeg": "jpeg", "png": "png", "gif": "gif", "webp": "webp"}.get(ext, "png")
        b64 = _b64.b64encode(raw).decode("ascii")
        self.emit("command", {"cmd": f"analyze_image: {rel}"})
        try:
            if self.provider == "anthropic" and self.anthropic_client:
                resp = self.anthropic_client.messages.create(
                    model=self.model, max_tokens=1024,
                    messages=[{"role": "user", "content": [
                        {"type": "text", "text": question},
                        {"type": "image", "source": {"type": "base64",
                         "media_type": f"image/{mime}", "data": b64}},
                    ]}],
                )
                usage = getattr(resp, "usage", None)
                if usage:
                    self._emit_cost(int(getattr(usage, "input_tokens", 0) or 0),
                                    int(getattr(usage, "output_tokens", 0) or 0))
                out = "".join(getattr(b, "text", "") for b in getattr(resp, "content", [])
                              if getattr(b, "type", "") == "text").strip()
            elif self.openai_client:
                resp = self.openai_client.chat.completions.create(
                    model=self.model,
                    messages=[{"role": "user", "content": [
                        {"type": "text", "text": question},
                        {"type": "image_url", "image_url": {"url": f"data:image/{mime};base64,{b64}"}},
                    ]}],
                )
                usage = getattr(resp, "usage", None)
                if usage:
                    self._emit_cost(int(getattr(usage, "prompt_tokens", 0) or 0),
                                    int(getattr(usage, "completion_tokens", 0) or 0))
                out = (resp.choices[0].message.content or "").strip()
            else:
                self._last_tool_progress = False
                return "[tool error] no vision-capable client configured"
        except Exception as e:
            self._last_tool_progress = False
            return f"[tool error] analyze_image: {e}"
        out = out or "(vision model returned no description)"
        self.emit("output", {"text": out})
        self._update_evidence_from_output(f"analyze_image: {rel}", out)
        if self._maybe_auto_submit_from_output(out, source=f"analyze_image: {rel}"):
            self._last_tool_progress = True
            return "Flag auto-submitted from image analysis."
        self._last_tool_progress = bool(out and "no description" not in out)
        return self._truncate_for_context(out)

    def _tool_remote_interact(self, args: dict) -> str:
        """Interactive TCP (nc-style) or WebSocket exchange with a remote service.
        Fixes two gaps: WS-only backends (umdmarket/rainbet) were totally unreachable, and
        hand-rolled socket readline loops deadlocked against prompts."""
        url = str(args.get("url") or "").strip()
        host = str(args.get("host") or "").strip()
        port = str(args.get("port") or "").strip()
        target = self.target if isinstance(self.target, dict) else {}
        if not url and not host:
            url = str(target.get("url") or "").strip()
            host = str(target.get("host") or "").strip()
            port = port or str(target.get("port") or "").strip()
        send = args.get("send")
        if isinstance(send, str):
            send = [send]
        if not isinstance(send, list):
            send = []
        payload = {
            "url": url,
            "host": host,
            "port": port,
            "send": [str(s) for s in send],
            "recv_timeout": max(1, min(int(args.get("recv_timeout") or 6), 120)),
            "read_until": str(args.get("read_until") or ""),
            "overall_timeout": max(2, min(int(args.get("overall_timeout") or 30), 300)),
        }
        spec = _shell_quote(json.dumps(payload))
        cmd = (
            "python3 - " + spec + " <<'PY'\n"
            "import json,sys,socket,time\n"
            "s=json.loads(sys.argv[1])\n"
            "url=(s.get('url') or '').strip()\n"
            "def log(*a): print(*a)\n"
            "if url.startswith('ws://') or url.startswith('wss://'):\n"
            "    try:\n"
            "        import websocket\n"
            "    except Exception:\n"
            "        import subprocess; subprocess.run(['pip','install','-q','websocket-client'])\n"
            "        import websocket\n"
            "    ws=websocket.create_connection(url, timeout=s['recv_timeout'])\n"
            "    log('WS CONNECTED', url)\n"
            "    try:\n"
            "        ws.settimeout(s['recv_timeout'])\n"
            "        try:\n"
            "            log('RECV<', ws.recv())\n"
            "        except Exception: pass\n"
            "        for msg in s['send']:\n"
            "            ws.send(msg); log('SEND>', msg)\n"
            "            try: log('RECV<', ws.recv())\n"
            "            except Exception as e: log('(no reply:', e, ')')\n"
            "    finally:\n"
            "        ws.close()\n"
            "else:\n"
            "    host=s.get('host') or ''; port=int(s.get('port') or 0)\n"
            "    if url.startswith('tcp://'):\n"
            "        rest=url[6:]; host=rest.split(':')[0]; port=int(rest.split(':')[1])\n"
            "    if not host or not port:\n"
            "        print('[error] no host/port'); sys.exit(0)\n"
            "    sock=socket.create_connection((host,port), timeout=s['recv_timeout'])\n"
            "    sock.settimeout(s['recv_timeout'])\n"
            "    log('TCP CONNECTED', host, port)\n"
            "    def drain():\n"
            "        buf=b''\n"
            "        try:\n"
            "            while True:\n"
            "                d=sock.recv(4096)\n"
            "                if not d: break\n"
            "                buf+=d\n"
            "                if s['read_until'] and s['read_until'].encode() in buf: break\n"
            "                if len(buf)>65536: break\n"
            "        except Exception: pass\n"
            "        return buf.decode('utf-8','replace')\n"
            "    log('RECV<', drain())\n"
            "    for line in s['send']:\n"
            "        data=(line if line.endswith(chr(10)) else line+chr(10)).encode()\n"
            "        sock.sendall(data); log('SEND>', line)\n"
            "        log('RECV<', drain())\n"
            "    sock.close()\n"
            "PY"
        )
        label = f"remote_interact: {url or (host + ':' + port)}"
        self.emit("command", {"cmd": label})
        out = self.container.run(cmd, timeout=payload["overall_timeout"] + 10)
        self.emit("output", {"text": out})
        self._update_evidence_from_output(label, out)
        if self._maybe_auto_submit_from_output(out, source=f"remote_interact: {url or host}"):
            self._last_tool_progress = True
            return "Flag auto-submitted from remote interaction."
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
            "files": args.get("files") if isinstance(args.get("files"), dict) else {},
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
            "files_spec = spec.get('files') or {}\n"
            "req_files = None\n"
            "opened_handles = []\n"
            "def ctf_path(value):\n"
            "    raw = str(value or '')\n"
            "    if raw.startswith('/ctf/'):\n"
            "        return Path(raw)\n"
            "    return Path('/ctf') / raw.lstrip('/')\n"
            "if files_spec:\n"
            "    req_files = {}\n"
            "    for field, val in files_spec.items():\n"
            "        if isinstance(val, dict):\n"
            "            fpath_full = ctf_path(val.get('path'))\n"
            "            fname = val.get('filename') or fpath_full.name\n"
            "            mime = val.get('mime_type') or val.get('mime') or 'application/octet-stream'\n"
            "            fh = open(fpath_full, 'rb')\n"
            "            opened_handles.append(fh)\n"
            "            req_files[field] = (fname, fh, mime)\n"
            "        elif isinstance(val, list) and len(val) >= 2:\n"
            "            fname, fpath = val[0], val[1]\n"
            "            mime = val[2] if len(val) > 2 else 'application/octet-stream'\n"
            "            fh = open(ctf_path(fpath), 'rb')\n"
            "            opened_handles.append(fh)\n"
            "            req_files[field] = (fname, fh, mime)\n"
            "        else:\n"
            "            fpath_full = ctf_path(val)\n"
            "            fh = open(fpath_full, 'rb')\n"
            "            opened_handles.append(fh)\n"
            "            req_files[field] = (fpath_full.name, fh, 'application/octet-stream')\n"
            "try:\n"
            "    if req_files:\n"
            "        resp = sess.request(\n"
            "            spec.get('method', 'GET').upper(),\n"
            "            spec['url'],\n"
            "            headers=spec.get('headers') or None,\n"
            "            data=spec.get('form') or None,\n"
            "            files=req_files,\n"
            "            allow_redirects=bool(spec.get('follow_redirects', True)),\n"
            "            timeout=int(spec.get('timeout') or 20),\n"
            "        )\n"
            "    else:\n"
            "        resp = sess.request(\n"
            "            spec.get('method', 'GET').upper(),\n"
            "            spec['url'],\n"
            "            headers=spec.get('headers') or None,\n"
            "            data=spec.get('body') if spec.get('body') is not None else (spec.get('form') or None),\n"
            "            json=spec.get('json_body'),\n"
            "            allow_redirects=bool(spec.get('follow_redirects', True)),\n"
            "            timeout=int(spec.get('timeout') or 20),\n"
            "        )\n"
            "finally:\n"
            "    for fh in opened_handles:\n"
            "        try: fh.close()\n"
            "        except Exception: pass\n"
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
