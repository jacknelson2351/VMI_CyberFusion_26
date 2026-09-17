"""
Login browser for the challenge importer — network/remote-safe.

Big Stein usually runs on a different machine than the operator's browser (LAN box reached by IP),
so a Chromium window on the server is invisible to them. Instead the server runs Chromium and
STREAMS it into the import modal (CDP screencast → JPEG frames) with mouse/keyboard forwarded back,
so the operator drives a real browser remotely. Being a real headed browser it clears Cloudflare /
"verify you're human" walls; the persistent profile remembers the login next time.

The moment login is captured we stop streaming (the login view closes) and keep the browser context
alive so the import agent can read pages + download files through the same authenticated session —
no window is ever shown again. We also hand back a cookie header so imports can run off the token.

Single operator → one global session. Playwright's sync API is thread-bound, so the session owns a
dedicated worker thread and every browser call runs through a command queue on that thread.
"""
from __future__ import annotations

import base64
import queue
import threading
import time

from config import BASE_DIR
from extensions import socketio

_UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")
_VIEWPORT = {"width": 1180, "height": 760}
_PROFILE_DIR = BASE_DIR / ".browser_profiles" / "import"
_EMIT_MIN_INTERVAL = 0.04    # cap streamed frames ~25fps
_LAUNCH_ARGS = [
    "--disable-blink-features=AutomationControlled", "--no-sandbox", "--disable-infobars",
    "--window-position=-2400,0", "--window-size=1200,860",
    # Keep an off-screen headed window compositing so the screencast still produces frames.
    "--disable-features=CalculateNativeWinOcclusion",
    "--disable-backgrounding-occluded-windows", "--disable-renderer-backgrounding",
    "--disable-background-timer-throttling",
]


def _reap_profile():
    """A persistent-profile Chromium is single-instance: an orphan from an abrupt exit keeps the
    profile's Singleton lock and blocks the next launch. Kill it and drop the stale locks."""
    prof = str(_PROFILE_DIR)
    try:
        import psutil
        for p in psutil.process_iter(["pid", "cmdline"]):
            try:
                if prof in " ".join(p.info.get("cmdline") or []):
                    p.kill()
            except Exception:
                pass
    except Exception:
        pass
    for name in ("SingletonLock", "SingletonCookie", "SingletonSocket"):
        try:
            (_PROFILE_DIR / name).unlink()
        except Exception:
            pass


class BrowserSession:
    def __init__(self, sid: str = ""):
        self.sid = sid                     # socket room to stream frames to
        self.viewport = dict(_VIEWPORT)
        self._q: "queue.Queue[tuple]" = queue.Queue()
        self._thread: threading.Thread | None = None
        self._alive = False
        self._ready = threading.Event()
        self._start_error = ""
        self._streaming = True
        self._last_emit = 0.0
        self._last_url = ""
        self._agent_page = None

    # ── lifecycle ────────────────────────────────────────────────────────────
    def start(self, url: str) -> tuple[bool, str]:
        self._thread = threading.Thread(target=self._run, args=(url,), daemon=True)
        self._thread.start()
        self._ready.wait(timeout=60)
        return (self._alive, self._start_error)

    def stop(self):
        self._alive = False
        self._q.put(("stop", None))

    @property
    def alive(self) -> bool:
        return self._alive

    def set_sid(self, sid):
        self.sid = sid

    # ── streamed login input (enqueue onto the worker) ───────────────────────
    def click(self, x, y):   self._q.put(("click", {"x": x, "y": y}))
    def down(self, x, y):    self._q.put(("down", {"x": x, "y": y}))
    def up(self, x, y):      self._q.put(("up", {"x": x, "y": y}))
    def move(self, x, y):    self._q.put(("move", {"x": x, "y": y}))
    def scroll(self, dy):    self._q.put(("scroll", {"dy": dy}))
    def type_text(self, t):  self._q.put(("type", {"text": t}))
    def insert(self, t):     self._q.put(("insert", {"text": t}))     # paste
    def key(self, k):        self._q.put(("key", {"key": k}))
    def navigate(self, url): self._q.put(("nav", {"url": url}))
    def back(self):          self._q.put(("back", None))
    def refresh_frame(self): self._q.put(("frame", None))

    def stop_streaming(self):
        """Login captured → stop pushing frames (login view closes); keep the context for imports."""
        self._streaming = False
        self._q.put(("stop_stream", None))

    # ── blocking calls used by the import agent ──────────────────────────────
    def _call(self, op, timeout=45):
        box: dict = {"val": None, "err": None}
        done = threading.Event()
        self._q.put((op, {"box": box, "done": done}))
        if not done.wait(timeout=timeout):
            raise RuntimeError("browser timed out")
        if box["err"]:
            raise RuntimeError(box["err"])
        return box["val"]

    def read_page(self, url: str) -> dict:
        return self._call(("read_page", url), timeout=45)

    def fetch_json(self, url: str) -> dict:
        return self._call(("fetch_json", url), timeout=30)

    def fetch_bytes(self, url: str) -> dict:
        return self._call(("fetch_bytes", url), timeout=60)

    def get_cookies(self) -> list:
        try:
            return self._call(("cookies", None), timeout=8) or []
        except Exception:
            return []

    def current_url(self) -> str:
        try:
            return self._call(("url", None), timeout=5) or ""
        except Exception:
            return ""

    def login_probe(self) -> dict:
        """Best-effort generic 'is the operator logged in?' check — looks for a logout affordance
        on the live login page. Returns {url, logged_in}."""
        try:
            return self._call(("probe", None), timeout=6) or {}
        except Exception:
            return {}

    def cookie_header(self, base_url: str) -> str:
        from urllib.parse import urlparse
        host = urlparse(base_url).hostname or ""
        parts = []
        for c in self.get_cookies():
            dom = (c.get("domain") or "").lstrip(".")
            if not dom or host.endswith(dom) or dom.endswith(host):
                parts.append(f"{c.get('name')}={c.get('value')}")
        return "; ".join(parts)

    # ── worker thread ────────────────────────────────────────────────────────
    def _launch(self, pw):
        """A REAL headed Chromium — this is a genuine user session, not a bot, so we do NOT try to
        evade Cloudflare; the operator clears any human-check themselves in the stream, exactly as
        they would in their own browser. Headed browsers aren't flagged the way headless is. The
        window is positioned off-screen (it renders for the CDP stream but isn't shown on the server
        desktop). On a display-less server, set up a virtual display (e.g. xvfb) for this to run."""
        _PROFILE_DIR.mkdir(parents=True, exist_ok=True)
        _reap_profile()
        return pw.chromium.launch_persistent_context(
            str(_PROFILE_DIR), headless=False, args=_LAUNCH_ARGS,
            user_agent=_UA, locale="en-US", viewport=self.viewport,
            ignore_default_args=["--enable-automation"])

    def _run(self, start_url: str):
        try:
            from playwright.sync_api import sync_playwright
        except Exception as e:
            self._start_error = f"Playwright not installed: {e}"
            self._ready.set()
            return
        try:
            with sync_playwright() as pw:
                ctx = self._launch(pw)
                page = ctx.pages[0] if ctx.pages else ctx.new_page()
                self._alive = True
                self._ready.set()

                cdp = ctx.new_cdp_session(page)

                def on_frame(params):
                    try:
                        cdp.send("Page.screencastFrameAck", {"sessionId": params.get("sessionId")})
                    except Exception:
                        pass
                    if not (self._streaming and self.sid):
                        return
                    now = time.time()
                    if now - self._last_emit < _EMIT_MIN_INTERVAL:
                        return
                    self._last_emit = now
                    try:
                        url = page.url
                    except Exception:
                        url = self._last_url
                    self._last_url = url
                    socketio.emit("import_browser_frame",
                                  {"img": params.get("data", ""), "url": url,
                                   "w": self.viewport["width"], "h": self.viewport["height"]},
                                  room=self.sid)

                cdp.on("Page.screencastFrame", on_frame)
                self._start_screencast(cdp)
                try:
                    page.goto(start_url, timeout=30000, wait_until="domcontentloaded")
                except Exception:
                    pass

                while self._alive:
                    drained = False
                    try:
                        while True:
                            op, arg = self._q.get_nowait()
                            drained = True
                            if op == "stop":
                                self._alive = False
                                break
                            self._handle(page, cdp, op, arg)
                    except queue.Empty:
                        pass
                    if not self._alive:
                        break
                    if self._streaming:
                        try:
                            page.wait_for_timeout(45)     # pump screencast frames
                        except Exception:
                            time.sleep(0.05)
                    elif not drained:
                        # Not streaming: block for the next agent command instead of spinning.
                        try:
                            op, arg = self._q.get(timeout=0.5)
                            if op == "stop":
                                break
                            self._handle(page, cdp, op, arg)
                        except queue.Empty:
                            pass
                try:
                    ctx.close()
                except Exception:
                    pass
        except Exception as e:
            self._start_error = str(e)
            self._ready.set()
        finally:
            self._alive = False

    def _start_screencast(self, cdp):
        try:
            cdp.send("Page.startScreencast", {"format": "jpeg", "quality": 55,
                                              "maxWidth": self.viewport["width"],
                                              "maxHeight": self.viewport["height"], "everyNthFrame": 1})
        except Exception:
            pass

    def _handle(self, page, cdp, op, arg):
        # op is either a bare string (login input) or a ("name", payload) tuple (agent calls).
        if isinstance(op, tuple):
            name, payload = op
            box, done = arg["box"], arg["done"]
            try:
                if name == "url":
                    box["val"] = page.url
                elif name == "probe":
                    info = page.evaluate(
                        """() => {
                            const isAuthPage = /\\/(login|log-in|signin|sign-in|register|signup|sign-up|auth|sso|oauth)\\b/i.test(location.pathname);
                            const hasPassword = !!document.querySelector('input[type=password]');
                            const hasLogout = Array.from(document.querySelectorAll('a[href],button,[role=menuitem]')).some(a => {
                                const h = ((a.getAttribute && a.getAttribute('href')) || '').toLowerCase();
                                const x = (((a.innerText||'') + ' ' + ((a.getAttribute&&(a.getAttribute('aria-label')||a.getAttribute('title')))||''))).toLowerCase();
                                return h.includes('logout') || h.includes('signout') || h.includes('sign-out') || h.includes('log-out') || /\\blog ?out\\b|\\bsign ?out\\b/.test(x);
                            });
                            return {url: location.href, isAuthPage, hasPassword, hasLogout};
                        }""")
                    if info.get("hasPassword"):
                        self._saw_login_form = True
                    # Logged in if: a clear logout affordance exists, OR a login form we saw earlier
                    # is now gone on a non-auth page (a real transition through login).
                    logged_in = bool(info.get("hasLogout")) or (
                        getattr(self, "_saw_login_form", False)
                        and not info.get("hasPassword") and not info.get("isAuthPage"))
                    box["val"] = {"url": info.get("url"), "logged_in": logged_in}
                elif name == "cookies":
                    box["val"] = page.context.cookies()
                elif name == "read_page":
                    box["val"] = self._do_read_page(page, payload)
                elif name == "fetch_json":
                    box["val"] = page.evaluate(
                        """async (u) => { try {
                            const r = await fetch(u, {headers:{'Accept':'application/json'}, credentials:'include'});
                            return {status:r.status, ct:(r.headers.get('content-type')||''), body:await r.text()};
                        } catch(e){ return {status:0, ct:'', body:'', err:String(e)}; } }""", payload)
                elif name == "fetch_bytes":
                    try:
                        r = page.context.request.get(payload, timeout=60000)
                        box["val"] = {"status": r.status, "b64": base64.b64encode(r.body()).decode()}
                    except Exception as e:
                        box["val"] = {"status": 0, "b64": "", "err": str(e)}
            except Exception as e:
                box["err"] = str(e)
            finally:
                done.set()
            return
        # login input ops (no result)
        try:
            if op == "click":       page.mouse.click(arg["x"], arg["y"])
            elif op == "down":      page.mouse.move(arg["x"], arg["y"]); page.mouse.down()
            elif op == "up":        page.mouse.move(arg["x"], arg["y"]); page.mouse.up()
            elif op == "move":      page.mouse.move(arg["x"], arg["y"])
            elif op == "scroll":    page.mouse.wheel(0, arg["dy"])
            elif op == "type":      page.keyboard.type(arg["text"])
            elif op == "insert":    page.keyboard.insert_text(arg["text"])
            elif op == "key":       page.keyboard.press(arg["key"])
            elif op == "nav":
                u = arg["url"]
                if u and not u.startswith(("http://", "https://")):
                    u = "https://" + u
                page.goto(u, timeout=30000, wait_until="domcontentloaded")
            elif op == "back":      page.go_back(timeout=15000)
            elif op == "frame":     pass
            elif op == "stop_stream":
                try:
                    cdp.send("Page.stopScreencast")
                except Exception:
                    pass
        except Exception:
            pass

    def _do_read_page(self, page, url):
        ap = self._agent_page
        if ap is None:
            ap = page.context.new_page()
            self._agent_page = ap
        try:
            ap.goto(url, timeout=20000, wait_until="domcontentloaded")
            try:
                ap.wait_for_load_state("networkidle", timeout=1500)
            except Exception:
                pass
            text = ap.evaluate("() => (document.body && document.body.innerText || '')")
            links = ap.evaluate(
                """() => {
                    const out=[], seen=new Set();
                    const push=(t,href)=>{ if(!href) return;
                        try{ href=new URL(href, location.href).href }catch(e){ return }
                        if(!/^https?:/.test(href)||seen.has(href)) return; seen.add(href);
                        out.push({t:(t||'').trim().slice(0,90), href}); };
                    document.querySelectorAll('a[href],[download],[data-href],[data-url],[data-download]').forEach(el=>
                        push(el.innerText||el.getAttribute('aria-label')||el.getAttribute('title'),
                             el.getAttribute('href')||el.getAttribute('data-href')||el.getAttribute('data-url')||el.getAttribute('data-download')));
                    const rx=/\\.(zip|tar|gz|tgz|7z|rar|bin|elf|exe|key|pem|enc|pcap|pcapng|img|iso|jpg|jpeg|png|gif|bmp|wav|mp3|txt|csv|json|pdf|docx?|xlsx?|py|c|cpp|apk|jar|class|raw|dump|mem)(\\?|#|$)/i;
                    document.querySelectorAll('[href],[src]').forEach(el=>{ const u=el.getAttribute('href')||el.getAttribute('src');
                        if(u&&rx.test(u)) push(el.innerText||el.getAttribute('alt'),u); });
                    return out.slice(0,250);
                }""")
            return {"url": ap.url, "title": ap.title(), "text": (text or "")[:9000], "links": links}
        except Exception as e:
            return {"url": url, "title": "", "text": "", "links": [], "error": str(e)}


# ── module singleton ─────────────────────────────────────────────────────────
_session: BrowserSession | None = None
_lock = threading.Lock()


def open_session(url: str, sid: str = "") -> tuple["BrowserSession | None", bool, str]:
    close_session()
    sess = BrowserSession(sid=sid)
    ok, err = sess.start(url)
    if ok:
        with _lock:
            global _session
            _session = sess
    return (sess if ok else None), ok, err


def get_session() -> "BrowserSession | None":
    with _lock:
        return _session if (_session and _session.alive) else None


def close_session():
    global _session
    with _lock:
        sess = _session
        _session = None
    if sess:
        try:
            sess.stop()
        except Exception:
            pass
