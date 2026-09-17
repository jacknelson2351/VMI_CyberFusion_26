"""
Login browser for the challenge importer.

Opens a real, visible Chromium window (Playwright, persistent profile) pointed at the CTF platform.
The operator logs in there directly — a genuine browser, so it sails through Cloudflare / "verify
you're human" walls, and the login is remembered next time via the persistent profile. We then read
the CTFd API *through that same browser* (so the real session and any Cloudflare clearance apply),
which is far more reliable than replaying a cookie from a separate HTTP client.

Single operator → a single global session. Playwright's sync API is thread-bound, so the session
owns a dedicated worker thread and every browser call runs through a command queue on that thread.
"""
from __future__ import annotations

import queue
import threading

from config import BASE_DIR

_UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")
_PROFILE_DIR = BASE_DIR / ".browser_profiles" / "import"


def _reap_profile():
    """A persistent-profile Chromium is single-instance: if a previous run was killed abruptly
    (server restart), its orphaned Chromium keeps the profile's Singleton lock and the next launch
    fails. Kill anything still using this profile and drop the stale lock files."""
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
    def __init__(self):
        self._q: "queue.Queue[tuple]" = queue.Queue()
        self._thread: threading.Thread | None = None
        self._alive = False
        self._ready = threading.Event()
        self._start_error = ""

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

    # ── requests onto the worker thread ──────────────────────────────────────
    def _call(self, op, timeout=30):
        box: dict = {"val": None, "err": None}
        done = threading.Event()
        self._q.put((op, {"box": box, "done": done}))
        if not done.wait(timeout=timeout):
            raise RuntimeError("browser timed out")
        if box["err"]:
            raise RuntimeError(box["err"])
        return box["val"]

    def read_page(self, url: str) -> dict:
        """Navigate a background page to `url` (JS rendered) and return its visible text + links,
        so the import agent can browse the logged-in site like a person. Returns
        {url, title, text, links:[{t,href}]}."""
        return self._call(("read_page", url), timeout=45)

    def fetch_json(self, url: str) -> dict:
        """GET a URL from inside the logged-in page (real session + Cloudflare clearance).
        Returns {status, ct, body}."""
        return self._call(("fetch_json", url))

    def fetch_bytes(self, url: str) -> dict:
        """GET binary (a challenge file) through the page. Returns {status, b64}."""
        return self._call(("fetch_bytes", url), timeout=60)

    def current_url(self) -> str:
        try:
            return self._call(("url", None), timeout=5) or ""
        except Exception:
            return ""

    def get_cookies(self) -> list:
        try:
            return self._call(("cookies", None), timeout=8) or []
        except Exception:
            return []

    def cookie_header(self, base_url: str) -> str:
        """Cookie: header string for base_url's host, from the live browser (HttpOnly + cf_clearance
        included) — this is the 'token' we hand to the importer once login is detected."""
        from urllib.parse import urlparse
        host = urlparse(base_url).hostname or ""
        parts = []
        for c in self.get_cookies():
            dom = (c.get("domain") or "").lstrip(".")
            if not dom or host.endswith(dom) or dom.endswith(host):
                parts.append(f"{c.get('name')}={c.get('value')}")
        return "; ".join(parts)

    # ── worker thread: owns the Playwright objects ───────────────────────────
    def _run(self, start_url: str):
        try:
            from playwright.sync_api import sync_playwright
        except Exception as e:
            self._start_error = f"Playwright not installed: {e}"
            self._ready.set()
            return
        try:
            _PROFILE_DIR.mkdir(parents=True, exist_ok=True)
            _reap_profile()
            with sync_playwright() as pw:
                ctx = pw.chromium.launch_persistent_context(
                    str(_PROFILE_DIR),
                    headless=False,                 # a real, visible window the operator drives
                    no_viewport=True,
                    user_agent=_UA,
                    locale="en-US",
                    args=[
                        "--disable-blink-features=AutomationControlled",
                        "--no-sandbox",
                        "--disable-infobars",
                        "--window-size=1280,900",
                        "--window-position=120,80",
                    ],
                    ignore_default_args=["--enable-automation"],
                )
                try:
                    ctx.add_init_script("Object.defineProperty(navigator,'webdriver',{get:()=>undefined});")
                except Exception:
                    pass
                page = ctx.pages[0] if ctx.pages else ctx.new_page()
                try:
                    page.bring_to_front()
                except Exception:
                    pass
                self._alive = True
                self._ready.set()
                try:
                    page.goto(start_url, timeout=30000, wait_until="domcontentloaded")
                except Exception:
                    pass

                while self._alive:
                    try:
                        op, arg = self._q.get(timeout=0.5)
                    except queue.Empty:
                        continue
                    if op == "stop":
                        break
                    self._handle(page, op, arg)
                try:
                    ctx.close()
                except Exception:
                    pass
        except Exception as e:
            self._start_error = str(e)
            self._ready.set()
        finally:
            self._alive = False

    def _handle(self, page, op, arg):
        kind, payload = op
        box, done = arg["box"], arg["done"]
        try:
            if kind == "url":
                box["val"] = page.url
            elif kind == "cookies":
                box["val"] = page.context.cookies()
            elif kind == "read_page":
                ap = getattr(self, "_agent_page", None)
                if ap is None:
                    ap = page.context.new_page()
                    self._agent_page = ap
                try:
                    ap.goto(payload, timeout=30000, wait_until="domcontentloaded")
                    try:
                        ap.wait_for_load_state("networkidle", timeout=4000)
                    except Exception:
                        ap.wait_for_timeout(500)
                    text = ap.evaluate("() => (document.body && document.body.innerText || '')")
                    # Gather link-like targets broadly: anchors, elements with download/data-href/
                    # data-url, and any href/src that looks like a downloadable file — so a
                    # "Download" button that isn't a plain <a href> is still discoverable.
                    links = ap.evaluate(
                        """() => {
                            const out = [], seen = new Set();
                            const push = (t, href) => {
                                if (!href) return;
                                try { href = new URL(href, location.href).href; } catch(e) { return; }
                                if (!/^https?:/.test(href) || seen.has(href)) return;
                                seen.add(href); out.push({t:(t||'').trim().slice(0,90), href});
                            };
                            document.querySelectorAll('a[href], [download], [data-href], [data-url], [data-download]').forEach(el => {
                                push(el.innerText || el.getAttribute('aria-label') || el.getAttribute('title'),
                                     el.getAttribute('href') || el.getAttribute('data-href') || el.getAttribute('data-url') || el.getAttribute('data-download'));
                            });
                            const rx = /\\.(zip|tar|gz|tgz|7z|rar|bin|elf|exe|key|pem|enc|pcap|pcapng|img|iso|jpg|jpeg|png|gif|bmp|wav|mp3|txt|csv|json|pdf|docx?|xlsx?|py|c|cpp|apk|jar|class|raw|dump|mem|vmdk|ova)(\\?|#|$)/i;
                            document.querySelectorAll('[href],[src]').forEach(el => {
                                const u = el.getAttribute('href') || el.getAttribute('src');
                                if (u && rx.test(u)) push(el.innerText || el.getAttribute('alt'), u);
                            });
                            return out.slice(0, 250);
                        }""")
                    box["val"] = {"url": ap.url, "title": ap.title(),
                                  "text": (text or "")[:9000], "links": links}
                except Exception as e:
                    box["val"] = {"url": payload, "title": "", "text": "", "links": [], "error": str(e)}
            elif kind == "fetch_json":
                box["val"] = page.evaluate(
                    """async (u) => {
                        try {
                            const r = await fetch(u, {headers:{'Accept':'application/json'}, credentials:'include'});
                            const t = await r.text();
                            return {status:r.status, ct:(r.headers.get('content-type')||''), body:t};
                        } catch (e) { return {status:0, ct:'', body:'', err:String(e)}; }
                    }""", payload)
            elif kind == "fetch_bytes":
                # Use Playwright's request API (carries the context's cookies, and — unlike an
                # in-page fetch — is NOT subject to CORS), so cross-origin artifact hosts like
                # artifacts.picoctf.net / S3 download fine.
                import base64 as _b64
                try:
                    r = page.context.request.get(payload, timeout=60000)
                    box["val"] = {"status": r.status, "b64": _b64.b64encode(r.body()).decode()}
                except Exception as e:
                    box["val"] = {"status": 0, "b64": "", "err": str(e)}
        except Exception as e:
            box["err"] = str(e)
        finally:
            done.set()


# ── module singleton ─────────────────────────────────────────────────────────
_session: BrowserSession | None = None
_lock = threading.Lock()


def open_session(url: str) -> tuple["BrowserSession | None", bool, str]:
    close_session()
    sess = BrowserSession()
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
