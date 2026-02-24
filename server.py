"""
Big Stein (The Penetrator) — Flask + Socket.IO backend
Open http://localhost:7331 in your browser
"""
import threading
import time
import webbrowser

from config import load_config, _as_bool
from extensions import app, socketio
import routes  # noqa: F401 — registers all @app.route and @socketio.on handlers

if __name__ == "__main__":
    cfg = load_config()
    auto_open_browser = _as_bool(cfg.get("auto_open_browser"), default=True)
    if auto_open_browser:
        def _open_browser():
            time.sleep(0.8)
            try:
                webbrowser.open("http://127.0.0.1:7331", new=2)
            except Exception:
                pass
        threading.Thread(target=_open_browser, daemon=True).start()

    print("\n  Big Stein (The Penetrator)")
    print("  ─────────────────────────────")
    print("  Open http://localhost:7331\n")
    socketio.run(app, host="0.0.0.0", port=7331, debug=False, allow_unsafe_werkzeug=True)
