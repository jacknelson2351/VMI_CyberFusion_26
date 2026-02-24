import time

_agents: dict = {}
_logs: dict = {}

def _log_event(cid: str, event: str, data: dict):
    if not cid:
        return
    buf = _logs.setdefault(cid, [])
    buf.append({"ts": time.time(), "event": event, "data": data})
    # cap log size to avoid unbounded growth
    if len(buf) > 2000:
        del buf[:200]
