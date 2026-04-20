import time

from storage import append_event_log, load_event_log

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
    append_event_log(cid, event, data)


def _load_log_events(cid: str) -> list[dict]:
    if cid in _logs and _logs[cid]:
        return list(_logs[cid])
    persisted = load_event_log(cid)
    if persisted:
        _logs[cid] = list(persisted)
    return list(persisted)
