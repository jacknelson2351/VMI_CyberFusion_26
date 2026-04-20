"""
Docker container management: ContainerConnection class, per-challenge registry,
and helpers for starting/stopping containers and syncing uploaded files.
"""
import re
import shutil
import threading
from datetime import datetime
from pathlib import Path

import docker

from db import get_challenge, update_challenge
from storage import build_challenge_environment, challenge_workspace_dir, write_workspace_manifest
from utils import _shell_quote

IMAGE_NAME       = "ctf-kali:latest"
CONTAINER_PREFIX = "ctf-agent-"
_docker_client   = None


def get_docker():
    global _docker_client
    if _docker_client is None:
        _docker_client = docker.from_env()
    return _docker_client


def image_exists() -> bool:
    try:
        get_docker().images.get(IMAGE_NAME)
        return True
    except Exception:
        return False


class ContainerConnection:
    def __init__(self, challenge_id: str):
        self.cid       = challenge_id
        self._lock     = threading.Lock()
        self.container = None
        self.workspace = challenge_workspace_dir(challenge_id)

    def start(self):
        name = f"{CONTAINER_PREFIX}{self.cid}"
        chal = get_challenge(self.cid) or {"id": self.cid}
        write_workspace_manifest(chal)
        env = {"TERM": "xterm-256color"}
        env.update(build_challenge_environment(chal))
        try:
            old = get_docker().containers.get(name)
            old.remove(force=True)
        except docker.errors.NotFound:
            pass
        self.container = get_docker().containers.run(
            IMAGE_NAME,
            name=name,
            command="sleep infinity",
            detach=True,
            remove=False,
            mem_limit="2g",
            cpu_period=100000,
            cpu_quota=200000,
            network_mode="bridge",
            privileged=False,
            security_opt=["no-new-privileges"],
            working_dir="/ctf",
            environment=env,
            volumes={
                str(self.workspace): {
                    "bind": "/ctf",
                    "mode": "rw",
                }
            },
        )
        self.run("mkdir -p /ctf /ctf/.sessions /ctf/.artifacts")

    def run(self, cmd: str, timeout: int = 60) -> str:
        with self._lock:
            if not self.container:
                return "[container not running]"
            try:
                # Normalize venv activation usage to avoid missing activate script.
                if "/ctf/.venv/bin/activate" in cmd:
                    cmd = cmd.replace("source /ctf/.venv/bin/activate && ", "")
                    cmd = re.sub(r"^\s*python(3(\.\d+)*)?\b", "/ctf/.venv/bin/python", cmd, count=1)
                    cmd = "python3 -m venv /ctf/.venv >/dev/null 2>&1 || true; " + cmd
                qcmd = _shell_quote(cmd)
                exec_cmd = f"bash -lc {qcmd}"
                if timeout and int(timeout) > 0:
                    # Enforce an execution deadline when available; fall back if `timeout` is missing.
                    exec_cmd = (
                        f"if command -v timeout >/dev/null 2>&1; then "
                        f"timeout {int(timeout)}s bash -lc {qcmd}; "
                        f"else bash -lc {qcmd}; fi"
                    )
                # Persist a live activity log that humans can tail from an attached shell.
                # This allows watching the agent's command/output stream in real time.
                ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
                qraw = _shell_quote(cmd)
                qexec = _shell_quote(exec_cmd)
                wrapped = (
                    "set -o pipefail; "
                    "LOG=/ctf/.agent_live.log; "
                    "touch \"$LOG\"; "
                    "printf '[%s] CMD %s\\n' "
                    + _shell_quote(ts)
                    + " "
                    + qraw
                    + " >> \"$LOG\"; "
                    "{ "
                    + "eval "
                    + qexec
                    + "; "
                    "rc=$?; "
                    "printf '[%s] EXIT %s\\n\\n' "
                    + _shell_quote(ts)
                    + " \"$rc\" >> \"$LOG\"; "
                    "exit \"$rc\"; "
                    "} 2>&1 | tee -a \"$LOG\"; "
                    "exit ${PIPESTATUS[0]}"
                )
                _, output = self.container.exec_run(
                    ["bash", "-lc", wrapped], workdir="/ctf",
                    demux=False
                )
                return (output or b"").decode("utf-8", errors="replace").strip()
            except Exception as e:
                return f"[exec error: {e}]"

    def run_gdb(self, binary: str, gdb_cmds: list, timeout: int = 60) -> str:
        batch = " ".join(f'-ex "{c}"' for c in gdb_cmds)
        cmd = (
            f'PWNDBG=$(ls /usr/share/pwndbg/gdbinit.py /opt/pwndbg/gdbinit.py 2>/dev/null | head -1); '
            f'if [ -n "$PWNDBG" ]; then '
            f'  gdb -batch -nx -ex "source $PWNDBG" {batch} {binary} 2>&1; '
            f'else '
            f'  gdb -batch -nx {batch} {binary} 2>&1; '
            f'fi'
        )
        return self.run(cmd, timeout)

    def upload_file(self, local_path: str) -> str:
        local = Path(local_path)
        fname = local.name
        dest = self.workspace / fname
        dest.parent.mkdir(parents=True, exist_ok=True)
        if local.resolve() != dest.resolve():
            shutil.copy2(local, dest)
        ext = local.suffix.lower()
        if self.running and ext == ".zip":
            self.run(f"cd /ctf && unzip -o '{fname}' 2>&1")
        elif self.running and ext in (".tar", ".gz", ".tgz", ".bz2", ".xz"):
            self.run(f"cd /ctf && tar xf '{fname}' 2>&1")
        return f"/ctf/{fname}"

    def write_file(self, fname: str, content: str) -> str:
        """Write a file directly into /ctf/ in the container."""
        fname = fname.lstrip("/").replace("../", "")
        target = self.workspace / fname
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return f"/ctf/{fname}"

    def stop(self):
        if self.container:
            try:
                self.container.remove(force=True)
            except Exception:
                pass
            self.container = None

    @property
    def running(self) -> bool:
        if not self.container:
            return False
        try:
            self.container.reload()
            return self.container.status == "running"
        except Exception:
            return False


# ── Per-challenge container registry ─────────────────────────────────────────

_containers: dict[str, ContainerConnection] = {}


def get_container(cid: str) -> ContainerConnection:
    if cid not in _containers or not _containers[cid].running:
        _containers[cid] = ContainerConnection(cid)
        _containers[cid].start()
    return _containers[cid]


def sync_challenge_uploads(cid: str, container: ContainerConnection):
    """Bind-mounted workspaces are already live inside /ctf/; just refresh metadata."""
    chal = get_challenge(cid)
    if chal:
        write_workspace_manifest(chal)
    files = []
    for p in sorted(container.workspace.iterdir()):
        if p.is_file() and not p.name.startswith("."):
            files.append(p.name)
    update_challenge(cid, files=files)
