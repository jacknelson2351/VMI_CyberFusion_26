"""
EvidenceMixin — evidence tracking, forensics/rev fast-paths, output parsing.
"""
import re


class EvidenceMixin:

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

    def _run_rev_qna_fastpath(self, recon: str, challenge_desc: str) -> str:
        if self.category != "rev":
            return ""
        ctx = f"{challenge_desc}\n{recon}".lower()
        if "questions" not in ctx and "each correct answer solves one flag" not in ctx:
            return ""
        if "rechallenge1" not in ctx and "reverse engineering challenge 1" not in ctx:
            return ""

        self.emit("thought", {"text": "Running rev Q/A fast-path for filetype/packer/domain/IP extraction.", "type": "system"})
        cmd = (
            "unzip -P infected -o /ctf/REChallenge1.zip -d /ctf >/dev/null 2>&1 || true; "
            "python3 - <<'PY'\n"
            "import re, subprocess\n"
            "from pathlib import Path\n"
            "exe = Path('/ctf/REChallenge1.exe')\n"
            "if not exe.exists():\n"
            "    print('FAST_ANS_MISSING=REChallenge1.exe')\n"
            "    raise SystemExit(0)\n"
            "try:\n"
            "    fline = subprocess.check_output(['file', str(exe)], stderr=subprocess.STDOUT).decode('utf-8', 'ignore').strip()\n"
            "except Exception:\n"
            "    fline = ''\n"
            "packed = exe.read_bytes()\n"
            "packer = 'UPX' if (b'UPX0' in packed or b'UPX1' in packed or b'UPX!' in packed) else 'UNKNOWN'\n"
            "unpacked = Path('/ctf/REChallenge1_unpacked_fast.exe')\n"
            "if unpacked.exists():\n"
            "    unpacked.unlink()\n"
            "subprocess.run(['upx', '-d', '-o', str(unpacked), str(exe)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)\n"
            "cands = [unpacked, Path('/ctf/REChallenge1_unpacked.exe'), Path('/ctf/REChallenge1_upx_unpacked.exe'), exe]\n"
            "target = next((p for p in cands if p.exists()), exe)\n"
            "data = target.read_bytes()\n"
            "def valid_ip(s):\n"
            "    try:\n"
            "        p = [int(x) for x in s.split('.')]\n"
            "        return len(p) == 4 and all(0 <= x <= 255 for x in p)\n"
            "    except Exception:\n"
            "        return False\n"
            "ips = []\n"
            "for m in re.finditer(rb'(?<!\\d)(?:\\d{1,3}\\.){3}\\d{1,3}(?!\\d)', data):\n"
            "    s = m.group(0).decode('ascii', 'ignore')\n"
            "    if valid_ip(s):\n"
            "        ips.append(s)\n"
            "ip = ips[0] if ips else ''\n"
            "domains = []\n"
            "for m in re.finditer(rb'(?i)\\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+(?:com|net|org|io|ru|cn|xyz|info|biz)\\b', data):\n"
            "    d = m.group(0).decode('ascii', 'ignore').lower().strip('.')\n"
            "    if d.endswith(('.dll', '.exe', '.sys', '.obj', '.lib', '.pdb', '.startup', '.part', '.mingw')):\n"
            "        continue\n"
            "    domains.append(d)\n"
            "if not domains:\n"
            "    i = 0\n"
            "    mov_domains = []\n"
            "    while i + 4 <= len(data):\n"
            "        if data[i] == 0xC6 and data[i + 1] == 0x45:\n"
            "            j = i\n"
            "            prev = None\n"
            "            seq = []\n"
            "            while j + 4 <= len(data) and data[j] == 0xC6 and data[j + 1] == 0x45:\n"
            "                off = data[j + 2]\n"
            "                ch = data[j + 3]\n"
            "                if prev is not None and ((off - prev) & 0xff) != 1:\n"
            "                    break\n"
            "                prev = off\n"
            "                seq.append(ch)\n"
            "                j += 4\n"
            "            if len(seq) >= 6:\n"
            "                s = bytes(seq).split(b'\\x00', 1)[0].decode('latin1', 'ignore').lower()\n"
            "                if re.fullmatch(r'[a-z0-9-]{1,63}(?:\\.[a-z0-9-]{1,63})+', s):\n"
            "                    mov_domains.append(s)\n"
            "            i = j if j > i else i + 1\n"
            "        else:\n"
            "            i += 1\n"
            "    domains = mov_domains\n"
            "domain = domains[0] if domains else ''\n"
            "print('FAST_ANS_FILETYPE=' + fline)\n"
            "print('FAST_ANS_PACKER=' + packer)\n"
            "if domain:\n"
            "    print('FAST_ANS_DOMAIN=' + domain)\n"
            "if ip:\n"
            "    print('FAST_ANS_IP=' + ip)\n"
            "PY"
        )
        self.emit("command", {"cmd": "[rev-fastpath] extract filetype/packer/domain/ip"})
        out = self.container.run(cmd, timeout=120)
        self.emit("output", {"text": out})
        self._update_evidence_from_output("rev-fastpath", out)

        answers = {}
        for m in re.finditer(r"^FAST_ANS_([A-Z_]+)=(.*)$", out or "", re.MULTILINE):
            answers[m.group(1)] = (m.group(2) or "").strip()

        ftype = answers.get("FILETYPE", "")
        if ftype:
            self._add_evidence("confirmed", ftype[:220])
            if re.search(r"\bPE32\+\s+executable\b", ftype, re.IGNORECASE):
                self._remember_answer_candidate("PE32+ executable")
        packer = answers.get("PACKER", "")
        if packer:
            self._remember_answer_candidate(packer)
        domain = answers.get("DOMAIN", "")
        if domain:
            self._remember_answer_candidate(domain)
            self._add_evidence("confirmed", f"Recovered domain candidate: {domain}")
        ip = answers.get("IP", "")
        if ip:
            self._remember_answer_candidate(ip)
            self._add_evidence("confirmed", f"Recovered IP candidate: {ip}")

        if answers:
            parts = []
            if ftype:
                parts.append(f"filetype={ftype}")
            if packer:
                parts.append(f"packer={packer}")
            if domain:
                parts.append(f"domain={domain}")
            if ip:
                parts.append(f"ip={ip}")
            self.emit("thought", {"text": "RE fast-path facts: " + "; ".join(parts), "type": "reasoning"})

        facts = []
        if ftype:
            facts.append(f"- filetype: {ftype}")
        if packer:
            facts.append(f"- packer: {packer}")
        if domain:
            facts.append(f"- domain: {domain}")
        if ip:
            facts.append(f"- ip: {ip}")
        if not facts:
            return ""
        return "\n\n[REV FAST-PATH FACTS]\n" + "\n".join(facts) + "\n"

    def _update_evidence_from_output(self, cmd: str, output: str):
        out = output or ""
        if not out:
            return
        self._harvest_answer_candidates(out)
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
