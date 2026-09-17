#!/usr/bin/env python3
import re, subprocess

data = subprocess.check_output(['objdump','-s','-j','.rodata','/ctf/roulette']).decode('utf-8','ignore').splitlines()
# lines look like: ' 499000 01000200 00000000 2849676e 6f726520  ........(Ignore '
hexline=re.compile(r'^\s*([0-9a-fA-F]+)\s+((?:[0-9a-fA-F]{8}\s+)+)')
chunks=[]
for line in data:
    m=hexline.match(line)
    if not m:
        continue
    addr=int(m.group(1),16)
    bs=b''
    for word in m.group(2).split():
        if len(word)!=8:
            continue
        bs += bytes.fromhex(word)
    chunks.append((addr,bs))

if not chunks:
    raise SystemExit('No rodata chunks parsed')
chunks.sort()
base=chunks[0][0]
blob=b''
cur=base
for a,bs in chunks:
    if a>cur:
        blob += b'\x00'*(a-cur)
        cur=a
    blob += bs
    cur += len(bs)

print('rodata base',hex(base),'size',len(blob))

# extract strings containing braces/flag tokens
hits=[]
cur_s=b''; start=0
for i,b in enumerate(blob):
    if 32<=b<127:
        if not cur_s:
            start=i
        cur_s += bytes([b])
    else:
        if len(cur_s)>=4:
            s=cur_s.decode('ascii','ignore')
            if '{' in s or 'flag' in s.lower():
                hits.append((base+start,s))
        cur_s=b''

for addr,s in hits[:200]:
    print(hex(addr), s)
print('total hits',len(hits))
