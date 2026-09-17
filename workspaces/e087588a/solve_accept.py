#!/usr/bin/env python3
from pwn import *

# Patch-less solution: satisfy internal state machine by crafting the exact first-line input
# It appears to require input length 0x6a and winning number 1.

def run(inp: bytes):
    p = process(['/ctf/roulette'])
    p.send(inp)
    out = p.recvall(timeout=1).decode('utf-8','ignore')
    return out

# Build: '1' then pad with 'A' to total 0x6a bytes including trailing newline.
# Ensure newline exists and total length exactly 0x6a.
base=b'1'
# we need newline too
# total bytes = 0x6a
pad_len=0x6a - len(base) - 1
payload = base + b'A'*pad_len + b'\n'
print('payload_len',len(payload))
print(run(payload))
