#!/usr/bin/env python3
from pwn import *
context.log_level = 'error'

def run(payload: bytes) -> bytes:
    p = process(['/ctf/roulette'])
    p.send(payload)
    out = p.recvall(timeout=1)
    return out

# We observed: parsing/win is easy ("1" wins), but there's a hidden 27-round state-machine
# that gates printing "accepted". We must satisfy its checks.
#
# The check at 0x4018d8 iterates rdx from 0..?? and, for each of 4 bytes (ecx=0,8,16,24),
# ORs bits from r14[rdx] shifted by cl into edi, but only when rdx <= 0x69.
# This is equivalent to building a 32-bit little-endian word from 4 consecutive bytes of the input
# at offsets rdx, rdx+1, rdx+2, rdx+3 (with the special rule that bytes past 0x69 are treated as 0).
# Then eax = edi xor eax0 (eax0 is some running value), compared to table[rbp].
#
# We can treat this as a constrained system and solve by observing that our input only has 0x6a bytes.
# So for rdx > 0x69, bytes are 0, making words near end partially zero.
#
# Practical approach: brute-force rdx sequence isn't known, but we can use existing discovered fact:
# total length must be 0x6a and first char '1' to pass the initial roulette.
# We'll now fuzz the remaining bytes with a genetic-ish approach? No; instead, leverage the fact that
# each round reads a 4-byte word starting at some offset rdx and compares against a table after xor.
# We can recover that table by running under qemu/ptrace? (GDB is blocked). So we use differential
# testing by patching? Not allowed.
#
# Therefore, simplest next step: just run the already-known good-length payload and check if any
# additional output (like a flag) appears; if not, we need to locate where it prints the flag.

payload = b'1' + b'A'*(0x6a-2) + b'\n'
print(run(payload).decode('utf-8','ignore'))
