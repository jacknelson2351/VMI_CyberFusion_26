import subprocess

# Basic script to brute force oracle ticket acceptance
# Using memcmp_override.so to bypass memcmp failures

BIN = "/ctf/oracle"
FEED = "/ctf/feed.bin"

# Open feed.bin as base ticket input
with open(FEED, "rb") as f:
    base_ticket = f.read()

# Try mutating last byte and testing acceptance
for i in range(256):
    ticket = base_ticket[:-1] + bytes([i])
    proc = subprocess.run([BIN, FEED], input=ticket, env={"LD_PRELOAD": "/ctf/memcmp_override.so"}, capture_output=True)
    out = proc.stdout.decode(errors='ignore') + proc.stderr.decode(errors='ignore')
    if "ticket accepted" in out.lower():
        print(f"Accepted ticket with last byte {i:02x}")
        print(out)
        break
    else:
        print(f"Rejected ticket with last byte {i:02x}")
