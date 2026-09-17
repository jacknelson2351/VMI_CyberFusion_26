#!/usr/bin/env python3
import socket, sys
from dnslib import DNSRecord, QTYPE

if len(sys.argv) < 3:
    print('Usage: query.py host:port name')
    sys.exit(1)

hostport = sys.argv[1]
name = sys.argv[2]
if ':' in hostport:
    host, port = hostport.split(':')
    port = int(port)
else:
    host = hostport
    port = 32323

q = DNSRecord.question(name, qtype='TXT')
qb = q.pack()
frame = len(qb).to_bytes(2, 'big') + qb

with socket.create_connection((host, port), timeout=10) as s:
    s.sendall(frame)
    # read 2 bytes length
    ln = s.recv(2)
    if len(ln) < 2:
        print('No response')
        sys.exit(1)
    l = int.from_bytes(ln, 'big')
    data = b''
    while len(data) < l:
        chunk = s.recv(l - len(data))
        if not chunk:
            break
        data += chunk

    from dnslib import DNSRecord
    resp = DNSRecord.parse(data)
    print(resp)
    for a in resp.rr:
        if a.rtype == QTYPE.TXT:
            print('TXT:', a.rdata.txt)
