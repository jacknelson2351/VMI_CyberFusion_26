#!/usr/bin/env python3
import socket, sys, time
from dnslib import DNSRecord, QTYPE

HOST = 'challs.umdctf.io'
PORT = 32323

def send_query(name):
    q = DNSRecord.question(name, qtype='TXT')
    qb = q.pack()
    frame = len(qb).to_bytes(2, 'big') + qb
    with socket.create_connection((HOST, PORT), timeout=10) as s:
        s.sendall(frame)
        ln = s.recv(2)
        if len(ln) < 2:
            raise RuntimeError('no response')
        l = int.from_bytes(ln, 'big')
        data = b''
        while len(data) < l:
            chunk = s.recv(l - len(data))
            if not chunk:
                break
            data += chunk
    resp = DNSRecord.parse(data)
    for a in resp.rr:
        if a.rtype == QTYPE.TXT:
            txt = str(a.rdata)
            # dnslib shows TXT as quoted string like '"O"'
            if txt.startswith('"') and txt.endswith('"'):
                return txt[1:-1]
            return txt
    return None

# fetch secret characters 0..818
secret_chars = []
for i in range(0,819):
    name = f"{i}.inside.info"
    try:
        v = send_query(name)
    except Exception as e:
        print('Error querying', name, e)
        v = None
    if v is None:
        print('No TXT for', name)
        secret_chars.append('?')
    else:
        secret_chars.append(v)
    time.sleep(0.005)

secret = ''.join(secret_chars)
print('Secret length', len(secret))
# build subdomain by splitting into 63-char labels
labels = [secret[i:i+63] for i in range(0, len(secret), 63)]
subdomain = '.'.join(labels)
print('Subdomain labels:', len(labels))
full = subdomain + '.inside.info'
flagtxt = send_query(full)
print('Flag TXT:', flagtxt)
