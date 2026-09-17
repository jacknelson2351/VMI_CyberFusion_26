#!/usr/bin/env python3
import socket, re, sys, math
HOST='challs.umdctf.io'
PORT=32767

n = 89496838321330017124211425752928111009238414395285545597372895783391482460166014550795440784240669454038164776392492949832230406030665778241454645944939829559549747525412818621247626093163657213524408194055221128159991890855776297338418179985226639927931716465641085590302394062423554511419578835789906477703
e = 65537
X = 0x67

s = socket.create_connection((HOST,PORT))
banner = s.recv(16384).decode()
print(banner)
m = re.search(r"Your flag: (\d+)", banner)
if not m:
    print('no ct')
    sys.exit(1)
ct = int(m.group(1))
print('ct=',ct)

L = (n.bit_length()+7)//8
B = 256**(L-1)
print('L,B',L,B)

intervals = [(0, n-1)]

def send_batch(ts):
    # compute ciphertexts
    cs = [str((ct * pow(t,e,n)) % n) for t in ts]
    msg = ','.join(cs) + '\n'
    s.send(msg.encode())
    # receive responses until we have len(ts) responses
    resp_list = []
    buf = ''
    while len(resp_list) < len(ts):
        data = s.recv(65536).decode()
        if not data:
            break
        buf += data
        # server prints one message per ct, separated by a blank line. We'll search sequentially for the two possible messages.
        while True:
            if 'ERROR: BRAINROT DETECTED' in buf:
                # find first occurrence and consume up to following blank line
                idx = buf.find('ERROR: BRAINROT DETECTED')
                # consume until the next double newline or until end
                nl = buf.find('\n\n', idx)
                if nl == -1:
                    break
                resp_list.append(True)
                buf = buf[nl+2:]
            elif 'The UMDCTF team thanks you for your message!' in buf:
                idx = buf.find('The UMDCTF team thanks you for your message!')
                nl = buf.find('\n\n', idx)
                if nl == -1:
                    break
                resp_list.append(False)
                buf = buf[nl+2:]
            else:
                break
    return resp_list

max_t = 40000
batch = 120
start = 1

t = start
import time
start_time = time.time()
while t <= max_t:
    ts = list(range(t, min(t+batch, max_t+1)))
    resp_list = send_batch(ts)
    if len(resp_list) != len(ts):
        print('got mismatch responses', len(resp_list), 'expected', len(ts))
        # try to continue with what we have
    for i, resp in enumerate(resp_list):
        ti = ts[i]
        # apply interval update for this t
        new = []
        if resp:
            for (a,b) in intervals:
                k_min = math.ceil((ti*a - (X+1)*B + 1) / n)
                k_max = math.floor((ti*b - X*B) / n)
                for k in range(max(0,k_min), k_max+1):
                    low = math.ceil((k*n + X*B) / ti)
                    high = math.floor((k*n + (X+1)*B - 1) / ti)
                    if low <= high:
                        lo = max(a, low)
                        hi = min(b, high)
                        if lo <= hi:
                            new.append((lo,hi))
        else:
            excludes = []
            for (a,b) in intervals:
                k_min = math.ceil((ti*a - (X+1)*B + 1) / n)
                k_max = math.floor((ti*b - X*B) / n)
                for k in range(max(0,k_min), k_max+1):
                    low = math.ceil((k*n + X*B) / ti)
                    high = math.floor((k*n + (X+1)*B - 1) / ti)
                    if low <= high:
                        lo = max(a, low)
                        hi = min(b, high)
                        if lo <= hi:
                            excludes.append((lo,hi))
            cur = []
            for (a,b) in intervals:
                segs = [(a,b)]
                for (ea,eb) in excludes:
                    newseg = []
                    for (sa,sb) in segs:
                        if eb < sa or ea > sb:
                            newseg.append((sa,sb))
                        else:
                            if sa < ea:
                                newseg.append((sa, ea-1))
                            if eb < sb:
                                newseg.append((eb+1, sb))
                    segs = newseg
                cur.extend(segs)
            new = cur
        # merge new into intervals
        new.sort()
        merged = []
        for seg in new:
            if not merged:
                merged.append(seg)
            else:
                a,b = merged[-1]
                if seg[0] <= b+1:
                    merged[-1] = (a, max(b, seg[1]))
                else:
                    merged.append(seg)
        intervals = merged
        tot = sum(b-a+1 for (a,b) in intervals)
        print('t=%d resp=%s intervals=%d total=%d time=%.1fs' % (ti, resp, len(intervals), tot, time.time()-start_time))
        if tot == 1 and len(intervals)==1 and intervals[0][0]==intervals[0][1]:
            mval = intervals[0][0]
            print('FOUND m', mval)
            try:
                flag = mval.to_bytes((mval.bit_length()+7)//8, 'big')
                print('flag:', flag)
            except Exception as e:
                print('err',e)
            sys.exit(0)
    t += batch
print('done')
