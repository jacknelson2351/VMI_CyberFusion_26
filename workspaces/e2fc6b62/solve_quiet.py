#!/usr/bin/env python3
import socket, re, sys, math, time

HOST='challs.umdctf.io'
PORT=32767

n = 89496838321330017124211425752928111009238414395285545597372895783391482460166014550795440784240669454038164776392492949832230406030665778241454645944939829559549747525412818621247626093163657213524408194055221128159991890855776297338418179985226639927931716465641085590302394062423554511419578835789906477703
e = 65537

X = 0x67

s = socket.create_connection((HOST,PORT))
banner = s.recv(8192).decode()
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

def query_for_t(t):
    c = (ct * pow(t,e,n)) % n
    s.send((str(c)+'\n').encode())
    out = s.recv(4096).decode()
    return ('BRAINROT' in out or 'ERROR' in out)

intervals = [(0,n-1)]

max_t = 20000
start = time.time()
for t in range(1, max_t+1):
    resp = query_for_t(t)
    # compute new intervals
    new = []
    if resp:
        for (a,b) in intervals:
            k_min = math.ceil((t*a - (X+1)*B +1) / n)
            k_max = math.floor((t*b - X*B) / n)
            for k in range(max(0,k_min), k_max+1):
                low = math.ceil((k*n + X*B) / t)
                high = math.floor((k*n + (X+1)*B - 1) / t)
                if low <= high:
                    lo = max(a, low)
                    hi = min(b, high)
                    if lo <= hi:
                        new.append((lo,hi))
    else:
        excludes = []
        for (a,b) in intervals:
            k_min = math.ceil((t*a - (X+1)*B +1) / n)
            k_max = math.floor((t*b - X*B) / n)
            for k in range(max(0,k_min), k_max+1):
                low = math.ceil((k*n + X*B) / t)
                high = math.floor((k*n + (X+1)*B - 1) / t)
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
    # merge
    new.sort()
    merged=[]
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
    print('t=%d resp=%s intervals=%d total=%d time=%.1fs' % (t, resp, len(intervals), tot, time.time()-start))
    if tot == 1 and len(intervals)==1 and intervals[0][0]==intervals[0][1]:
        mval = intervals[0][0]
        print('FOUND m', mval)
        try:
            flag = mval.to_bytes((mval.bit_length()+7)//8, 'big')
            print('flag:', flag)
        except Exception as e:
            print('err',e)
        break
print('done')
