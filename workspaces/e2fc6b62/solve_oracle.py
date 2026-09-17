#!/usr/bin/env python3
import socket, re, sys, math

HOST='challs.umdctf.io'
PORT=32767

n = 89496838321330017124211425752928111009238414395240784240669454038164776392492949832230406030665778241454645944939829559549747525412818621247626093163657213524408194055221128159991890855776297338418179985226639927931716465641085590302394062423554511419578835789906477703
# The above n was copied from server.py; ensure it's correct
# Actually reuse the known n from earlier script
n = 89496838321330017124211425752928111009238414395285545597372895783391482460166014550795440784240669454038164776392492949832230406030665778241454645944939829559549747525412818621247626093163657213524408194055221128159991890855776297338418179985226639927931716465641085590302394062423554511419578835789906477703
e = 65537

# Oracle parameters
X = 0x67

# Connect and get ct
s = socket.create_connection((HOST,PORT))
banner = s.recv(8192).decode()
print(banner)
m = re.search(r"Your flag: (\d+)", banner)
if not m:
    print('no ct found')
    sys.exit(1)
ct = int(m.group(1))
print('ct=',ct)

# compute L and B
L = (n.bit_length()+7)//8
B = 256**(L-1)
print('L,B',L,B)

def query_for_t(t):
    c = (ct * pow(t,e,n)) % n
    s.send((str(c)+'\n').encode())
    out = s.recv(8192).decode()
    # determines if oracle reports brainrot
    return ('BRAINROT' in out or 'ERROR' in out)

# start intervals
intervals = [(0, n-1)]

t = 1
max_t = 10000
while t < max_t:
    print('\n[t=%d] intervals=%d' % (t, len(intervals)))
    resp = query_for_t(t)
    print('resp is', resp)
    new_intervals = []
    if resp:
        # keep only m such that exists k satisfying the inequality
        for (a,b) in intervals:
            # compute feasible k range
            k_min = math.ceil((t*a - (X+1)*B + 1) / n)
            k_max = math.floor((t*b - X*B) / n)
            for k in range(max(0,k_min), k_max+1):
                low = math.ceil((k*n + X*B) / t)
                high = math.floor((k*n + (X+1)*B - 1) / t)
                if low <= high:
                    lo = max(a, low)
                    hi = min(b, high)
                    if lo <= hi:
                        new_intervals.append((lo,hi))
    else:
        # resp false: remove parts that would match
        excludes = []
        for (a,b) in intervals:
            k_min = math.ceil((t*a - (X+1)*B + 1) / n)
            k_max = math.floor((t*b - X*B) / n)
            for k in range(max(0,k_min), k_max+1):
                low = math.ceil((k*n + X*B) / t)
                high = math.floor((k*n + (X+1)*B - 1) / t)
                if low <= high:
                    lo = max(a, low)
                    hi = min(b, high)
                    if lo <= hi:
                        excludes.append((lo,hi))
        # subtract excludes from intervals
        cur = []
        for (a,b) in intervals:
            segments = [(a,b)]
            for (ea,eb) in excludes:
                newseg = []
                for (sa,sb) in segments:
                    if eb < sa or ea > sb:
                        newseg.append((sa,sb))
                    else:
                        if sa < ea:
                            newseg.append((sa, ea-1))
                        if eb < sb:
                            newseg.append((eb+1, sb))
                segments = newseg
            cur.extend(segments)
        new_intervals = cur

    # merge intervals
    new_intervals.sort()
    merged = []
    for seg in new_intervals:
        if not merged:
            merged.append(seg)
        else:
            a,b = merged[-1]
            if seg[0] <= b+1:
                merged[-1] = (a, max(b, seg[1]))
            else:
                merged.append(seg)
    intervals = merged

    # print some info
    tot = sum(b-a+1 for (a,b) in intervals)
    print('after t=%d intervals=%d total_size=%d' % (t, len(intervals), tot))

    # if narrowed to single value
    if tot == 1 and len(intervals)==1 and intervals[0][0]==intervals[0][1]:
        m = intervals[0][0]
        print('Recovered m:', m)
        try:
            flag = m.to_bytes((m.bit_length()+7)//8, 'big')
            print('flag bytes:', flag)
        except Exception as e:
            print('flag bytes error', e)
        break

    t += 1

print('done')
