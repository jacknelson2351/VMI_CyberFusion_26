#!/usr/bin/env python3
import socket, re, sys, time
HOST='challs.umdctf.io'
PORT=32767

def try_batch(batch):
    s = socket.create_connection((HOST,PORT), timeout=10)
    banner = s.recv(32768).decode()
    m = re.search(r"Your flag: (\d+)", banner)
    if not m:
        print('no ct')
        return 0
    ct = int(m.group(1))
    import math
    e=65537
    cs = [str((ct * pow(t,e,int('89496838321330017124211425752928111009238414395285545597372895783391482460166014550795440784240669454038164776392492949832230406030665778241454645944939829559549747525412818621247626093163657213524408194055221128159991890855776297338418179985226639927931716465641085590302394062423554511419578835789906477703')) ) % int('89496838321330017124211425752928111009238414395285545597372895783391482460166014550795440784240669454038164776392492949832230406030665778241454645944939829559549747525412818621247626093163657213524408194055221128159991890855776297338418179985226639927931716465641085590302394062423554511419578835789906477703') ) for t in range(1,batch+1)]
    msg = ','.join(cs) + '\n'
    start = time.time()
    try:
        s.send(msg.encode())
    except Exception as e:
        print('send failed',e)
        return 0
    s.settimeout(10.0)
    got=0
    try:
        data = s.recv(65536).decode()
        if data:
            got = data.count('The UMDCTF team thanks you for your message!') + data.count('ERROR: BRAINROT DETECTED')
    except Exception as e:
        print('recv err',e)
    print('batch',batch,'sent time',time.time()-start,'got',got)
    s.close()
    return got

if __name__=='__main__':
    for b in [1000,2000,4000,8000,16000]:
        print('trying',b)
        g=try_batch(b)
        time.sleep(1)
