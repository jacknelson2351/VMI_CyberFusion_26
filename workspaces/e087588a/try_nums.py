#!/usr/bin/env python3
import subprocess

for i in range(0,10000):
    p = subprocess.Popen(['/ctf/roulette'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    out = p.communicate(input=(str(i)+'\n').encode())[0].decode(errors='ignore')
    if 'accepted' in out or 'WON' in out or 'You just WON' in out:
        print('FOUND', i)
        print(out)
        break
    if i%1000==0:
        print('tried',i)
