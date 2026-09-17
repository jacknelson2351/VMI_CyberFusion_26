#!/usr/bin/env python3
import subprocess

for i in range(0,37):
    p = subprocess.Popen(['/ctf/roulette'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out,err = p.communicate(input=(str(i)+'\n').encode())
    s = out.decode(errors='ignore')+err.decode(errors='ignore')
    if 'accepted' in s or 'WON' in s or 'You just WON' in s or 'winner' in s or 'congrat' in s or 'accepted' in s:
        print('FOUND', i)
        print(s)
    else:
        print(i,':',s.strip())
