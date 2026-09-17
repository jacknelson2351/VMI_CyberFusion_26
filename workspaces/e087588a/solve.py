import subprocess

# We'll brute force numbers to find all that get accepted or win
for i in range(256):
    p = subprocess.Popen(['/ctf/roulette'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate(input=(str(i)+'\n').encode())
    s = out.decode(errors='ignore') + err.decode(errors='ignore')
    if 'accepted' in s or 'WON' in s or 'You just WON' in s or 'winner' in s or 'congrat' in s:
        print('FOUND', i)
        print(s)
        break
    else:
        print(f'{i} : {s.strip()}')
