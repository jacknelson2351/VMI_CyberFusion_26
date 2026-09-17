# Manual inspection of pickle data to inspect small parts
f=open('pickle.pkl','rb')
data=f.read()
f.close()

print('First 100 bytes:')
print(data[:100])
print('\nNear EOF 100 bytes:')
print(data[-100:])

print('\nExtract ASCII like sequences:')
import re
ascii_like = re.findall(rb'[ -~]{4,}', data)
for s in ascii_like[:10]:
    print(s.decode())
