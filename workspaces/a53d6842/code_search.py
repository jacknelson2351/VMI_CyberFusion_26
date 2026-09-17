import itertools
from collections import Counter

def gen():
    s = 1
    while True:
        yield s
        s *= 2

powers = [2**i for i in range(8)]

chars = ['a','b','c','d']
counts = powers[:len(chars)]

candidate = ''.join(c * f for c, f in zip(chars, counts))

print(f"Candidate: {candidate}")
ctr = Counter(candidate)
print(f"Counter: {ctr}")
print(f"Sorted counts: {sorted(ctr.values())}")
print(f"Expected powers: {counts}")

try:
    compile(candidate, '<string>', 'exec')
    print("Valid Python code")
except Exception as e:
    print("Invalid Python code", e)

# TODO: Extend search to permutations or small meaningful snippets
