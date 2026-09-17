import collections

def gen():
    s = 1
    while True:
        yield s
        s *= 2

powers = [next(gen()) for _ in range(10)]

candidates = [
    'print(1)',
    'if 1:print(1)',
    'a=1',
    'b=2',
    'if True:pass',
    'flag=42',
    'print("flag")',
    'a'*1+'b'*2+'c'*4+'d'*8,
]

for candidate in candidates:
    counts = collections.Counter(candidate).values()
    counts_sorted = sorted(counts)

    # Check if counts_sorted matches powers starting from 1
    def is_power_of_two_seq(cs):
        for i, c in enumerate(cs):
            if c != powers[i]:
                return False
        return True

    if is_power_of_two_seq(counts_sorted):
        print(f"Valid candidate found: {candidate}")
        # Check if can compile
        try:
            compile(candidate, '<string>', 'exec')
            print("Compile check: Passed")
        except Exception as e:
            print(f"Compile check: Failed: {e}")
    else:
        print(f"Invalid candidate: {candidate}, counts: {counts_sorted}")
