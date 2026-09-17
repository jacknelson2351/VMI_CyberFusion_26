from collections import Counter

def check_input(c):
    counts = sorted(Counter(c).values())
    def gen():
        s=1
        while True:
            yield s
            s*=2
    g = gen()
    expected = [next(g) for _ in range(len(counts))]
    if counts != expected:
        return False
    for ch in c:
        if ch in "#'\" \t\n\r\x0c\x0b":
            return False
    return True

print(check_input('abbcccdddd'))  # False
print(check_input('abbcccc'))  # ?
