from collections import Counter

def check_input(c):
    # Validate counts
    counts = sorted(Counter(c).values())
    # Generate expected exponential sequence for comparison
    def gen():
        s=1
        while True:
            yield s
            s*=2
    g = gen()
    expected = [next(g) for _ in range(len(counts))]
    if counts != expected:
        return False
    # Validate forbidden characters
    for ch in c:
        if ch in "#'\" \t\n\r\x0c\x0b":
            return False
    return True

# Test example
print(check_input('abbcccdddd'))  # False
print(check_input('abbcccc'))  # True or False?
