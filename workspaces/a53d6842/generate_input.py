from collections import Counter

forbidden = set("#'\" \t\n\r\x0c\x0b")

# Use characters allowed: ascii letters and digits, plus punctuation except forbidden chars
import string
allowed_chars = [c for c in string.ascii_letters + string.digits + string.punctuation if c not in forbidden]

# Generate exponential frequency counts
freqs = [2**i for i in range(len(allowed_chars))]

# Build a candidate string that is just 'a'*1 + 'b'*2 + 'c'*4 + ... up to the len(allowed_chars)

code_chars = allowed_chars[:12]  # limit for manageable length
freqs = freqs[:12]

output = ''.join(c * f for c, f in zip(code_chars, freqs))

print(Counter(output))
print(sorted(Counter(output).values()))
print(freqs)

# Now try to replace code_chars with characters forming a valid Python no-op or command
# For example, use 'i'=1, 'f'=2, 'o'=4, 'r'=8 -- form 'if for' in non-overlapping counts
# But must satisfy the sorted counts == freqs

# Print output string
print(output)