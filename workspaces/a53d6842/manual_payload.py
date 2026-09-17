# Try to build payload with 3 unique chars: 'i', 'f', 'x'
# counts: 1, 2, 4

# The string: 'if xx' == 1 i, 2 f, 4 x
# Let's see if this passes check_input

payload = 'i' + 'f'*2 + 'x'*4
print(payload)

from collections import Counter
ctr = Counter(payload)
print(ctr)

sorted_counts = sorted(ctr.values())
print(sorted_counts)

powers = [1,2,4]
print(sorted_counts == powers)

# Try compiling
try:
    compile(payload, '<string>', 'exec')
    print('Valid code')
except Exception as e:
    print('Invalid code', e)


# The code itself is 'if xxxx' which is incomplete, but valid counts

# We could improve to 'if 1:
  print(1)' but char counts?
