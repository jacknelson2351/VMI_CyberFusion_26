from itertools import permutations
from collections import Counter

allowed_chars = 'abcdefghijklmnopqrstuvwxyz'
powers = [1,2,4,8,16]

# Try small snippets of python expressions as templates
snippets = [
    'a=1',
    'b=2',
    'print(1)',
    'if a:print(b)',
    'for i in range(4):print(i)',
    'def f():\n  return 42',
    'flag = 42',
    'print(flag)'
]

def is_power_of_two_counts(s):
  c = Counter(s)
  counts_sorted = sorted(c.values())
  if counts_sorted == powers[:len(counts_sorted)]:
      return True
  return False


# Try permuting allowed_chars for each snippet, repeating letters according to power of two counts
for snippet in snippets:
    snippet = snippet.replace('\n', '')
    for unique_chars in permutations(allowed_chars, len(snippet)):
        test_str = ''.join(c * powers[i] for i, c in enumerate(unique_chars))
        # Remove placeholders? Can't map snippet chars to test_str chars easily
        # Instead, check if test_str is valid code
        try:
            compile(test_str, '<string>', 'exec')
            if is_power_of_two_counts(test_str):
                print(f"Valid code: {test_str}")
                exit()
        except:
            pass

print("No valid code found")
