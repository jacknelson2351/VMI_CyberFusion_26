import collections

candidate = 'print(1)'

ctr = collections.Counter(candidate)
print(f"Counter: {ctr}")
sorted_counts = sorted(ctr.values())
print(f"Sorted counts: {sorted_counts}")

powers = [2**i for i in range(len(sorted_counts))]
print(f"Powers for length {len(sorted_counts)}: {powers}")

matches = sorted_counts == powers
print(f"Matches powers of two counts? {matches}")
