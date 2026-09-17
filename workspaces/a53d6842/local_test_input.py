chars = ['p', 'r', 'i', 'n']
# counts: 1, 2, 4, 8 respectively
input_str = chars[0]*1 + chars[1]*2 + chars[2]*4 + chars[3]*8
print(f"Input string: {input_str}")

# Try to place 'print(1)' as the exec string, roughly
# But this string is not valid Python syntax, just character repetition
# So this is just a test for formatting
