def gen():
 s=1
 while True:
  yield s
  s*=2

print([next(gen()) for _ in range(10)])
