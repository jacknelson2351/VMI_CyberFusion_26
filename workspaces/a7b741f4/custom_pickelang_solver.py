from io import BytesIO
import operator
import struct
from pickle import Unpickler

class Pickelang(Unpickler):
    def find_class(self, module, name):
        if name in ['add', 'getitem']:
            return getattr(operator, name)
        if name in ['pack', 'unpack']:
            return getattr(struct, name)
        if name == 'input':
            return lambda prompt='': 'flag?'
        raise NotImplementedError('no')

    def persistent_load(self, pid):
        if not hasattr(self, '_depth'):
            self._depth = 0
        if self._depth > 10:  # limit recursion depth
            return '[DEPTH_LIMIT_REACHED]'
        self._depth += 1
        try:
            pickelang = Pickelang(BytesIO(pid))
            pickelang.memo = self.memo
            result = pickelang.load()
        except Exception as e:
            result = f'[ERROR: {e}]'
        self._depth -= 1
        return result

if __name__ == '__main__':
    with open('pickle.pkl', 'rb') as f:
        data = f.read()
    result = Pickelang(BytesIO(data)).load()
    print('=== Pickle main result ===')
    print(result)
