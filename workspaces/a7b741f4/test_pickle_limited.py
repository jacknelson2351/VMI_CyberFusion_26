#!/usr/local/bin/python3.13
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
        # Limit recursion depth by checking a memo counter attribute
        if not hasattr(self, '_depth'):
            self._depth = 0
        if self._depth > 10:
            print('Reached persistent_load recursion limit')
            return False
        self._depth += 1
        pickelang = Pickelang(BytesIO(pid))
        pickelang.memo = self.memo
        result = pickelang.load()
        self._depth -= 1
        return result

result = Pickelang(open('pickle.pkl','rb')).load()
print(f'Result: {result}')
