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
        print(f'persistent_load called with pid length: {len(pid)}')
        pickelang = Pickelang(BytesIO(pid))
        pickelang.memo = self.memo
        result = pickelang.load()
        print(f'persistent_load result type: {type(result)}')
        return result

result = Pickelang(open('pickle.pkl','rb')).load()
print(f'Main result type: {type(result)}')
print(result)
