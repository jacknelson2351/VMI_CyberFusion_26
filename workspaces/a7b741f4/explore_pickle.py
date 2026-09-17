import pickle
from io import BytesIO
import operator
import struct

class Pickelang(pickle.Unpickler):
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
        return pickelang.load()

pkl_data = open('pickle.pkl', 'rb').read()

# Attempt partial loading by truncation
for i in range(len(pkl_data), 0, -100):
    try:
        print(f'Trying to load first {i} bytes')
        data = pkl_data[:i]
        result = Pickelang(BytesIO(data)).load()
        print('Loaded data:', result)
        break
    except Exception as e:
        print(f'Error loading {i} bytes:', e)
