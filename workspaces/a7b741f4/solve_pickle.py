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
            # Return a string resembling a flag hint or query response
            return lambda prompt='': 'flag?'
        raise NotImplementedError('no')

    def persistent_load(self, pid):
        # Use the persistent_load method with recursion
        pickelang = Pickelang(BytesIO(pid))
        pickelang.memo = self.memo
        return pickelang.load()

pkl_data = open('pickle.pkl', 'rb').read()

try:
    result = Pickelang(BytesIO(pkl_data)).load()
    print('Unpickled result:', result)
except Exception as e:
    print('Exception while unpickling:', e)
