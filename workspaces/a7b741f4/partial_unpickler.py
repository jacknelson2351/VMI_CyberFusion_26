import pickle
from io import BytesIO
import operator
import struct

class PickelangPartial(pickle.Unpickler):
    def find_class(self, module, name):
        if name in ['add', 'getitem']:
            return getattr(operator, name)
        if name in ['pack', 'unpack']:
            return getattr(struct, name)
        if name == 'input':
            return lambda prompt='': 'flag?'
        raise NotImplementedError('no')

    def persistent_load(self, pid):
        # Return the persistent id data decoded as UTF-8 string ignoring errors
        return pid.decode('utf-8', errors='ignore')

if __name__ == '__main__':
    with open('pickle.pkl', 'rb') as f:
        data = f.read()
    result = PickelangPartial(BytesIO(data)).load()
    print('Partial unpickle result:')
    print(result)
