#!/usr/bin/env python3
# Connect to remote service and try random perturbations around local reference_window1.npy
import socket, sys, base64, struct, random, time

HOST='challs.umdctf.io'
PORT=30303

REF_PATH='/ctf/reference_window1.npy'

# minimal .npy v1.0 loader for little-endian float32
def load_npy(path):
    with open(path,'rb') as f:
        magic = f.read(6)
        if magic != b"\x93NUMPY":
            raise ValueError('not npy')
        ver = f.read(2)
        major, minor = ver[0], ver[1]
        if major != 1:
            raise ValueError('unsupported npy version')
        header_len = struct.unpack('<H', f.read(2))[0]
        header = f.read(header_len)
        header = header.decode('latin1')
        # parse descr and shape
        # crude parse
        if "'descr':" in header:
            dpos = header.find("'descr':")
            descr = header[dpos:].split("}")[0]
            # grab between quotes
            descr = descr.split(':')[1].strip().split(',')[0].strip()
            descr = descr.strip().strip("'")
        else:
            raise ValueError('no descr')
        if "'shape':" in header:
            spos = header.find("'shape':")
            shape_part = header[spos:]
            # find parenthesis
            p1 = shape_part.find('(')
            p2 = shape_part.find(')')
            shape_str = shape_part[p1+1:p2]
            dims = [int(x.strip()) for x in shape_str.split(',') if x.strip()]
            shape = tuple(dims)
        else:
            raise ValueError('no shape')
        # read data
        dtype = descr  # e.g. '<f4'
        endian = dtype[0]
        ft = dtype[1:]
        if ft != 'f4':
            raise ValueError('only float32 supported')
        count = 1
        for d in shape: count *= d
        data = f.read(4*count)
        vals = struct.unpack('<' + 'f'*count, data)
        return shape, vals

# build .npy file bytes for shape and float list
def build_npy_bytes(shape, floats):
    # header dict like { 'descr': '<f4', 'fortran_order': False, 'shape': (5, 64), }
    descr = "<'f4"  # placeholder wrong, fix below
    descr = "<f4"
    header = "{" + "'descr': '%s', 'fortran_order': False, 'shape': %s, }" % (descr, str(shape))
    header_bytes = header.encode('latin1')
    # pad to 16-byte alignment after magic+ver+hl
    magic = b"\x93NUMPY"
    ver = bytes([1,0])
    hl = 2
    # compute padding
    pad_len = ((16 - ((len(header_bytes)+hl) % 16)) % 16)
    header_bytes = header_bytes + b' ' * pad_len + b'\n'
    header_len = len(header_bytes)
    out = magic + ver + struct.pack('<H', header_len) + header_bytes
    # data
    out += struct.pack('<' + 'f'* (int(shape[0])*int(shape[1])), *floats)
    return out

if __name__=='__main__':
    shape, vals = load_npy(REF_PATH)
    print('Loaded local ref shape', shape)
    # make list mutable
    ref = list(vals)
    # try connecting
    s = socket.create_connection((HOST, PORT), timeout=10)
    # read until prompt
    data = b''
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
        if b'submit base64' in data or b'> ' in data:
            break
    print(data.decode(errors='ignore'))
    # now attempt candidates
    EPS = 0.08
    tries = 800
    for i in range(tries):
        # perturb each element by uniform in [-EPS,EPS]
        cand = [ref[j] + random.uniform(-EPS, EPS) for j in range(len(ref))]
        # clip to ensure linf
        # create bytes
        bts = build_npy_bytes(shape, cand)
        b64 = base64.b64encode(bts)
        s.sendall(b64 + b'\n')
        # read response
        resp = b''
        # read until next prompt or close
        try:
            s.settimeout(1.0)
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                resp += chunk
                if b'submit base64' in resp or b'FLAG:' in resp or b'OK  ' in resp or b'margin' in resp:
                    break
        except socket.timeout:
            pass
        txt = resp.decode(errors='ignore')
        print(f'Try {i}:', txt.strip())
        if 'FLAG:' in txt:
            print('FOUND')
            break
        # if still prompted, continue; else reconnect
        if b'submit base64' not in resp and b'> ' not in resp:
            try:
                s.close()
            except:
                pass
            time.sleep(0.5)
            s = socket.create_connection((HOST, PORT), timeout=10)
            data = s.recv(4096)
            print('reconnected')
    s.close()
