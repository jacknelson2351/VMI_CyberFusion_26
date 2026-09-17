from game import GameState
from policy import load_default_policy
from attack import AttackModel, load_from_base64
import numpy as np
import io, base64
from physics import initial_car
from game import CTF_GOAL

np.random.seed(0)
policy = load_default_policy()

best = {'dist': 1e9, 'model_b64': None, 'pos': None}

ATTEMPTS = 2000
STEPS = 600  # 60s at dt=0.1

def make_b64_from_arrays(W0,b0,W1,b1):
    buf = io.BytesIO()
    np.savez(buf, W0=W0, b0=b0, W1=W1, b1=b1)
    return base64.b64encode(buf.getvalue()).decode()

for i in range(ATTEMPTS):
    # sample weights small
    W0 = np.random.normal(scale=1.0, size=(16,8)).astype('float32')
    b0 = np.random.normal(scale=1.0, size=(16,)).astype('float32')
    W1 = np.random.normal(scale=1.0, size=(8,16)).astype('float32')
    b1 = np.random.normal(scale=1.0, size=(8,)).astype('float32')
    # clip to allowed max
    for arr in (W0,b0,W1,b1):
        np.clip(arr, -10.0, 10.0, out=arr)
    b64 = make_b64_from_arrays(W0,b0,W1,b1)
    try:
        attack = load_from_base64(b64)
    except Exception as e:
        # skip invalid
        continue
    G = GameState(policy)
    G.install_attack(attack)
    dt = 0.1
    min_dist = 1e9
    for s in range(STEPS):
        G.step(dt)
        dx = G.car.x - CTF_GOAL[0]
        dz = G.car.z - CTF_GOAL[1]
        dist = (dx*dx+dz*dz)**0.5
        if dist < min_dist:
            min_dist = dist
        if G.goal_reached:
            print('Found goal on attempt', i)
            print('flag:', G.flag)
            # Also print model b64
            print('model_b64=', b64)
            raise SystemExit(0)
        if G.timed_out:
            break
    if min_dist < best['dist']:
        best['dist'] = min_dist
        best['model_b64'] = b64
        best['pos'] = (G.car.x, G.car.z, G.time)
    if i%100==0:
        print('iter',i,'best_dist',best['dist'])

print('Done, best dist', best['dist'], 'pos', best['pos'])
print('best_model_b64=', best['model_b64'])
