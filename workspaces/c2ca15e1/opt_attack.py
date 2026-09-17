from game import GameState, CTF_GOAL
from policy import load_default_policy
from attack import load_from_base64
import numpy as np, io, base64
from physics import initial_car

policy = load_default_policy()

# helper to make model b64
def make_b64(W0,b0,W1,b1):
    buf = io.BytesIO()
    np.savez(buf, W0=W0.astype('float32'), b0=b0.astype('float32'), W1=W1.astype('float32'), b1=b1.astype('float32'))
    return base64.b64encode(buf.getvalue()).decode()

# start from scaled constant delta model from earlier
car = initial_car()
from game import LEGIT_GOAL
from observations import generate_observation
obs_legit = generate_observation(car, LEGIT_GOAL)
obs_ctf = generate_observation(car, CTF_GOAL)
delta = obs_ctf - obs_legit
# scale to max L2
if np.linalg.norm(delta) > 0.5:
    delta = delta * (0.5 / np.linalg.norm(delta))

# build model that outputs constant delta via zero W's and arctanh in b1
W0 = np.zeros((16,8), dtype='float32')
b0 = np.zeros((16,), dtype='float32')
W1 = np.zeros((8,16), dtype='float32')
b1 = np.arctanh(delta).astype('float32')

best_params = (W0.copy(), b0.copy(), W1.copy(), b1.copy())

# evaluate function: return min distance to goal during episode

def evaluate(params):
    W0,b0,W1,b1 = params
    b64 = make_b64(W0,b0,W1,b1)
    try:
        attack = load_from_base64(b64)
    except Exception as e:
        return 1e9
    G = GameState(policy)
    G.install_attack(attack)
    dt=0.1
    min_dist = 1e9
    for _ in range(600):
        G.step(dt)
        dx = G.car.x - CTF_GOAL[0]
        dz = G.car.z - CTF_GOAL[1]
        d = (dx*dx+dz*dz)**0.5
        if d < min_dist:
            min_dist = d
        if G.goal_reached:
            return 0.0
        if G.timed_out:
            break
    return min_dist

best_score = evaluate(best_params)
print('start score', best_score)

# hillclimb
rng = np.random.default_rng(12345)
for iter in range(2000):
    # mutate copy
    W0,b0,W1,b1 = [x.copy() for x in best_params]
    # pick param to mutate
    choice = rng.integers(4)
    if choice==0:
        i = tuple(rng.integers(s) for s in W0.shape)
        W0[i] += rng.normal(scale=0.5)
    elif choice==1:
        i = rng.integers(b0.size)
        b0[i] += rng.normal(scale=0.5)
    elif choice==2:
        i = tuple(rng.integers(s) for s in W1.shape)
        W1[i] += rng.normal(scale=0.5)
    else:
        i = rng.integers(b1.size)
        b1[i] += rng.normal(scale=0.5)
    # clip
    for arr in (W0,b0,W1,b1):
        np.clip(arr, -10.0, 10.0, out=arr)
    score = evaluate((W0,b0,W1,b1))
    if score < best_score:
        best_score = score
        best_params = (W0.copy(),b0.copy(),W1.copy(),b1.copy())
        print('iter',iter,'new best',best_score)
        if best_score==0.0:
            break
    if iter%100==0:
        print('iter',iter,'best',best_score)

print('done best',best_score)
if best_score==0.0:
    b64 = make_b64(*best_params)
    print('found model b64:', b64)
