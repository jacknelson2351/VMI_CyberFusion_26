from game import GameState, CTF_GOAL
from policy import load_default_policy
from attack import load_from_base64
import numpy as np, io, base64
from physics import initial_car

policy = load_default_policy()

# parameter sizes
sW0 = (16,8)
sb0 = (16,)
sW1 = (8,16)
sb1 = (8,)
Nparams = 16*8 + 16 + 8*16 + 8
print('Nparams',Nparams)

def pack(params):
    # params shape (Nparams,)
    idx = 0
    W0 = params[idx:idx+128].reshape(sW0); idx+=128
    b0 = params[idx:idx+16].reshape(sb0); idx+=16
    W1 = params[idx:idx+128].reshape(sW1); idx+=128
    b1 = params[idx:idx+8].reshape(sb1); idx+=8
    return W0,b0,W1,b1

def make_b64_from_params(params):
    W0,b0,W1,b1 = pack(params)
    buf = io.BytesIO()
    np.savez(buf, W0=W0.astype('float32'), b0=b0.astype('float32'), W1=W1.astype('float32'), b1=b1.astype('float32'))
    return base64.b64encode(buf.getvalue()).decode()

# evaluate
from game import GameState

def evaluate_params(params):
    b64 = make_b64_from_params(params)
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

# evolution
rng = np.random.default_rng(123)
pop_size = 60
generations = 200
# init population small random
pop = rng.normal(scale=0.5, size=(pop_size,Nparams)).astype('float32')
# clip to weight limits
for i in range(pop_size):
    np.clip(pop[i], -10.0, 10.0, out=pop[i])

scores = np.full(pop_size, 1e9)

best_params = None
best_score = 1e9

evals=0
for gen in range(generations):
    # evaluate
    for i in range(pop_size):
        if scores[i] > 1e8:
            scores[i] = evaluate_params(pop[i])
            evals += 1
            if scores[i] < best_score:
                best_score = scores[i]
                best_params = pop[i].copy()
                print(f'new best gen{gen} eval{evals} score {best_score}')
                if best_score==0.0:
                    b64 = make_b64_from_params(best_params)
                    print('FOUND MODEL', b64)
                    raise SystemExit(0)
    # select top
    idx = np.argsort(scores)
    elites = pop[idx[:10]]
    # create new pop
    newpop = np.zeros_like(pop)
    # keep elites
    newpop[:10] = elites
    # fill rest by mutating elites
    for i in range(10, pop_size):
        parent = elites[rng.integers(0,10)]
        child = parent + rng.normal(scale=0.5*(1 - gen/generations), size=Nparams)
        np.clip(child, -10.0, 10.0, out=child)
        newpop[i] = child
    pop = newpop
    scores = np.full(pop_size, 1e9)
    if gen%5==0:
        print('gen',gen,'best_score',best_score,'evals',evals)

print('done, best',best_score)
if best_params is not None:
    print('best b64', make_b64_from_params(best_params))
