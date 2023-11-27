import math
from collections import defaultdict
from tqdm import tqdm

def are_coprime(a, b):
    return math.gcd(a, b) == 1

p = 1009
q = 3643
n = p * q
phi = (p - 1) * (q - 1)

e_can = []
H = defaultdict(int)

for e in tqdm(range(1, phi)):
    if are_coprime(e, phi):
        e_can.append(e)
print('*'*50)

for e in tqdm(e_can):
    cnt = (1 + math.gcd(e-1, p-1))*(1 + math.gcd(e-1, q-1))
    H[cnt] += e

print(f'keyword: {H.keys()} and correspoding sum: {H[min(H.keys())]}')
