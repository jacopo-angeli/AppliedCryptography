#!/usr/bin/env python3

import argparse, hashlib, sys, datetime  # do not use any other imports/libraries

# took 1.5 hours

## Output of running `pow.py --difficulty 26`:
# [+] Solved in 44.342871 sec (1.1488 Mhash/sec)
# [+] Input: 4a41434f504f0000000003094c13
# [+] Solution: 00000005eff47119916dc0370347e31beb18b865d8386899c8dfcfc43b03fa93
# [+] Nonce: 50940947

CHALLENGE = "JACOPO"

parser = argparse.ArgumentParser(description='Proof-of-work solver')
parser.add_argument('--difficulty', default=0, type=int, help='Number of leading zero bits')
args = parser.parse_args()

challenge = CHALLENGE.encode('utf-8')
difficulty = args.difficulty

full_zero_bytes = difficulty // 8
extra_bits = difficulty % 8
mask = ((0xFF << (8 - extra_bits)) & 0xFF) if extra_bits else 0

attempts = 0
nonce = 0
t0 = datetime.datetime.now()

while True:
    # Build input per attempt: challenge || 8-byte big-endian nonce
    data = challenge + nonce.to_bytes(8, 'big', signed=False)

    # Double SHA-256
    h = hashlib.sha256(hashlib.sha256(data).digest()).digest()
    attempts += 1

    # Check difficulty (early reject via byte masks)
    ok = True
    for i in range(full_zero_bytes):
        if h[i] != 0:
            ok = False
            break
    if ok and (extra_bits == 0 or (h[full_zero_bytes] & mask) == 0):
        elapsed = (datetime.datetime.now() - t0).total_seconds()
        mhps = (attempts / elapsed) / 1_000_000
        print(f"[+] Solved in {elapsed:.6f} sec ({mhps:.4f} Mhash/sec)")
        print(f"[+] Input: {data.hex()}")
        print(f"[+] Solution: {h.hex()}")
        print(f"[+] Nonce: {nonce}")
        break

    nonce += 1