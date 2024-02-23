import random
import hashlib

import commune as c


class ZeroKnowledgeProof(c.Module):
    def __init__(self, p, g, h):
        self.p = p
        self.g = g
        self.h = h

    def generate_private_key(self):
        print('running generate_private_key')
        return random.randint(1, self.p - 1)

    def generate_public_key(self, private_key):
        print('running generate_public_key')
        return pow(self.g, private_key, self.p)

    def generate_proof(self, private_key, x):
        print('running generate_proof')
        r = random.randint(1, self.p - 1)
        R = pow(self.g, r, self.p)
        e = int(hashlib.sha256(str(R).encode()).hexdigest(), 16)
        s = (r + x * e) % (self.p - 1)
        return R, s

    def verify_proof(self, public_key, proof):
        print('running verify_proof')
        R, s = proof
        e = int(hashlib.sha256(str(R).encode()).hexdigest(), 16)
        V1 = pow(self.g, s, self.p)
        V2 = (pow(public_key, e, self.p) * R) % self.p
        return V1 == V2

    def generate_challenge(self, R):
        print('running generate_challenge')
        return int(hashlib.sha256(str(R).encode()).hexdigest(), 16)

    def compute_response(self, challenge, private_key, r):
        print('running compute_response')
        return (r + private_key * challenge) % (self.p - 1)
