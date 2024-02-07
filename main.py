from random import random
from Crypto.Hash import SHA256


def diffie(p, g):
    a_private = int(random()*p)
    b_private = int(random()*p)
    while a_private == b_private:
        b_private = int(random() * p)
    a_public = pow(g, a_private, p)
    b_public = pow(g, b_private, p)

    s_alice = pow(b_public, a_private, p)
    s_bob = pow(a_public, b_private, p)
    print(s_alice)
    print(s_bob)

    k_alice = SHA256.new()
    k_alice.update(bytes(s_alice))
    k_bob = SHA256.new()
    k_bob.update(bytes(s_bob))

    print(k_alice.digest())
    print(k_bob.digest())


if __name__ == "__main__":
    p = 37
    g = 5
    diffie(p, g)