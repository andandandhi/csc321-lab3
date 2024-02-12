from random import random
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util import num
from aes_cbc import cbc_encrypt, pkcs7


def diffie(p, g):
    a_private = int(random()*p)
    b_private = int(random()*p)
    while a_private == b_private:
        b_private = int(random() * p)
    a_public = pow(g, a_private, p)
    b_public = pow(g, b_private, p)

    s_alice = pow(b_public, a_private, p)
    s_bob = pow(a_public, b_private, p)

    k_alice = SHA256.new()
    k_alice.update(bytes(s_alice))
    k_bob = SHA256.new()
    k_bob.update(bytes(s_bob))

    a = truncate(k_alice.digest())
    b = truncate(k_bob.digest())
    return (a, b)

def truncate(digest):
    return bytearray(digest)[:16]


def exchange_6():
    p = 37
    g = 5
    (a, b) = diffie(p, g)
    init_vector = get_random_bytes()
    message = ""
    cbc_encrypt(message, a, init_vector)

def exchange_ietf1024():
    p

def rsa(m):
    #n modulo
    #d private
    e = 65537
    p = num.getPrime(2048)
    q = num.getPrime(2048)
    



if __name__ == "__main__":
    
    diffie(p, g)