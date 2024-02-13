from random import random
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util import number
from aes_cbc import cbc_encrypt, cbc_decrypt
from sympy import factor

KEY_SIZE = 16

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
    return bytearray(digest)[:KEY_SIZE]

def exchange_6():
    p = 37
    g = 5
    (a, b) = diffie(p, g)
    init_vector = get_random_bytes(KEY_SIZE)
    alice_bob_original = "Hello Bob! I am Alice. This message is long to test. I am writing now."
    alice_bob_cipher = cbc_encrypt(alice_bob_original, a, init_vector)
    alice_bob_decrypted = cbc_decrypt(alice_bob_cipher, b, init_vector)
    print(alice_bob_decrypted)

def exchange_ietf1024():
    pass

def rsa(m):
    #n modulo
    #d private
    e = 65537
    #i = int(random() * 2048)
    #j = int(random() * 2048)
    p = number.getPrime(2048)
    q = number.getPrime(2048)
    n = p * q
    phi = (p-1)*(q-1)
    crypt = pow(m,e,n)
    print(crypt)
    return (crypt,n, phi)

def hack_rsa():
    #n modulo
    #d private
    e = 65537
    #i = int(random() * 2048)
    #j = int(random() * 2048)
    p = 3
    q = 7
    n = p * q
    num = factor(n)
    print(num)
   
   

def decrypt(crypt, n, phi):
    e = 65537
    d = pow(e, -1, phi) 
    numb = pow(crypt, d, n)
    print(numb)
    return numb

    
if __name__ == "__main__":
    #crypt,n, phi = rsa(19)
    #decrypt(crypt, n, phi)
    hack_rsa()


    