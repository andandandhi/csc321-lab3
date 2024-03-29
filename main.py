from random import random
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util import number
from aes_cbc import cbc_encrypt, cbc_decrypt
import random
import datetime

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

def hack_rsa(m): #are we using the correct n?
    e = 65537
    crypt, n, phi= rsa(m)
    d = pow(e, -1, phi) 
    c_prime = mallory(crypt)
    s = pow(c_prime, d, n)
    k = SHA256.new()
    k.update(bytes(s))

    fin_key = truncate(k.digest())
    alice_original = "Hello Bob!"
    init_vector = get_random_bytes(KEY_SIZE)
    alice_cipher = cbc_encrypt(alice_original, fin_key, init_vector)
    return (alice_cipher, init_vector)

def mallory_decrypt(cipher, iv):
    mallory_k = SHA256.new()
    mallory_k.update(bytes(1))
    malfin = truncate(mallory_k.digest())
    message = cbc_decrypt(cipher, malfin, iv)
    print(message)
    return message



def mallory(crypt):
    crypt = 1
    return crypt
   

def decrypt(crypt, n, phi):
    e = 65537
    d = pow(e, -1, phi) 
    numb = pow(crypt, d, n)
    print(numb)
    return numb


def task_4_sha(m1, m2):
    hash1 = SHA256.new()
    hash1.update((m1.encode("utf-8")))
    print("Hash 1 digest: ", hash1.hexdigest())
    hash2 = SHA256.new()
    hash2.update((m2.encode("utf-8")))
    print("Hash 2 digest: ", hash2.hexdigest())


def task_4_collisions(m1, size):
    hash = SHA256.new()
    hash.update(m1.encode("utf-8"))
    final_digest = hash.hexdigest()[:size]
    return final_digest


def task_4_birthday():
    original_time = datetime.datetime.now()
    new_time = datetime.datetime.now()
    size = 4
    num_items = 0
    dictionary = {}
    collide = False
    while not collide:
        random_message = str(random.getrandbits(256))
        digest = task_4_collisions(random_message, size)
        if dictionary.get(digest) is not None:
            if dictionary[digest] != random_message:
                print(dictionary[digest])
                print(random_message)
                new_time = datetime.datetime.now()
                collide = True
            num_items -= 1
        dictionary[digest] = random_message
        num_items += 1
    print("Number of items: ", num_items)
    print("Total time: ", new_time-original_time)

    
if __name__ == "__main__":
    #crypt,n, phi = rsa(19)
    #decrypt(crypt, n, phi)
    #alice, iv = hack_rsa(19)
    #mallory_decrypt(alice, iv)
    #task_4_sha("apple", "appla")
    task_4_birthday()


    
