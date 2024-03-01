from random import random
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util import number
from aes_cbc import cbc_encrypt, cbc_decrypt
import math

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

    alice_SHA256 = SHA256.new()
    if (s_alice == 0):
        #edge-case
        s_alice_bytes_len = 1
    else:
        s_alice_bytes_len = math.floor(math.log(s_alice, 256) + 1)
    bytes_s_alice = s_alice.to_bytes(s_alice_bytes_len, "big") 
    #bytearray_print(bytes_s_alice)
    alice_SHA256.update(bytes_s_alice)

    bob_SHA256 = SHA256.new()
    if (s_bob == 0):
        s_bob_bytes_len = 1
    else:
        s_bob_bytes_len = math.floor(math.log(s_bob, 256) + 1)
    bytes_s_bob = s_bob.to_bytes(s_bob_bytes_len, "big") 
    bob_SHA256.update(bytes_s_bob)
    a = truncate(alice_SHA256.digest())
    b = truncate(bob_SHA256.digest())
    return (a, b)

def diffie_tamper_public(p, g):
    a_private = int(random()*p)
    b_private = int(random()*p)
    while a_private == b_private:
        b_private = int(random() * p)

    a_public = pow(g, a_private, p)
    b_public = pow(g, b_private, p)

    #TAMPER!
    a_public = p
    b_public = p

    s_alice = pow(b_public, a_private, p)
    s_bob = pow(a_public, b_private, p)

    alice_SHA256 = SHA256.new()
    if (s_alice == 0):
        #edge-case
        s_alice_bytes_len = 1
    else:
        s_alice_bytes_len = math.floor(math.log(s_alice, 256) + 1)
    bytes_s_alice = s_alice.to_bytes(s_alice_bytes_len, "big") 
    alice_SHA256.update(bytes_s_alice)

    bob_SHA256 = SHA256.new()
    if (s_bob == 0):
        s_bob_bytes_len = 1
    else:
        s_bob_bytes_len = math.floor(math.log(s_bob, 256) + 1)
    bytes_s_bob = s_bob.to_bytes(s_bob_bytes_len, "big") 
    bob_SHA256.update(bytes_s_bob)

    a = truncate(alice_SHA256.digest())
    b = truncate(bob_SHA256.digest())
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
    p_hex = '0xB10B8F96 A080E01D DE92DE5E AE5D54EC 52C99FBC FB06A3C6 \
        9A6A9DCA 52D23B61 6073E286 75A23D18 9838EF1E 2EE652C0 \
        13ECB4AE A9061123 24975C3C D49B83BF ACCBDD7D 90C4BD70 \
        98488E9C 219A7372 4EFFD6FA E5644738 FAA31A4F F55BCCC0 \
        A151AF5F 0DC8B4BD 45BF37DF 365C1A65 E68CFDA7 6D4DA708 \
        DF1FB2BC 2E4A4371'.replace(" ", "")
    p = int(p_hex, 0)
    
    g_hex ='0x\
        A4D1CBD5 C3FD3412 6765A442 EFB99905 F8104DD2 58AC507F \
        D6406CFF 14266D31 266FEA1E 5C41564B 777E690F 5504F213 \
        160217B4 B01B886A 5E91547F 9E2749F4 D7FBD7D3 B9A92EE1 \
        909D0D22 63F80A76 A6A24C08 7A091F53 1DBF0A01 69B6A28A \
        D662A4D1 8E73AFA3 2D779D59 18D08BC8 858F4DCE F97C2A24 \
        855E6EEB 22B3B2E5'.replace(" ", "")
    g = int(g_hex, 0)

    (a, b) = diffie(p, g)
    init_vector = get_random_bytes(KEY_SIZE)
    alice_bob_original = "Hello Bob! I am Alice. This message is long to test. I am writing now."
    alice_bob_cipher = cbc_encrypt(alice_bob_original, a, init_vector)
    alice_bob_decrypted = cbc_decrypt(alice_bob_cipher, b, init_vector)
    print(alice_bob_decrypted)

def exchange_ietf1024_hacked():
    p_hex = '0xB10B8F96 A080E01D DE92DE5E AE5D54EC 52C99FBC FB06A3C6 \
        9A6A9DCA 52D23B61 6073E286 75A23D18 9838EF1E 2EE652C0 \
        13ECB4AE A9061123 24975C3C D49B83BF ACCBDD7D 90C4BD70 \
        98488E9C 219A7372 4EFFD6FA E5644738 FAA31A4F F55BCCC0 \
        A151AF5F 0DC8B4BD 45BF37DF 365C1A65 E68CFDA7 6D4DA708 \
        DF1FB2BC 2E4A4371'.replace(" ", "")
    p = int(p_hex, 0)
    
    g_hex ='0x\
        A4D1CBD5 C3FD3412 6765A442 EFB99905 F8104DD2 58AC507F \
        D6406CFF 14266D31 266FEA1E 5C41564B 777E690F 5504F213 \
        160217B4 B01B886A 5E91547F 9E2749F4 D7FBD7D3 B9A92EE1 \
        909D0D22 63F80A76 A6A24C08 7A091F53 1DBF0A01 69B6A28A \
        D662A4D1 8E73AFA3 2D779D59 18D08BC8 858F4DCE F97C2A24 \
        855E6EEB 22B3B2E5'.replace(" ", "")
    g = int(g_hex, 0)
    (a, b) = diffie_tamper_public(p, g)
    init_vector = get_random_bytes(KEY_SIZE)
    alice_bob_original = "Hello Bob! I am Alice. This message is long to test. I am writing now."
    alice_bob_cipher = cbc_encrypt(alice_bob_original, a, init_vector)
    #bytearray_print(a)
    
    s_mallory = 0
    bytes_s_mallory = s_mallory.to_bytes(1, "big") 
    mallory_SHA256 = SHA256.new()
    mallory_SHA256.update(bytes_s_mallory)
    stolen_a = truncate(mallory_SHA256.digest())
    mallory_stolen = cbc_decrypt(alice_bob_cipher, stolen_a, init_vector)
    print(mallory_stolen)

def exchange_ietf1024_hacked_g1():
    p_hex = '0xB10B8F96 A080E01D DE92DE5E AE5D54EC 52C99FBC FB06A3C6 \
        9A6A9DCA 52D23B61 6073E286 75A23D18 9838EF1E 2EE652C0 \
        13ECB4AE A9061123 24975C3C D49B83BF ACCBDD7D 90C4BD70 \
        98488E9C 219A7372 4EFFD6FA E5644738 FAA31A4F F55BCCC0 \
        A151AF5F 0DC8B4BD 45BF37DF 365C1A65 E68CFDA7 6D4DA708 \
        DF1FB2BC 2E4A4371'.replace(" ", "")
    p = int(p_hex, 0)
    
    g_hex ='0x\
        A4D1CBD5 C3FD3412 6765A442 EFB99905 F8104DD2 58AC507F \
        D6406CFF 14266D31 266FEA1E 5C41564B 777E690F 5504F213 \
        160217B4 B01B886A 5E91547F 9E2749F4 D7FBD7D3 B9A92EE1 \
        909D0D22 63F80A76 A6A24C08 7A091F53 1DBF0A01 69B6A28A \
        D662A4D1 8E73AFA3 2D779D59 18D08BC8 858F4DCE F97C2A24 \
        855E6EEB 22B3B2E5'.replace(" ", "")
    g = int(g_hex, 0)

    g = 1 #TAMPER!!
    (a, b) = diffie(p, g)
    init_vector = get_random_bytes(KEY_SIZE)
    alice_bob_original = "Hello Bob! I am Alice. This message is long to test. I am writing now."
    alice_bob_cipher = cbc_encrypt(alice_bob_original, a, init_vector)
    
    s_mallory = 1
    bytes_s_mallory = s_mallory.to_bytes(1, "big") 
    mallory_SHA256 = SHA256.new()
    mallory_SHA256.update(bytes_s_mallory)
    stolen_a = truncate(mallory_SHA256.digest())
    mallory_stolen = cbc_decrypt(alice_bob_cipher, stolen_a, init_vector)
    print(mallory_stolen)

def exchange_ietf1024_hacked_gp():
    p_hex = '0xB10B8F96 A080E01D DE92DE5E AE5D54EC 52C99FBC FB06A3C6 \
        9A6A9DCA 52D23B61 6073E286 75A23D18 9838EF1E 2EE652C0 \
        13ECB4AE A9061123 24975C3C D49B83BF ACCBDD7D 90C4BD70 \
        98488E9C 219A7372 4EFFD6FA E5644738 FAA31A4F F55BCCC0 \
        A151AF5F 0DC8B4BD 45BF37DF 365C1A65 E68CFDA7 6D4DA708 \
        DF1FB2BC 2E4A4371'.replace(" ", "")
    p = int(p_hex, 0)
    
    g_hex ='0x\
        A4D1CBD5 C3FD3412 6765A442 EFB99905 F8104DD2 58AC507F \
        D6406CFF 14266D31 266FEA1E 5C41564B 777E690F 5504F213 \
        160217B4 B01B886A 5E91547F 9E2749F4 D7FBD7D3 B9A92EE1 \
        909D0D22 63F80A76 A6A24C08 7A091F53 1DBF0A01 69B6A28A \
        D662A4D1 8E73AFA3 2D779D59 18D08BC8 858F4DCE F97C2A24 \
        855E6EEB 22B3B2E5'.replace(" ", "")
    g = int(g_hex, 0)

    g = p #TAMPER!!
    (a, b) = diffie(p, g)
    init_vector = get_random_bytes(KEY_SIZE)
    alice_bob_original = "Hello Bob! I am Alice. This message is long to test. I am writing now."
    alice_bob_cipher = cbc_encrypt(alice_bob_original, a, init_vector)
    
    s_mallory = 0
    bytes_s_mallory = s_mallory.to_bytes(1, "big") 
    mallory_SHA256 = SHA256.new()
    mallory_SHA256.update(bytes_s_mallory)
    stolen_a = truncate(mallory_SHA256.digest())
    mallory_stolen = cbc_decrypt(alice_bob_cipher, stolen_a, init_vector)
    print(mallory_stolen)

def exchange_ietf1024_hacked_gp1():
    p_hex = '0xB10B8F96 A080E01D DE92DE5E AE5D54EC 52C99FBC FB06A3C6 \
        9A6A9DCA 52D23B61 6073E286 75A23D18 9838EF1E 2EE652C0 \
        13ECB4AE A9061123 24975C3C D49B83BF ACCBDD7D 90C4BD70 \
        98488E9C 219A7372 4EFFD6FA E5644738 FAA31A4F F55BCCC0 \
        A151AF5F 0DC8B4BD 45BF37DF 365C1A65 E68CFDA7 6D4DA708 \
        DF1FB2BC 2E4A4371'.replace(" ", "")
    p = int(p_hex, 0)
    
    g_hex ='0x\
        A4D1CBD5 C3FD3412 6765A442 EFB99905 F8104DD2 58AC507F \
        D6406CFF 14266D31 266FEA1E 5C41564B 777E690F 5504F213 \
        160217B4 B01B886A 5E91547F 9E2749F4 D7FBD7D3 B9A92EE1 \
        909D0D22 63F80A76 A6A24C08 7A091F53 1DBF0A01 69B6A28A \
        D662A4D1 8E73AFA3 2D779D59 18D08BC8 858F4DCE F97C2A24 \
        855E6EEB 22B3B2E5'.replace(" ", "")
    g = int(g_hex, 0)

    g = p-1 #TAMPER!!
    (a, b) = diffie(p, g)
    init_vector = get_random_bytes(KEY_SIZE)
    alice_bob_original = "Hello Bob! I am Alice. This message is long to test. I am writing now."
    alice_bob_cipher = cbc_encrypt(alice_bob_original, a, init_vector)

    s_mallory1 = 1
    bytes_s_mallory1 = s_mallory1.to_bytes(1, "big") 
    mallory_SHA256 = SHA256.new()
    mallory_SHA256.update(bytes_s_mallory1)
    stolen_a1 = truncate(mallory_SHA256.digest())
    mallory_stolen1 = cbc_decrypt(alice_bob_cipher, stolen_a1, init_vector)
    print(mallory_stolen1)

def bytearray_print(x):
    print(''.join('\\{:02x}'.format(letter) for letter in x))
    #0 = leading 0 padding
    #2 = min width 2
    #x = interpret letter as hex



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

    
if __name__ == "__main__":
    #crypt,n, phi = rsa(19)
    #decrypt(crypt, n, phi)
    
    #alice, iv = hack_rsa(19)
    #mallory_decrypt(alice, iv)
    exchange_ietf1024_hacked_gp1()
    