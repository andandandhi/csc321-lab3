from Crypto.Cipher import AES
from typing import Generator

KEY_SIZE = 16

def pkcs7(buf: bytes) -> bytes:
    pad_len =  KEY_SIZE - len(buf)
    ba_buf = bytearray(buf) 
    for _ in range (pad_len):
        ba_buf.append(pad_len)
    return bytes(ba_buf)

def xor(words, iv):
    code = b""
    for i in range(0,len(words)):
        byte_1 = words[i]
        byte_2 = iv[i]
        xor_val = bytes([byte_1 ^ byte_2])
        code = code + xor_val
    return code

def cbc_encrypt_block(plaintextBlock: bytes, key: bytes, prev_chain: bytes) -> bytes:
    xor_val = xor(plaintextBlock, prev_chain)
    simpleCipher = AES.new(key, AES.MODE_ECB)    
    encryptedBlock = simpleCipher.encrypt(xor_val)
    return encryptedBlock

def cbc_encrypt(plaintext: str, key: bytes, init_v: bytes):
    byte_data = plaintext.encode('utf-8')
    ciphertext = bytearray()
    prev_cipherblock = init_v
    for byte16 in get_buf_pad(byte_data):
        cipherblock = cbc_encrypt_block(byte16, key, prev_cipherblock)
        ciphertext.extend(cipherblock)
        prev_cipherblock = cipherblock
    return(bytes(ciphertext))

def cbc_decrypt(ciphertext: bytes, key: bytes, init_v: bytes) -> str:
    """Decrypts CBC ciphertext.
    """
    algorithm = AES.new(key, AES.MODE_ECB)    
    decrypted_bytearray = bytearray()
    prev_cipherblock = init_v
    for cipherblock in get_buf(ciphertext):
        aes_out = algorithm.decrypt(cipherblock)
        plainblock = xor(aes_out, prev_cipherblock)
        decrypted_bytearray.extend(plainblock)
        prev_cipherblock = cipherblock
    pad_remove = decrypted_bytearray[-1]
    int(pad_remove)
    decrypted_bytearray = decrypted_bytearray[:-pad_remove]
    return decrypted_bytearray.decode('utf-8', errors='replace')


def get_buf_pad(message: bytes) -> Generator[bytes, None, None]:
    """Splits the message into 16 byte blocks, adding end padding.
    """
    buf = bytearray()
    for b in message:
        buf.append(b)
        if len(buf) == 16:
            encoding = bytes(buf)
            yield encoding
            buf = bytearray()
    padding = pkcs7(bytes(buf))
    yield padding

def get_buf(message: bytes) -> Generator[bytes, None, None]:
    """Splits the message into 16 byte blocks.
    Len(input) must be multiple of 16
    Does NOT remove padding. 
    TODO: remove padding.
    """
    buf = bytearray()
    for b in message:
        buf.append(b)
        if len(buf) == 16:
            yield bytes(buf)
            buf = bytearray()

    
    

