from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import sys

KEY_SIZE = 16
#below is for task 2
#aes_key = get_random_bytes(KEY_SIZE)
#iv = get_random_bytes(KEY_SIZE)

def file_reader() -> None:
    aes_key = get_random_bytes(KEY_SIZE)
    iv = get_random_bytes(KEY_SIZE)

    n = len(sys.argv)
    if(n < 1):
        print("Missing file name")
    
    filename = sys.argv[1]
    with open(filename, "rb") as in_file, \
        open("ecb_ciphertext.bmp", "wb") as ecb_file:
        
        ecb_file.write(in_file.read(54)) #i dont know how big bmp header is; this is guess

        buf = in_file.read(KEY_SIZE)
        while len(buf) == KEY_SIZE:
            ecb_file.write(ecb_encrypt(buf, aes_key))
            buf = in_file.read(KEY_SIZE)
        ecb_file.write(ecb_encrypt(pkcs7(buf), aes_key))

#changes start here for CBC
    with open(filename, "rb") as in_file, \
        open("cbc_ciphertext.bmp", "wb") as cbc_file:
        
        cbc_file.write(in_file.read(54)) #i dont know how big bmp header is; this is guess

        buf = in_file.read(KEY_SIZE)
        while len(buf) == KEY_SIZE:
            encrypted_buf = cbc_encrypt(buf, aes_key, iv)
            cbc_file.write(encrypted_buf)
            buf = in_file.read(KEY_SIZE)
            iv = encrypted_buf
        cbc_file.write(cbc_encrypt(pkcs7(buf), aes_key, iv))

def pkcs7(buf: bytes) -> bytes:
    pad_len =  KEY_SIZE - len(buf)
    ba_buf = bytearray(buf) 
    for _ in range (pad_len):
        ba_buf.append(pad_len)
    return bytes(ba_buf)

def ecb_encrypt(plaintextBlock: bytes, aes_key: bytes) -> bytes:
    simpleCipher = AES.new(aes_key, AES.MODE_ECB)
    encryptedBlock = simpleCipher.encrypt(plaintextBlock)
    return(encryptedBlock)

def conversion(word): #maybe change for just : and =
    conversion = ""
    for i in word:
        con = ord(i)
        conversion = conversion  + str(con)
    conversion  = int(conversion)
    return conversion

def xor(words, iv):
    code = b""
    for i in range(0,len(words)):
        byte_1 = words[i]
        byte_2 = iv[i]
        xor_val = bytes([byte_1 ^ byte_2])
        code = code + xor_val
    return code


def cbc_encrypt(plaintextBlock: bytes, key: bytes, init_v: bytes) -> bytes:
    
    #plaintextBlock = get_random_bytes(16) #in bytes
    #init_v = get_random_bytes(16) #in bytes
    #key = get_random_bytes(KEY_SIZE) #generating new key as per diagram in bytes
    xor_val = xor(plaintextBlock, init_v) #xoring plaintext and init vector
    #print("xor val:") #checking xor, you can remove thes two lines
    #print(xor_val)
    
    simpleCipher = AES.new(key, AES.MODE_ECB) #creating encrytpion alg
   
    
    encryptedBlock = simpleCipher.encrypt(xor_val)#encrypting the xored value with ECB (so this is CBC)
    #print("encrypted block:", encryptedBlock) #checking encryption
    return encryptedBlock
    

   #decryptedBlock = simpleCipher.decrypt(encryptedBlock) #checking decryption
    #print(decryptedBlock)

   

 

    

if __name__ == '__main__':
    file_reader()
    

