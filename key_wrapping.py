#link: https://asecuritysite.com/encryption/kek

import binascii
import struct
from Crypto.Cipher import AES
import sys

QUAD = struct.Struct('>Q')

# code from https://github.com/kurtbrose/aes_keywrap/blob/master/aes_keywrap.py
def aes_unwrap_key(kek, wrapped):
    n = len(wrapped)//8 - 1
    #NOTE: R[0] is never accessed, left in for consistency with RFC indices
    R = [None]+[wrapped[i*8:i*8+8] for i in range(1, n+1)]
    A = QUAD.unpack(wrapped[:8])[0]
    decrypt = AES.new(kek, AES.MODE_ECB).decrypt
    for j in range(5,-1,-1): #counting down
        for i in range(n, 0, -1): #(n, n-1, ..., 1)
            ciphertext = QUAD.pack(A^(n*j+i)) + R[i]
            B = decrypt(ciphertext)
            A = QUAD.unpack(B[:8])[0]
            R[i] = B[8:]
    return b"".join(R[1:]), A


# code from https://github.com/kurtbrose/aes_keywrap/blob/master/aes_keywrap.py
def aes_wrap_key(kek, plaintext, iv=0xa6a6a6a6a6a6a6a6):
    n = len(plaintext)//8
    R = [None]+[plaintext[i*8:i*8+8] for i in range(0, n)]
    A = iv
    encrypt = AES.new(kek, AES.MODE_ECB).encrypt
    for j in range(6):
        for i in range(1, n+1):
            B = encrypt(QUAD.pack(A) + R[i])
            A = QUAD.unpack(B[:8])[0] ^ (n*j + i)
            R[i] = B[8:]
    return QUAD.pack(A) + b"".join(R[1:])

kek="000102030405060708090A0B0C0D0E0F"
key="00112233445566778899AABBCCDDEEFF"

if (len(sys.argv)>1):
	kek=str(sys.argv[1])
if (len(sys.argv)>2):
	key=str(sys.argv[2])

KEK = binascii.unhexlify(kek)
KEY = binascii.unhexlify(key)

wrapped=aes_wrap_key(KEK,KEY)

rtn,iv=aes_unwrap_key(KEK,wrapped)
print ("KEK: ",kek)
print ("Key: ",key)
print ("Wrapped Key: ",binascii.hexlify(wrapped))
print ("Unwrapped key: ",binascii.hexlify(rtn))

# Test from RFC5649
# KEK: 000102030405060708090A0B0C0D0E0F
# Key: 00112233445566778899AABBCCDDEEFF
# Wrap: 1FA68B0A8112B447 AEF34BD8FB5A7B82 9D3E862371D2CFE5