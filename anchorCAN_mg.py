from anchor_enc import encryption
from anchor_dec import decryption
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from Crypto.Util import Counter
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256

import sys
import os
import random
import time

def xor( var, key):
        key = key[:len(var)]
        int_var = int.from_bytes(var, sys.byteorder)
        int_key = int.from_bytes(key, sys.byteorder)
        int_enc = int_var ^ int_key
        return int_enc.to_bytes(len(var), sys.byteorder)
#Key derivation function
program_start = time.time()
R1 = random.getrandbits(64)
salt = os.urandom(64)
kdf= PBKDF2HMAC(
    algorithm = hashes.SHA256(),
    length = 64,
    salt = salt,
    iterations = 10000,
    backend = default_backend()
)

Cj= Counter.new(128)
Kb = kdf.derive(str(R1).encode())
encryption_start = time.time()

#Encryption
TA = '01'
dataframe = 'thisisthemessagethisisthemessagethisisthemessagethisis'
hmac = HMAC.new(Kb, digestmod = SHA256)
hmac.update(str(dataframe+TA+str(R1)).encode())
authentication = hmac.hexdigest().encode()[:8]
print(authentication)

KA = b'thisisjustakeeeythisisjustakeeey'
block_cipher = AES.new(KA, AES.MODE_CTR, counter = Cj)
key_derivation = block_cipher.encrypt(Kb)

ciphertext = xor(dataframe.encode()+TA.encode()+authentication, key_derivation)

message = xor(ciphertext, key_derivation)
message = message.decode()


#decryption
hmac = HMAC.new(Kb, digestmod = SHA256)
hmac.update(str(message[:54]+message[54:56]+str(R1)).encode())

if  hmac.hexdigest()[:8] == message[56:64]:
    print(message)
else:
    print("Failed authentication, can't retrieve message!")
