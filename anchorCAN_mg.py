from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from Crypto.Util import Counter
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256

import sys
from Crypto.Random import get_random_bytes

def xor( var, key):
        key = key[:len(var)]
        int_var = int.from_bytes(var, sys.byteorder)
        int_key = int.from_bytes(key, sys.byteorder)
        int_enc = int_var ^ int_key
        return int_enc.to_bytes(len(var), sys.byteorder)
    
def sendCanFrame(anchor_random_number, message, can_id_key, can_id_counter, can_id_initial_vector, gateway_private_key, gateway_initial_vector):
    # Key derivation function
    salt = get_random_bytes(64)
    kdf= PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length = 64,
        salt = salt,
        iterations = 10000,
        backend = default_backend()
    )
    kdf_output = kdf.derive(str(anchor_random_number).encode())
    block_cipher = AES.new(can_id_key, AES.MODE_CTR, counter = can_id_initial_vector)
    derived_key = block_cipher.encrypt(kdf_output)
    
    # Authentication
    hmac = HMAC.new(kdf_output, digestmod = SHA256)
    hmac.update(str(message + can_id_counter + str(anchor_random_number)).encode())
    authentication = hmac.hexdigest().encode()[:8]
    
    # Encryption
    ciphertext = xor(message.encode() + can_id_counter.encode() + authentication, derived_key)
    
    message = xor(ciphertext, derived_key) #TODO: understand why ? isnt it already done ?
    
    return ciphertext

def receiveCanFrame(anchor_random_number, can_id_key, can_id_initial_vector):
    #Key derivation function
    salt = get_random_bytes(64)
    kdf= PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length = 64,
        salt = salt,
        iterations = 10000,
        backend = default_backend()
    )
    kdf_output = kdf.derive(str(anchor_random_number).encode())
    block_cipher = AES.new(can_id_key, AES.MODE_CTR, counter = can_id_initial_vector)
    derived_key = block_cipher.encrypt(kdf_output)
    
    #decryption
    hmac = HMAC.new(kdf_output, digestmod = SHA256)
    hmac.update(str(message[:54] + message[54:56] + str(anchor_random_number)).encode())
    
    if  hmac.hexdigest()[:8] == message[56:64]:
        print(message)
    else:
        print("Failed authentication, can't retrieve message!")
    
anchor_random_number = get_random_bytes(64)
can_id_initial_vector= Counter.new(128)
can_id_counter = '01'
message = 'thisisthemessagethisisthemessagethisisthemessagethisis'
can_id_key = b'thisisjustakeeeythisisjustakeeey'
