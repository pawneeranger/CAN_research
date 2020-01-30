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
    
def sendCanFrame(anchor_random_number, message, can_id_key, can_id_counter, can_id_initial_vector):
    # Key derivation function
    salt = anchor_random_number
    kdf= PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length = 64,
        salt = salt,
        iterations = 10000,
        backend = default_backend()
    )
    kdf_output = kdf.derive(can_id_key)
    print("kdf_output_sending: " + str("".join("\\x%02x" % i for i in kdf_output)))
    block_cipher = AES.new(can_id_key, AES.MODE_CTR, counter = can_id_initial_vector)
    derived_key = block_cipher.encrypt(kdf_output)
    print("derived_key_sending: " + str("".join("\\x%02x" % i for i in kdf_output)))
    
    # Authentication
    hmac = HMAC.new(kdf_output, digestmod = SHA256)
    hmac.update(str(message + can_id_counter + anchor_random_number).encode())
    authentication = hmac.hexdigest().encode()[:8]
    
    # Encryption
    frame = message + can_id_counter + authentication
    print("frame_sending: " + str("".join("\\x%02x" % i for i in frame)))
    ciphertext = xor(message + can_id_counter + authentication, derived_key)
    
    return ciphertext

def receiveCanFrame(anchor_random_number, can_id_key, can_id_initial_vector, ciphertext):
    # Key derivation function
    salt = anchor_random_number
    kdf= PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length = 64,
        salt = salt,
        iterations = 10000,
        backend = default_backend()
    )
    kdf_output = kdf.derive(can_id_key)
    print("kdf_output_receiving: " + str("".join("\\x%02x" % i for i in kdf_output)))
    block_cipher = AES.new(can_id_key, AES.MODE_CTR, counter = can_id_initial_vector)
    derived_key = block_cipher.encrypt(kdf_output)
    print("derived_key_receiving: " + str("".join("\\x%02x" % i for i in kdf_output)))
    
    #decryption
    frame = xor(derived_key, ciphertext)
    print("frame_receiving: " + str("".join("\\x%02x" % i for i in frame)))
    hmac = HMAC.new(kdf_output, digestmod = SHA256)
    hmac.update(str(frame[:54] + frame[54:56] + str(anchor_random_number)).encode())
    
    if  hmac.hexdigest()[:8] == message[56:64]:
        print(message)
    else:
        print("Failed authentication, can't retrieve message!")



# Example code to use the functions
        
#sendCanFrame(anchor_random_number, message, can_id_key, can_id_counter, can_id_initial_vector)
anchor_random_number = get_random_bytes(64)
print("random_number: " + str("".join("\\x%02x" % i for i in anchor_random_number))) # display bytes
message = b'thisisthemessagethisisthemessagethisisthemessagethisis'
print("message: " + str("".join("\\x%02x" % i for i in message))) # display bytes
can_id_key = b'thisisjustakeeeythisisjustakeeey'
print("can_id_key: " + str("".join("\\x%02x" % i for i in can_id_key))) # display bytes
can_id_counter = b'01'
print("can_id_counter: " + str("".join("\\x%02x" % i for i in can_id_counter))) # display bytes
can_id_initial_vector= Counter.new(128)
ciphertext = sendCanFrame(anchor_random_number, message, can_id_key, can_id_counter, can_id_initial_vector)

receiveCanFrame(anchor_random_number, can_id_key, can_id_initial_vector, ciphertext)