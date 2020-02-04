from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from Crypto.Util import Counter
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Util.strxor import strxor as xor
from Crypto.Random import get_random_bytes
import can

def generateAnchorFrame(anchor_random_number, message, can_id_key, can_id_counter, nonce):
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
    ctr_counter = Counter.new(120, nonce) #counter size will be 120 bits + *nonce size* bits. Counter size should be as big as block size (https://pythonhosted.org/pycrypto/Crypto.Cipher.blockalgo-module.html#MODE_CTR)
    block_cipher = AES.new(can_id_key, AES.MODE_CTR, counter = ctr_counter)
    derived_key = block_cipher.encrypt(kdf_output)
    
    # Authentication
    hmac = HMAC.new(kdf_output, digestmod = SHA256)
    hmac.update(message + can_id_counter + anchor_random_number)
    authentication = hmac.hexdigest().encode()[:8]
    
    # Encryption
    data_frame = message + can_id_counter + authentication
    ciphertext = xor(data_frame, derived_key)
    
    return ciphertext
   
def getCanID(can_frame):
    can_id = can_frame[1:11]
    return can_id



def generateAnchorCanData(anchor_random_number, message, can_id_key, can_id_counter, nonce):
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
    ctr_counter = Counter.new(120, nonce) #counter size will be 120 bits + *nonce size* bits. Counter size should be as big as block size (https://pythonhosted.org/pycrypto/Crypto.Cipher.blockalgo-module.html#MODE_CTR)
    block_cipher = AES.new(can_id_key, AES.MODE_CTR, counter = ctr_counter)
    derived_key = block_cipher.encrypt(kdf_output)
    
    # Authentication
    hmac = HMAC.new(kdf_output, digestmod = SHA256)
    hmac.update(message + can_id_counter + anchor_random_number)
    authentication = hmac.hexdigest().encode()[:8]
    
    # Encryption
    data_frame = message + can_id_counter + authentication
    ciphertext = xor(data_frame, derived_key)
    
    return ciphertext

def verifyAnchorCanData(anchor_random_number, can_id_key, nonce, ciphertext):
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
    ctr_counter = Counter.new(120, nonce) #counter size will be 120 bits + *nonce size* bits. Counter size should be as big as block size (https://pythonhosted.org/pycrypto/Crypto.Cipher.blockalgo-module.html#MODE_CTR)
    block_cipher = AES.new(can_id_key, AES.MODE_CTR, counter = ctr_counter)
    derived_key = block_cipher.encrypt(kdf_output)
    
    # Decryption
    data_frame = xor(derived_key, ciphertext)
    message = data_frame[:54]
    counter = data_frame[54:56]
    received_hash = data_frame[56:64]
    
    # Authentication check
    hmac = HMAC.new(kdf_output, digestmod = SHA256)
    hmac.update(message + counter + anchor_random_number)
    authentication = hmac.hexdigest().encode()[:8]
    
    #TODO: add Ta (counter) check
    
    if  authentication == received_hash:
        print("\nSuccesful authentication, message is: " + str(message))
    else:
        print("\nFailed authentication, can't retrieve message!")


# Example code to use the functions

#generateAnchorCanData(anchor_random_number, message, can_id_key, can_id_counter, can_id_initial_vector)
anchor_random_number = get_random_bytes(56)
print("random_number: " + str("".join("\\x%02x" % i for i in anchor_random_number))) # display bytes
message = b'thisisthemessagethisisthemessagethisisthemessagethisis'
print("message: " + str("".join("\\x%02x" % i for i in message))) # display bytes
can_id_key = b'thisisjustakeeeythisisjustakeeey'
print("can_id_key: " + str("".join("\\x%02x" % i for i in can_id_key))) # display bytes
can_id_counter = b'01' #must be incremented
print("can_id_counter: " + str("".join("\\x%02x" % i for i in can_id_counter))) # display bytes
initial_vector = get_random_bytes(1)
nonce = initial_vector
ciphertext = generateAnchorCanData(anchor_random_number, message, can_id_key, can_id_counter, nonce)

#verifyAnchorCanData(anchor_random_number, can_id_key, can_id_initial_vector, ciphertext)
can_id_key = b'thisisjustakeeeythisisjustakeeey'
can_id_counter = b'01' #must be incremented
verifyAnchorCanData(anchor_random_number, can_id_key, nonce, ciphertext)

#
bustype = 'socketcan'
channel = 'vcan0'
bus = can.interface.Bus(channel=channel, bustype=bustype)
for i in range(10):
    msg = can.Message(arbitration_id = 0xc0ffee, data = [id, i, 0, 1, 3, 1, 4, 1], is_extended_id = False, check = True)
    bus.send(msg)
