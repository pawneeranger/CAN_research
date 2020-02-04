# -*- coding: utf-8 -*-
"""AnchorCAN implementation

AnchorCAN is an Anchor-based Secure CAN Communications System.

This code is an attempt at implementing in Python the proposal of the
AnchorCAN_ research paper.

.. _AnchorCAN: https://ieeexplore.ieee.org/document/8625173/

An example of possible usage is the following:

    >>> gateway_private_key = b'thisisjustakeeeythisisjustakeeey'
    >>> gateway_initial_vector = b'1'
    >>> gateway_can_id = b'01'
    >>>
    >>> gateway1 = GatewayECU(gateway_private_key, gateway_initial_vector, gateway_can_id)
    >>> random = get_random_bytes(56)
    >>> anchor_frame = gateway1.generateAnchorFrame(random)
    >>> 
    >>> ecu1 = ECU(gateway_private_key, gateway_initial_vector, gateway_can_id)
    >>>
    >>> random_number = ecu.readAnchorFrame(anchor_frame)
    >>> ecu1.setCurrentAnchorRandomNumber(random_number)
    >>>
    >>> can_id = b'02'
    >>> can_id_private_key = b'thisisjustakeeeythisisjustakeeey'
    >>> can_id_counter = b'01'
    >>> can_id_initial_vector = b'1'
    >>> ecu1.addCanIDConfig(can_id, can_id_private_key, can_id_counter, can_id_initial_vector)
    >>>
    >>> message = message = b'thisisthemessagethisisthemessagethisisthemessagethisis'
    >>> can_data_frame = ecu1.generateAnchorCanData(message, can_id)

.. _AnchorCAN: https://ieeexplore.ieee.org/document/8625173/
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from Crypto.Util import Counter
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Util.strxor import strxor as xor

class GatewayECU:
    """Class defining a stateful GatewayECU object, used as trusted party and 
    global source of freshness
    """
    def __init__(self, gateway_private_key, gateway_initial_vector, gateway_can_id):
        """Constructor for GatewayECU"""
        self.gateway_private_key = gateway_private_key
        self.gateway_initial_vector = gateway_initial_vector
        self.gateway_can_id = gateway_can_id
        
    def generateAnchorFrame(self, anchor_random_number):
        """Return an anchor frame: an encrypted random number ready to be securely sent to ECUs
        
        Parameters
        
        - **anchor_random_number** *byte string* : random number to send to the ECUs
        """
        # Key derivation function
        salt = self.gateway_initial_vector
        kdf= PBKDF2HMAC(
            algorithm = hashes.SHA256(),
            length = 64,
            salt = salt,
            iterations = 10000,
            backend = default_backend()
        )
        kdf_output = kdf.derive(self.gateway_private_key)
        ctr_counter = Counter.new(120, self.gateway_initial_vector) #counter size will be 120 bits + *gateway_initial_vector size* bits. Counter size should be as big as block size (https://pythonhosted.org/pycrypto/Crypto.Cipher.blockalgo-module.html#MODE_CTR)
        block_cipher = AES.new(self.gateway_private_key, AES.MODE_CTR, counter = ctr_counter)
        derived_key = block_cipher.encrypt(kdf_output)
        
        # Authentication
        hmac = HMAC.new(kdf_output, digestmod = SHA256)
        hmac.update(anchor_random_number)
        authentication = hmac.hexdigest().encode()[:8]
        
        # Encryption
        data_frame = anchor_random_number + authentication
        ciphertext = xor(data_frame, derived_key)
        
        return ciphertext
    
class ECU:
    """Class defining a stateful ECU object"""
    def __init__(self, gateway_private_key, gateway_initial_vector, gateway_can_id):
        """Constructor for an ECU
        
        Parameters 
        
        - **gateway_private_key** *byte string* : private key of the gateway ECU
    
        - **gateway_initial_vector** *byte string* : initial vector of the gateway ECU
        
        - **gateway_can_id** *byte string* : the CAN ID used by the gateway to send anchor frames
        """
        self.gateway_private_key = gateway_private_key
        self.gateway_initial_vector = gateway_initial_vector
        self.gateway_can_id = gateway_can_id
        self.can_id_data = {} #**can_id_data** *dict* : dictionnary associating CAN IDs and their corresponding key, counter, and initial vector
        self.current_anchor_random_number = "" #**current_anchor_random_number** *byte string* : last anchor random number received by the ECU
        
    def addCanIDConfig(self, can_id, can_id_private_key, can_id_counter, can_id_initial_vector):
        """Set private key, local counter and initial vector for a given CAN ID.
        Those informations are then added to the ECU.
        
        Parameters
        
        - **can_id** *byte string* : CAN ID
        
        - **can_id_private_key** *byte string* : private key corresponding to the CAN ID
        
        - **can_id_initial_vector** *byte string* : initial vector used for this CAN ID
        """
        self.can_id_data[can_id] = [can_id_private_key, can_id_counter, can_id_initial_vector]
        
    def removeCanIDConfig(self, can_id):
        """Remove private key, local counter and initial vector for a given CAN ID.
        
        Parameters
        
        - **can_id** *byte string* : CAN ID
        """
        del self.can_id_data[can_id]
        
    def setCurrentAnchorRandomNumber(self, anchor_random_number):
        """Set current anchor random number to the given number"""
        self.current_anchor_random_number = anchor_random_number
        
    def readAnchorFrame(self, ciphertext):
        """Decrypt and verify an anchor frame
        
        Parameters
        
        - **ciphertext** *byte string* : encrypted anchor frame
        """
        # Key derivation function
        salt = self.gateway_initial_vector
        kdf= PBKDF2HMAC(
            algorithm = hashes.SHA256(),
            length = 64,
            salt = salt,
            iterations = 10000,
            backend = default_backend()
        )
        kdf_output = kdf.derive(self.gateway_private_key)
        ctr_counter = Counter.new(120, self.gateway_initial_vector) #counter size will be 120 bits + *gateway_initial_vector size* bits. Counter size should be as big as block size (https://pythonhosted.org/pycrypto/Crypto.Cipher.blockalgo-module.html#MODE_CTR)
        block_cipher = AES.new(self.gateway_private_key, AES.MODE_CTR, counter = ctr_counter)
        derived_key = block_cipher.encrypt(kdf_output)
        
        # Decryption
        data_frame = xor(derived_key, ciphertext)
        anchor_random_number = data_frame[:56]
        received_hash = data_frame[56:64]
        
        # Authentication check
        hmac = HMAC.new(kdf_output, digestmod = SHA256)
        hmac.update(anchor_random_number)
        authentication = hmac.hexdigest().encode()[:8]
        
        if  authentication == received_hash:
            print("\nSuccesful authentication, anchor random number is: " + str("".join("\\x%02x" % i for i in anchor_random_number)))
        else:
            print("\nFailed authentication, can't retrieve anchor random number!")
            
        return anchor_random_number
    
    def generateAnchorCanData(self, message, can_id):
        """Return an encrypted CAN data frame
        
        Parameters
        
        - **message** *byte string* : data to be sent securely
        
        - **can_id** *byte string* : CAN ID to be used for this communication
        """
        can_id_key = self.can_id_data[can_id][0]
        can_id_counter = self.can_id_data[can_id][1]
        nonce = self.can_id_data[can_id][2]
        # TODO: understand why can_id_counter is only 2 bits while documentation recommends 4bits
        # Key derivation function
        salt = self.current_anchor_random_number
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
        hmac.update(message + can_id_counter + self.current_anchor_random_number)
        authentication = hmac.hexdigest().encode()[:8]
        
        # Encryption
        data_frame = message + can_id_counter + authentication
        ciphertext = xor(data_frame, derived_key)
        
        return ciphertext
    
    def readAnchorCanData(self, ciphertext, can_id):
        """Decrypt and verify a CAN data frame
        
        Parameters
        
        - **ciphertext** *byte string* : encrypted CAN data frame
        
        - **can_id** *byte string* : CAN ID used for this communication
        """
        can_id_key = self.can_id_data[can_id][0]
        #can_id_counter = self.can_id_data[can_id][1]
        nonce = self.can_id_data[can_id][2]
        # Key derivation function
        salt = self.current_anchor_random_number
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
        hmac.update(message + counter + self.current_anchor_random_number)
        authentication = hmac.hexdigest().encode()[:8]
        
        #TODO: add Ta (counter) check
        
        if  authentication == received_hash:
            print("\nSuccesful authentication, message is: " + str("".join("\\x%02x" % i for i in message)))
        else:
            print("\nFailed authentication, can't retrieve message!")
            
        return message
   
# TODO     
#    def read():
#        ldz
#        
#    def send():
#        ezfz
        
from Crypto.Random import get_random_bytes
    
gateway_private_key = b'thisisjustakeeeythisisjustakeeey'
gateway_initial_vector = b'1'
gateway_can_id = b'01'

gateway1 = GatewayECU(gateway_private_key, gateway_initial_vector, gateway_can_id)
random = get_random_bytes(56)
anchor_frame = gateway1.generateAnchorFrame(random)

ecu1 = ECU(gateway_private_key, gateway_initial_vector, gateway_can_id)

random_number = ecu1.readAnchorFrame(anchor_frame)
ecu1.setCurrentAnchorRandomNumber(random_number)

can_id = b'02'
can_id_private_key = b'thisisjustakeeeythisisjustakeeey'
can_id_counter = b'01'
can_id_initial_vector = b'1'
ecu1.addCanIDConfig(can_id, can_id_private_key, can_id_counter, can_id_initial_vector)

message = message = b'thisisthemessagethisisthemessagethisisthemessagethisis'
can_data_frame = ecu1.generateAnchorCanData(message, can_id)