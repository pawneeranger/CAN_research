# -*- coding: utf-8 -*-
"""AnchorCAN implementation

AnchorCAN is an Anchor-based Secure CAN Communications System.

This code is an attempt at implementing in Python the proposal of the
AnchorCAN_ research paper.

.. _AnchorCAN: https://ieeexplore.ieee.org/document/8625173/

An example of possible usage is the following:

    >>> gateway_private_key = b'thisisjustakeeeythisisjustakeeey'
    >>> gateway_initial_vector = b'1'
    >>> gt = GatewayECU(gateway_private_key, gateway_initial_vector)
    >>> random = get_random_bytes(56)
    >>> gt.generateAnchorFrame(random)

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
    def __init__(self, gateway_private_key, gateway_initial_vector):
        """Constructor for GatewayECU"""
        self.gateway_private_key = gateway_private_key
        self.gateway_initial_vector = gateway_initial_vector
        
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
    def __init__(self, gateway_private_key, gateway_initial_vector):
        """Constructor for an ECU"""
        self.gateway_private_key = gateway_private_key
        self.gateway_initial_vector = gateway_initial_vector