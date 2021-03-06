# -*- coding: utf-8 -*-
"""
Created on Sun Jan 12 16:06:59 2020

@author: server
"""

# Keys, Initial Vectors and Counters are set manually in each ECU

## Gateway functions ##
# generate anchor frame

## ECU functions ##
# receive anchor frame
# send CAN frame
# receive CAN frame

from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Hash import HMAC, SHA256

def send_anchor_frame(private_key, initial_vector, random_number):
    """Return an anchor frame (an encrypted random number ready to be securely sent to ECUs)
    
    Parameters
    
    - **private_key** *byte string* : private key of the gateway ECU
    
    - **initial vector** *byte string* : initial vector of the gateway ECU
    
    - **random_number** *byte string* : random number to send to the ECUs
    """
    # Inputs validation
    if not len(random_number) == 7:
        raise ValueError("Random number must have length of 7")
    if not (type(private_key) is bytes and type(initial_vector) is bytes):
        raise TypeError("inputs must be of type bytes")
        
    
    print("private key: " + str("".join("\\x%02x" % i for i in private_key))) # display bytes
    print("initial vector: " + str("".join("\\x%02x" % i for i in initial_vector))) # display bytes
    
    
    # Key derivation
    counter_length = 1 * 8 #value in bits, must be multiple of 8
    session_key = PBKDF2(private_key, initial_vector, dkLen=16, prf=None) # dklen = size of output in bytes, prf = pseudo random function, default is HMAC-SHA1
    nonce = initial_vector #set up counter with initial vector
    counter_function = Counter.new(counter_length, nonce) #counter size will be 64 bits + *nonce size* bits. Counter size should be as big as block size (https://pythonhosted.org/pycrypto/Crypto.Cipher.blockalgo-module.html#MODE_CTR)
    block_cipher = AES.new(session_key, AES.MODE_CTR, counter=counter_function) #cipher bits, CTR mode is used (cf III. B.)
    print (block_cipher._cipher)
    # TODO: ensure block_cipher is 64b
    
    # Shrinking
    
    # Authentication of the message
    authentication_information = HMAC.new(random_number, digestmod=SHA256).digest
    # TODO: shrink to (64 - bytesize_of_random_number) and ensure it is this size
    authenticated_random_number = random_number + authentication_information
    
    # Encryption
    #block_cipher.encrypt performs XOR
    anchor_frame = block_cipher.encrypt(authenticated_random_number)
    return anchor_frame

# Generation of the random number that will be send to all ECUs
predefined_random_number_length = 7 #bytes, must be less than 8
random_number = get_random_bytes(predefined_random_number_length)
print("Random number to be sent to ECUs: " + str("".join("\\x%02x" % i for i in random_number))) # display bytes

ivb = get_random_bytes(8)
kb = b"ohmykey"

send_anchor_frame(kb,ivb,random_number)