# Let's break down the task into several steps:
# 1. Split the data into three parts.
# 2. Randomly determine the order of the three public keys.
# 3. Use each public key to encrypt the corresponding part of the data.
# 4. Compute the hash of each part of the data.
# 5. Concatenate the encrypted order, the encrypted data, and the hashes.
# 6. Encrypt the concatenated data with the first public key.

import hashlib
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Define the function to split the data into three parts
def split_data(data):
    third = len(data) // 3
    return [data[:third], data[third:2*third], data[2*third:]]

# Define the function to encrypt the data with a public key
def encrypt_with_public_key(data, public_key):
    cipher_rsa = PKCS1_OAEP.new(public_key)
    return cipher_rsa.encrypt(data)

# Define the function to compute the hash of the data
def compute_hash(data):
    return hashlib.sha256(data).digest()

# Now use these functions to perform the task
# Assume that the three public keys are stored in the files "public_key1.pem", "public_key2.pem", and "public_key3.pem"
public_keys = [RSA.import_key(open("/mnt/data/public_key{}.pem".format(i+1)).read()) for i in range(3)]
key_order = list(range(3))
random.shuffle(key_order)

data_parts = split_data(encrypted_image)
encrypted_data_parts = [encrypt_with_public_key(data_parts[key_order[i]], public_keys[i]) for i in range(3)]
hashes = [compute_hash(data_parts[i]) for i in range(3)]

# Concatenate the encrypted order, the encrypted data, and the hashes
result = b''.join([bytes(key_order),] + encrypted_data_parts + hashes)

# Encrypt the result with the first public key
encrypted_result = encrypt_with_public_key(result, public_keys[0])

# The encrypted result is now a byte string, we can encode it in base64 to make it easier to store or transmit
encrypted_result_b64 = b64encode(encrypted_result).decode()

encrypted_result_b64  # Return the final encrypted data
