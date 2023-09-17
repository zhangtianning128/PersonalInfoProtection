# Let's break down the task into several steps for the decryption side:
# 1. Decrypt the data with the first private key.
# 2. Extract the encrypted order, the encrypted data, and the hashes from the decrypted data.
# 3. Use each private key to decrypt the corresponding part of the data.
# 4. Verify the hash of each part of the data.

# Define the function to decrypt the data with a private key
def decrypt_with_private_key(data, private_key):
    cipher_rsa = PKCS1_OAEP.new(private_key)
    return cipher_rsa.decrypt(data)

# Define the function to verify the hash of the data
def verify_hash(data, hash_value):
    return hashlib.sha256(data).digest() == hash_value

# Now use these functions to perform the task
# Assume that the three private keys are stored in the files "private_key1.pem", "private_key2.pem", and "private_key3.pem"
private_keys = [RSA.import_key(open("/mnt/data/private_key{}.pem".format(i+1)).read()) for i in range(3)]

# Decrypt the data with the first private key
decrypted_result = decrypt_with_private_key(b64decode(encrypted_result_b64), private_keys[0])

# Extract the encrypted order, the encrypted data, and the hashes from the decrypted data
key_order = list(decrypted_result[:3])
encrypted_data_parts = [decrypted_result[3+i*256:3+(i+1)*256] for i in range(3)]
hashes = [decrypted_result[3+3*256+i*32:3+3*256+(i+1)*32] for i in range(3)]

# Use each private key to decrypt the corresponding part of the data
data_parts = [decrypt_with_private_key(encrypted_data_parts[key_order[i]], private_keys[i]) for i in range(3)]

# Verify the hash of each part of the data
hash_verification_results = [verify_hash(data_parts[i], hashes[i]) for i in range(3)]

# Check if all hash verification results are True
all(hash_verification_results)
