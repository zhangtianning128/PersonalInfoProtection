from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import base64
import hashlib

def encrypt_url_with_public_key(url, public_key_filename, encrypted_filename, hash_filename):
    # 1. Load the public key from the file
    with open(public_key_filename, 'rb') as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())

    # 2. Encrypt the URL using the public key
    encrypted_url = public_key.encrypt(
        url.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Convert encrypted data to base64 for easier storage
    encrypted_url_b64 = base64.b64encode(encrypted_url)

    # 3. Save the encrypted URL to the file
    with open(encrypted_filename, 'wb') as encrypted_file:
        encrypted_file.write(encrypted_url_b64)

    # 4. Compute the hash of the URL
    url_hash = hashlib.sha256(url.encode('utf-8')).hexdigest()

    # 5. Save the hash to the file
    with open(hash_filename, 'w') as hash_file:
        hash_file.write(url_hash)

if __name__ == "__main__":
    url = input("Enter the URL to be encrypted: ")
    public_key_filename = input("Enter the filename containing the public key: ")
    encrypted_filename = input("Enter the filename to store the encrypted URL: ")
    hash_filename = input("Enter the filename to store the hash of the URL: ")

    encrypt_url_with_public_key(url, public_key_filename, encrypted_filename, hash_filename)
    print("Encryption and hashing done!")
