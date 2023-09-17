from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import base64
import requests

def decrypt_url_with_private_key(encrypted_filename, private_key_filename):
    # 1. Load the private key from the file
    with open(private_key_filename, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )

    # 2. Load the encrypted URL (base64 format) from the file
    with open(encrypted_filename, 'rb') as encrypted_file:
        encrypted_url_b64 = encrypted_file.read()
        encrypted_url = base64.b64decode(encrypted_url_b64)

    # 3. Decrypt the URL using the private key
    decrypted_url = private_key.decrypt(
        encrypted_url,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode('utf-8')

    return decrypted_url

if __name__ == "__main__":
    encrypted_filename = input("Enter the filename containing the encrypted URL: ")
    private_key_filename = input("Enter the filename containing the private key: ")

    decrypted_url = decrypt_url_with_private_key(encrypted_filename, private_key_filename)
    print(f"Decrypted URL: {decrypted_url}")

    # 4. Access the decrypted URL
    try:
        response = requests.get(decrypted_url)
        print(f"Response from {decrypted_url}:\n{response.text}")
    except Exception as e:
        print(f"Error accessing the URL: {e}")
