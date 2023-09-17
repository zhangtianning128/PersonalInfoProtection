from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

class Participant:
    def __init__(self):
        self.key = RSA.generate(2048)
        self.public_key = self.key.publickey()
        self.private_key = self.key

    def help_decrypt(self, encrypted_data, requester_public_key):
        cipher_rsa = PKCS1_OAEP.new(self.private_key)
        decrypted_data = cipher_rsa.decrypt(encrypted_data)

        cipher_rsa = PKCS1_OAEP.new(requester_public_key)
        encrypted_result = cipher_rsa.encrypt(decrypted_data)
        return encrypted_result

# Create three participants
participants = [Participant() for _ in range(3)]

# Assume that the encrypted data and the public key of the requester are provided
encrypted_data = ...
requester_public_key = ...

# Request each participant to help decrypt the data
results = [p.help_decrypt(encrypted_data, requester_public_key) for p in participants]
