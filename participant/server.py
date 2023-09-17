from flask import Flask, request, jsonify
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

app = Flask(__name__)

# Assume that the private key of the participant is provided
private_key = ...

@app.route('/decrypt', methods=['POST'])
def decrypt():
    # Parse the request data
    data = request.get_json()
    encrypted_data = base64.b64decode(data['encrypted_data'])
    requester_public_key = RSA.import_key(base64.b64decode(data['requester_public_key']))

    # Decrypt the data with the private key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    decrypted_data = cipher_rsa.decrypt(encrypted_data)

    # Encrypt the result with the requester's public key
    cipher_rsa = PKCS1_OAEP.new(requester_public_key)
    encrypted_result = cipher_rsa.encrypt(decrypted_data)

    # Convert the result to a base64 string and return it in a JSON response
    encrypted_result_b64 = base64.b64encode(encrypted_result).decode()
    return jsonify({'encrypted_result': encrypted_result_b64})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
