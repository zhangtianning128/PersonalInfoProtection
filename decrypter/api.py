import cryptography
import secrets
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from base64 import b64encode, b64decode
import datetime
from PIL import Image, ImageDraw
from io import BytesIO
import random
import hashlib
import psycopg2
import time
import numpy as np
from PIL import Image
import requests


app = Flask(__name__)

@app.route('/api/decrypt_data', methods=['POST'])
def decrypt_data():
    # Check if both encrypted_data and encrypted_image are present in the request
    if 'encrypted_data' not in request.files or 'encrypted_image' not in request.files:
        return jsonify({'error': 'Both encrypted_data and encrypted_image fields are required.'}), 400

    encrypted_data_file = request.files['encrypted_data']
    encrypted_image_file = request.files['encrypted_image']

    # Read the contents of the uploaded files
    encrypted_data = encrypted_data_file.read()
    encrypted_image = encrypted_image_file.read()

    # 加载第二方私钥
    with open('second_party_private_key.pem', 'rb') as f:
        second_party_private_key = serialization.load_pem_private_key(f.read(), password=None)

    # 解密对称密钥的顺序
    encrypted_order_length = second_party_private_key.key_size // 8
    encrypted_order = encrypted_data[:encrypted_order_length]
    key_order = second_party_private_key.decrypt(
        encrypted_order,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    key_order = list(key_order)
    print("This is key order")
    print(key_order)

    # 使用三个私钥解密对称密钥的三部分
    encrypted_symmetric_key_length = encrypted_order_length * 3  # Three parts each encrypted with a public key
    print("encrypted_symmetric_key_length = %d", encrypted_symmetric_key_length)
    encrypted_symmetric_key_parts = [encrypted_data[encrypted_order_length + i*encrypted_order_length:encrypted_order_length + (i+1)*encrypted_order_length] for i in range(3)]

    decrypted_symmetric_key_parts = []
    decrypt_service_ports = [4100, 4101, 4102]

    for i, encrypted_part in enumerate(encrypted_symmetric_key_parts):
        port = decrypt_service_ports[key_order[i]]
        response = requests.post(f"http://localhost:{port}/decrypt?key_number={key_order[i]+1}", data=encrypted_part)
        if response.status_code != 200:
            return f"Error in decryption from service at port {port}!", 500
        decrypted_symmetric_key_parts.append(response.content)


    # 组合对称密钥的三部分
    symmetric_key = b''.join(decrypted_symmetric_key_parts)

    # 提取公钥加密的对称密钥的hash
    encrypted_hash = encrypted_data[encrypted_order_length + encrypted_symmetric_key_length:]
    decrypted_hash = second_party_private_key.decrypt(
        encrypted_hash,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    computed_hash = compute_hash(symmetric_key)

    if decrypted_hash != computed_hash:
        return "Failed hash verification!", 400

    # 使用对称密钥解密图片
    cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(b'1234567890123456'), backend=default_backend())
    decryptor = cipher.decryptor()
    image_bytes = decryptor.update(encrypted_image) + decryptor.finalize()

    # 保存解密后的图片
    with open("decrypted_image.png", "wb") as image_file:
        image_file.write(image_bytes)

    return "Image saved successfully!"

# Test the function
# decrypted_message = decrypt_data(ENCRYPTED_DATA)  # Assuming ENCRYPTED_DATA contains the encrypted data
# print(decrypted_message)

# Define the function to compute the hash of the data
def compute_hash(data):
    return hashlib.sha256(data).digest()


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=4000)