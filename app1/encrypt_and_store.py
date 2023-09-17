# 文件：encrypt_and_store.py

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from sqlalchemy import insert
from create_db import engine, users
import base64
import time

start_time = time.time()

# 加载公钥
with open('public_key.pem', 'r') as f:
    public_key = RSA.importKey(f.read())

cipher_rsa = PKCS1_OAEP.new(public_key)

# 你的个人信息
personal_info = "My personal info"

# 加密个人信息
encrypted_data = cipher_rsa.encrypt(personal_info.encode())

with engine.connect() as connection:
    result = connection.execute(insert(users), {"id": 'user1', "encrypted_data": base64.b64encode(encrypted_data).decode()})

end_time = time.time()

print(f"Encrypt and store time: {end_time - start_time} seconds")
