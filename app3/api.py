import cryptography
import secrets
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from flask import Flask, request, jsonify
from sqlalchemy import create_engine, select, MetaData, Table
from lsbsteg import LSBSteg 
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from base64 import b64encode, b64decode
import jwt
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
SECRET_KEY = "my_secret_key"
TOKEN_EXPIRATION = 600  # 令牌有效期（秒）

@app.route('/login', methods=['POST'])
def login():
    start_time = time.time()
    # 获取用户的公钥和签名
    user_public_key = request.form.get('public_key')
    user_signature = base64.b64decode(request.form.get('signature'))

    # 验证签名
    try:
        key = serialization.load_pem_public_key(user_public_key.encode())
        key.verify(user_signature, user_public_key.encode(), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
    except (ValueError, TypeError):
        return jsonify({'message': 'Invalid public key or signature'}), 401

    # 创建令牌
    token = jwt.encode({
        'public_key': user_public_key,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=10)  # 令牌将在10分钟后过期
    }, SECRET_KEY, algorithm='HS256')
    print("Login took {:.6f} seconds".format(time.time() - start_time))
    return jsonify({'token': token})

@app.route('/api/get_data', methods=['GET'])
def get_data():
    print("Get data")
    start_time = time.time()
    # 从请求头中获取令牌
    token = request.headers.get('Authorization')
    request_type = request.args.get('request_type')  # 获取请求类型参数

    if not token:
        return jsonify({'message': 'Missing token'}), 401

    if not request_type:
        return jsonify({'message': 'Missing request type'}), 400

    try:
        # 验证令牌
        data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 401
    
    print("Get data took {:.6f} seconds".format(time.time() - start_time))
    
    return process_request(request_type)

def process_request(request_type):
    print("Process request")
    start_time = time.time()

    encrypted_data = read_from_table()

    # 使用 base64 解码从数据库中读取的加密数据字符串，以获取原始加密数据
#    privacy_values = b64decode(privacy_values_b64)

    # 加载私钥
    with open('private_key.pem', 'rb') as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)


    # 解密数据
    decrypted_data = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode()

    print(decrypted_data)

    # 加载第二方公钥
    with open('second_party_public_key.pem', 'rb') as f:
        second_party_public_key = serialization.load_pem_public_key(f.read())

    if request_type == 'Identity Verification':
        # 处理 type1 请求
        hidden_string = hide_random_bytes(decrypted_data, fraction_to_hide=0.1)
        image = string_to_image(hidden_string.decode())
        hidden_watermark = "Public key: {}\nTimestamp: {}".format(second_party_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode(), int(time.time()))
        image_with_hidden_watermark = add_hidden_watermark(image, hidden_watermark)
        image_with_hidden_watermark.save("watermarked_image.png")

        # 将PIL图像保存到字节缓冲区中
        buf = BytesIO()
        image_with_hidden_watermark.save(buf, format="PNG")
        image_bytes = buf.getvalue()

        # Assuming the helper functions like encrypt_with_public_key and compute_hash are defined elsewhere

        encrypt_start_time = time.time()

        # 1. 生成对称密钥
        symmetric_key = secrets.token_bytes(32)

        # 2. 使用对称密钥加密图片
        cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(b'1234567890123456'), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_image = encryptor.update(image_bytes) + encryptor.finalize()

        # 3. 将对称密钥分为3段
        third = len(symmetric_key) // 3
        symmetric_key_parts = [symmetric_key[:third], symmetric_key[third:2*third], symmetric_key[2*third:]]

        # Determine the order of public keys using shuffle
        public_keys = [serialization.load_pem_public_key(open("public_key_{}.pem".format(i+1), 'rb').read()) for i in range(3)]
        key_order = list(range(3))
        random.shuffle(key_order)

        # 4. 使用3个被shuffle后的公钥加密对称密钥的每一段
        encrypted_symmetric_key_parts = [public_keys[key_order[i]].encrypt(symmetric_key_parts[i], padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)) for i in range(3)]
        for idx, part in enumerate(encrypted_symmetric_key_parts):
            print(f"Part {idx + 1}: {len(part)}")

        # Encrypt the order using the second party's key
        encrypted_order = second_party_public_key.encrypt(
            bytes(key_order),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print("Encrypted key order len = %d", len(encrypted_order))

        # 使用第二方公钥加密的对称密钥的hash
        encrypted_symmetric_key_hash = second_party_public_key.encrypt(compute_hash(symmetric_key), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        print("Encrypted key hash len = %d", len(encrypted_symmetric_key_hash))

        # 结合所有结果
        result = b''.join([encrypted_order] + encrypted_symmetric_key_parts + [encrypted_symmetric_key_hash])

        # Print the encryption time
        print("Encrypt took {:.6f} seconds".format(time.time() - encrypt_start_time))

        print("ProcessRequest took {:.6f} seconds".format(time.time() - start_time))

        send_encrypted_data_to_decrypt_service(result, encrypted_image)

        return jsonify({'message': 'Request processed successfully.'}), 200

    elif request_type == 'Identity Collection':
        # 处理 type2 请求
        hidden_string = decrypted_data
        image = string_to_image(hidden_string.decode())
        hidden_watermark = "Public key: {}\nTimestamp: {}".format(second_party_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode(), int(time.time()))
        image_with_hidden_watermark = add_hidden_watermark(image, hidden_watermark)
        image_with_hidden_watermark.save("watermarked_image.png")

        # 将PIL图像保存到字节缓冲区中
        buf = BytesIO()
        image_with_hidden_watermark.save(buf, format="PNG")
        image_bytes = buf.getvalue()

        # Assuming the helper functions like encrypt_with_public_key and compute_hash are defined elsewhere

        encrypt_start_time = time.time()

        # 1. 生成对称密钥
        symmetric_key = secrets.token_bytes(32)

        # 2. 使用对称密钥加密图片
        cipher = Cipher(algorithms.AES(symmetric_key), modes.CFB(b'1234567890123456'), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_image = encryptor.update(image_bytes) + encryptor.finalize()

        # 3. 将对称密钥分为3段
        third = len(symmetric_key) // 3
        symmetric_key_parts = [symmetric_key[:third], symmetric_key[third:2*third], symmetric_key[2*third:]]

        # Determine the order of public keys using shuffle
        public_keys = [serialization.load_pem_public_key(open("public_key_{}.pem".format(i+1), 'rb').read()) for i in range(3)]
        key_order = list(range(3))
        random.shuffle(key_order)

        # 4. 使用3个被shuffle后的公钥加密对称密钥的每一段
        encrypted_symmetric_key_parts = [public_keys[key_order[i]].encrypt(symmetric_key_parts[i], padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)) for i in range(3)]
        for idx, part in enumerate(encrypted_symmetric_key_parts):
            print(f"Part {idx + 1}: {len(part)}")

        # Encrypt the order using the second party's key
        encrypted_order = second_party_public_key.encrypt(
            bytes(key_order),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print("Encrypted key order len = %d", len(encrypted_order))

        # 使用第二方公钥加密的对称密钥的hash
        encrypted_symmetric_key_hash = second_party_public_key.encrypt(compute_hash(symmetric_key), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        print("Encrypted key hash len = %d", len(encrypted_symmetric_key_hash))

        # 结合所有结果
        result = b''.join([encrypted_order] + encrypted_symmetric_key_parts + [encrypted_symmetric_key_hash])

        # Print the encryption time
        print("Encrypt took {:.6f} seconds".format(time.time() - encrypt_start_time))

        print("ProcessRequest took {:.6f} seconds".format(time.time() - start_time))

        send_encrypted_data_to_decrypt_service(result, encrypted_image)

        return jsonify({'message': 'Request processed successfully.'}), 200

    else:
        # 如果没有匹配的请求类型，返回错误消息
        return {'message': f'Unknown request type: {request_type}'}, 400


def hide_random_bytes(input_string, fraction_to_hide=0.1):
    start_time = time.time()
    string_bytes = input_string.encode()
    bytes_to_hide = int(len(string_bytes) * fraction_to_hide)
    hide_indices = random.sample(range(len(string_bytes)), bytes_to_hide)
    hidden_string_bytes = bytearray(string_bytes)
    for i in hide_indices:
        hidden_string_bytes[i] = ord('*')  # Replace with '*'
    print("HideRandomBytes took {:.6f} seconds".format(time.time() - start_time))
    return bytes(hidden_string_bytes)

def string_to_image(input_string):
    image_size = (100, 100)  # Start with a small image size
    font_size = 10  # Smaller font
    image = Image.new('RGB', image_size, color=(73, 109, 137))
    d = ImageDraw.Draw(image)
    lines = "\n".join([input_string[i:i+image_size[0]//font_size] for i in range(0, len(input_string), image_size[0]//font_size)])
    d.text((10,10), lines, fill=(255,255,0))
    
    buf = BytesIO()
    image.save(buf, format="PNG")
    while len(buf.getvalue()) > 570:
        # Reduce image size
        image_size = (image_size[0]-10, image_size[1]-10)
        image = Image.new('RGB', image_size, color=(73, 109, 137))
        d = ImageDraw.Draw(image)
        lines = "\n".join([input_string[i:i+image_size[0]//font_size] for i in range(0, len(input_string), image_size[0]//font_size)])
        d.text((10,10), lines, fill=(255,255,0))
        
        buf = BytesIO()
        image.save(buf, format="PNG")
        
    return image

def add_hidden_watermark(image, watermark_text):
    start_time = time.time()

    # 将PIL图像转换为numpy数组
    image_np = np.array(image)

    # 使用LSBSteg来隐藏水印
    carrier = LSBSteg(image_np)
    image_with_hidden_watermark_np = carrier.encode_text(watermark_text)

    # 将numpy数组转换回PIL图像
    image_with_hidden_watermark = Image.fromarray(image_with_hidden_watermark_np)

    print("AddHiddenWatermark took {:.6f} seconds".format(time.time() - start_time))
    return image_with_hidden_watermark

def read_from_table():
    start_time = time.time()
    conn = psycopg2.connect(
        host="db_container",  # 这是Docker容器的名字
        dbname="postgres",
        user="postgres",
        password="mysecretpassword"   # 这应该与您启动数据库容器时设置的密码匹配
    )

    cur = conn.cursor()
    cur.execute("SELECT data FROM encrypted_data WHERE name = 'Alice';")
    # 获取查询结果
    encrypted_data = bytes(cur.fetchone()[0])

#    print(encrypted_data)

    # 提取privacy列的内容
#    privacy_values_m = row[2]

#    privacy_values = memoryview_to_str(privacy_values_m)

#    print("Data read from database:", row[2])

    # 关闭游标和连接
    cur.close()
    conn.close()

    print("ReadFromTable took {:.6f} seconds".format(time.time() - start_time))

    # 返回提取的内容
    return encrypted_data  #privacy_values

import base64

def memoryview_to_str(memoryview_obj):
    # Convert memoryview to bytes
    decoded_bytes = memoryview_obj.tobytes()
    
    # Ensure the base64 string is correctly padded
    padding = 4 - (len(decoded_bytes) % 4)
    if padding:
        decoded_bytes += b'=' * padding
    
    try:
        # Convert bytes to base64 encoded string
        decoded_data = base64.b64decode(decoded_bytes)
        return decoded_data.decode('utf-8')
    except Exception as e:
        print("Error decoding:", e)
        return None



# Define the function to split the data into three parts
def split_data(data):
    sixth = len(data) // 6
    return [
        data[:sixth],
        data[sixth:2*sixth],
        data[2*sixth:3*sixth],
        data[3*sixth:4*sixth],
        data[4*sixth:5*sixth],
        data[5*sixth:]
    ]

# Define the function to encrypt the data with a public key
def encrypt_with_public_key(data, public_key):
    return public_key.encrypt(data, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

# Define the function to compute the hash of the data
def compute_hash(data):
    return hashlib.sha256(data).digest()

DECRYPT_SERVICE_URL = "http://192.168.3.13:4000"  # Replace with your decrypt service URL

def send_encrypted_data_to_decrypt_service(encrypted_data, encrypted_image):
    files = {
        'encrypted_data': encrypted_data,
        'encrypted_image': encrypted_image
    }
    response = requests.post(f"{DECRYPT_SERVICE_URL}/api/decrypt_data", files=files)
    
    if response.status_code == 200:
        print("Encrypted data sent successfully!")
    else:
        print(f"Failed to send encrypted data. Status code: {response.status_code}. Message: {response.text}")


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
