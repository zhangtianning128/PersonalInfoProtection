from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

app = Flask(__name__)

@app.route('/decrypt', methods=['POST'])
def decrypt_part():
    encrypted_data = request.data
    key_number = request.args.get('key_number')

    # 加载相应的私钥
    with open(f"private_key_{key_number}.pem", 'rb') as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    decrypted_data = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return decrypted_data

if __name__ == '__main__':
    # 获取要监听的端口
    import sys
    port = int(sys.argv[1])
    app.run(host='0.0.0.0', port=port)
