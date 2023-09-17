from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import psycopg2
import time
from base64 import b64encode, b64decode



def create_and_insert_into_table():
    start_time = time.time()

    # 加载公钥
    with open('public_key.pem', 'rb') as f:
        public_key = serialization.load_pem_public_key(
            f.read()
        )

    plaintext = "This is my personal info"

    ciphertext = public_key.encrypt(
        plaintext.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # 将加密数据转为base64字符串
    #ciphertext_b64 = b64encode(ciphertext).decode()

    conn = psycopg2.connect(
        host="db_container",  # 这是Docker容器的名字
        dbname="postgres",
        user="postgres",
        password="mysecretpassword"  # 这应该与您启动数据库容器时设置的密码匹配
    )

    cur = conn.cursor()

    # 创建表
    cur.execute("DROP TABLE IF EXISTS encrypted_data;")
    cur.execute("CREATE TABLE encrypted_data (id serial PRIMARY KEY, name text,data bytea);")

    # 插入加密数据
    cur.execute("INSERT INTO encrypted_data (name, data) VALUES (%s, %s) RETURNING id;", ('Alice', ciphertext,))
#    cur.execute("INSERT INTO encrypted_table (name, privacy) VALUES (%s, %s)", (name, plaintext))

#    print("Encrypted personal info (base64):", ciphertext_b64)
#    print("personal info (base64):", plaintext)
    # 提交更改
    conn.commit()

    end_time = time.time()

    print(f"Write database time: {end_time - start_time} seconds")

    cur.close()
    conn.close()

if __name__ == "__main__":
    create_and_insert_into_table()
