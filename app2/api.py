import psycopg2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

def test_table():

# 加载公钥
    with open('public_key.pem', 'rb') as f:
        public_key = serialization.load_pem_public_key(
            f.read()
        )

    with open('private_key.pem', 'rb') as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    # 3. 使用公钥加密数据
    plaintext = "Hello, World!"
    ciphertext = public_key.encrypt(
        plaintext.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print(ciphertext)

    # 4. 将加密的数据存储到 PostgreSQL 数据库
    conn = psycopg2.connect(
            host="db_container",  # 这是Docker容器的名字
            dbname="postgres",
            user="postgres",
            password="mysecretpassword"  # 这应该与您启动数据库容器时设置的密码匹配
        )
    cur = conn.cursor()
    cur.execute("DROP TABLE IF EXISTS encrypted_data;")
    cur.execute("CREATE TABLE encrypted_data (id serial PRIMARY KEY, name text,data bytea);")
#    cur.execute("""
#        CREATE TABLE IF NOT EXISTS encrypted_table (
#            id SERIAL PRIMARY KEY,
#            name TEXT NOT NULL,
#            privacy BYTEA
#        )
#        """)
    name = "Alice"
#    cur.execute("INSERT INTO encrypted_table (name, privacy) VALUES (%s, %s)", (name, ciphertext))
    cur.execute("INSERT INTO encrypted_data (name, data) VALUES (%s, %s) RETURNING id;", ('Alice', ciphertext,))
    row_id = cur.fetchone()[0]
    conn.commit()

    # 5. 从数据库读取加密的数据
    cur.execute("SELECT data FROM encrypted_data WHERE name = 'Alice';")
#    cur.execute("SELECT privacy FROM encrypted_table WHERE name = 'Alice'")
    encrypted_data = bytes(cur.fetchone()[0])
#    encrypted_data = bytes(cur.fetchone()[0])
    print(encrypted_data)

    # 6. 使用私钥解密数据
    decrypted_data = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode()

    print(decrypted_data)  # 应该输出 "Hello, World!"

    cur.close()
    conn.close()

if __name__ == '__main__':
    test_table()