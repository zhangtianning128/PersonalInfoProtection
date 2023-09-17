#import requests

#response = requests.get('http://localhost:5000/blockchain/new')

#if response.status_code == 201:
#    print("New blockchain created successfully")
#    print("Blockchain ID:", response.json()['blockchain_id'])
#else:
#    print("Failed to create new blockchain")


import requests
import time
import base64

num_requests = 10
total_time = 0

# Read public key and signature from files
with open('D:\区块链\保护个人用户的隐私\public_key.pem', 'r', encoding='utf-8') as pk_file:
    public_key = pk_file.read().strip()

with open('D:\区块链\保护个人用户的隐私\signature.sig', 'rb') as sig_file:
    signature_binary = sig_file.read()
    # Encode the binary data to base64 for use in the JSON payload
    signature = base64.b64encode(signature_binary).decode('utf-8')

headers = {"Content-Type": "application/json"}
data = {
    "public_key": public_key,
    "signature": signature
}

for _ in range(num_requests):
    start_time = time.time()
    
    response = requests.post('http://localhost:5000/blockchain/new', headers=headers, json=data)

    end_time = time.time()
    duration = end_time - start_time
    total_time += duration

    if response.status_code == 201:
        print(f"New blockchain created successfully in {duration:.2f} seconds")
        print("Blockchain ID:", response.json()['blockchain_id'])
    else:
        print("Failed to create new blockchain")

average_time = total_time / num_requests
print(f"\nAverage time to create a new blockchain: {average_time:.2f} seconds")
