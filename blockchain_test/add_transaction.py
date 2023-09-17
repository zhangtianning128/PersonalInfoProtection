import requests
import json
import base64
import time

def create_transaction(blockchain_id, transaction_data):
    headers = {
        'Content-Type': 'application/json',
        'Blockchain-ID': blockchain_id
    }

    start_time = time.time()

    response = requests.post("http://127.0.0.1:5000/transactions/new", data=json.dumps(transaction_data), headers=headers)

    end_time = time.time()
    duration = end_time - start_time

    if response.status_code == 201:
        print("Transaction successfully created!")
        print(f"\nAverage time to add a transaction: {duration:.2f} seconds")
    else:
        print(f"Failed to create transaction. Error: {response.text}")

if __name__ == "__main__":
    blockchain_id = input("Enter the Blockchain ID: ")
    transaction_type = input("Enter transaction type (request or response): ")

    if transaction_type == "request":
        url = input("Enter URL: ")
        public_key_filename = input("Enter filename for public key: ")
        signature_filename = input("Enter filename for signature: ")
        reason = input("Enter reason: ")

        with open(public_key_filename, 'r', encoding='utf-8') as pk_file:
            public_key = pk_file.read().strip()

        with open(signature_filename, 'rb') as sig_file:
            signature_binary = sig_file.read()
            # Encode the binary data to base64 for use in the JSON payload
            signature = base64.b64encode(signature_binary).decode('utf-8')

        transaction_data = {
            "transaction_type": "request",
            "url": url,
            "public_key": public_key,
            "signature": signature,
            "reason": reason
        }
    elif transaction_type == "response":
        encrypted_info_filename = input("Enter filename for encrypted information: ")
        hash_filename = input("Enter filename for hash: ")

        with open(encrypted_info_filename, 'r', encoding='utf-8') as enc_file:
            encrypted_info = enc_file.read().strip()

        with open(hash_filename, 'r', encoding='utf-8') as hash_file:
            hash_val = hash_file.read().strip()

        transaction_data = {
            "transaction_type": "response",
            "encrypted_info": encrypted_info,
            "hash_val": hash_val
        }
    else:
        print("Invalid transaction type.")
        exit()

    create_transaction(blockchain_id, transaction_data)
