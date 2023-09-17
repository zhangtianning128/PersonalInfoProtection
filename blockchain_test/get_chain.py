import requests
import time
import base64

blockchain_id = 'f05663fa-15eb-422e-affc-3a2aceb0593e'

num_requests = 10
total_time = 0

for _ in range(num_requests):
    start_time = time.time()
    
    response = requests.get('http://localhost:5000/chain', headers={'Blockchain-ID': blockchain_id})

    end_time = time.time()
    duration = end_time - start_time
    total_time += duration

    if response.status_code == 200:
        chain_info = response.json()
        print(f"Length of the chain: {chain_info['length']}")
        print("Blocks:")
        for block in chain_info['chain']:
            print(block)
    else:
        print("Failed to get chain information")

average_time = total_time / num_requests
print(f"\nAverage time to fetch the chain: {average_time:.2f} seconds")
