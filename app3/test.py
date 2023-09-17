import requests
import base64

BASE_URL = "http://localhost:8080"

def login_to_service(public_key_filename, signature_filename):
    # Load public key from file
    with open(public_key_filename, 'r') as f:
        public_key = f.read()

    # Load signature from file
    with open(signature_filename, 'rb') as f:
        signature_binary = f.read()
        signature = base64.b64encode(signature_binary).decode()

    # Send login request
    data = {
        'public_key': public_key,
        'signature': signature
    }

    response = requests.post(f"{BASE_URL}/login", data=data)
    if response.status_code == 200:
        print("Successfully logged in!")
        return response.json().get('token')
    else:
        print(f"Login failed. Status code: {response.status_code}, Error: {response.text}")
        return None

def get_data_from_service(token, request_type):
    headers = {
        "Authorization": token
    }
    params = {
        "request_type": request_type
    }

    response = requests.get(f"{BASE_URL}/api/get_data", headers=headers, params=params)
    if response.status_code == 200:
        print("Data retrieved successfully!")
        return response.status_code
    else:
        print(f"Failed to retrieve data. Status code: {response.status_code}, Error: {response.text}")
        return None

if __name__ == "__main__":
    # Login
    public_key_filename = "second_party_public_key.pem"
    signature_filename = "second_party_signature.sig"
    token = login_to_service(public_key_filename, signature_filename)
    
    if token:
        # Get data
        request_type = "Identity Verification"  # or "Identity Collection"
        data = get_data_from_service(token, request_type)
        print(data)
