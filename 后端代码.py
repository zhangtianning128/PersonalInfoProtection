from flask import Flask, request
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)

@app.route('/', methods=['POST'])
def verify_signature():
    # Get the public key and signature from the form data
    public_key_pem = request.form.get('public_key').encode()
    signature = bytes.fromhex(request.form.get('signature'))

    # The message that the user signed
    message = "This is a message that needs to be signed"

    # Load the public key
    public_key = serialization.load_pem_public_key(public_key_pem, default_backend())

    try:
        # Verify the signature
        public_key.verify(
            signature,
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return "The signature is valid."
    except InvalidSignature:
        return "The signature is invalid."

if __name__ == '__main__':
    app.run(debug=True)
