from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from steganography.steganography import Steganography
from PIL import Image, ImageDraw
import random
import time
from io import BytesIO
from base64 import b64encode

def hide_random_bytes(input_string, fraction_to_hide=0.1):
    string_bytes = input_string.encode()
    bytes_to_hide = int(len(string_bytes) * fraction_to_hide)
    hide_indices = random.sample(range(len(string_bytes)), bytes_to_hide)
    hidden_string_bytes = bytearray(string_bytes)
    for i in hide_indices:
        hidden_string_bytes[i] = ord('*')  # Replace with '*'
    return bytes(hidden_string_bytes)

def string_to_image(input_string, image_size=(500, 500), font_size=20):
    image = Image.new('RGB', image_size, color=(73, 109, 137))
    d = ImageDraw.Draw(image)
    lines = "\n".join([input_string[i:i+image_size[0]//font_size] for i in range(0, len(input_string), image_size[0]//font_size)])
    d.text((10,10), lines, fill=(255,255,0))
    return image

def add_hidden_watermark(image, watermark_text):
    image.save("temp.png")
    Steganography.encode("temp.png", "image_with_hidden_watermark.png", watermark_text)
    return Image.open("image_with_hidden_watermark.png")

def encrypt_image_with_public_key(image, public_key):
    byte_arr = BytesIO()
    image.save(byte_arr, format='PNG')
    plaintext = byte_arr.getvalue()
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_image = cipher_rsa.encrypt(plaintext)
    return encrypted_image

input_string = "This is my personal data. Please handle it carefully."
key = RSA.generate(2048)
public_key = key.publickey()

hidden_string = hide_random_bytes(input_string, fraction_to_hide=0.1)
image = string_to_image(hidden_string.decode())
hidden_watermark = "Public key: {}\nTimestamp: {}".format(public_key.export_key().decode(), int(time.time()))
image_with_hidden_watermark = add_hidden_watermark(image, hidden_watermark)
image_with_hidden_watermark.save("watermarked_image.png")
encrypted_image = encrypt_image_with_public_key(image_with_hidden_watermark, public_key)

encrypted_image_b64 = b64encode(encrypted_image).decode()
print(encrypted_image_b64)
print(public_key.export_key().decode())
