from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
import binascii

def pad(text):
    # Pads the text to be a multiple of 8 bytes
    while len(text) % 8 != 0:
        text += ' '
    return text

def encrypt(plain_text, key):
    des = DES.new(key, DES.MODE_ECB)
    padded_text = pad(plain_text)
    encrypted_text = des.encrypt(padded_text.encode('utf-8'))
    return binascii.hexlify(encrypted_text).decode('utf-8')

def decrypt(encrypted_text, key):
    des = DES.new(key, DES.MODE_ECB)
    encrypted_text_bytes = binascii.unhexlify(encrypted_text)
    decrypted_text = des.decrypt(encrypted_text_bytes).decode('utf-8')
    return decrypted_text.rstrip()  # Remove padding spaces

def random_key(byte_len=8):
    return get_random_bytes(byte_len)

# Example usage
"""
key = random_key(8)  # DES key must be 8 bytes long
plain_text = "Hello World"

print(f"Original text: {plain_text}")
print(f"Key: {binascii.hexlify(key).decode('utf-8')}")

encrypted_text = encrypt(plain_text, key)
print(f"Encrypted text: {encrypted_text}")

decrypted_text = decrypt(encrypted_text, key)
print(f"Decrypted text: {decrypted_text}")
"""