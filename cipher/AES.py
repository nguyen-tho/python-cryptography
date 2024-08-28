from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import binascii
def pad(text):
    # Pads the text to be a multiple of 8 bytes
    while len(text) % 16 != 0:
        text += ' '
    return text

def generate_aes_key(length=32):
    """
    Generate a random AES key of specified length.
    Default length is 32 bytes (256 bits).
    """
    if length not in [16, 24, 32]:
        raise ValueError("Invalid key length. Choose 16, 24, or 32 bytes.")
    return get_random_bytes(length)

def encrypt(plain_text, key):
    des = AES.new(key, AES.MODE_ECB)
    padded_text = pad(plain_text)
    encrypted_text = des.encrypt(padded_text.encode('utf-8'))
    return binascii.hexlify(encrypted_text).decode('utf-8')

def decrypt(encrypted_text, key):
    des = AES.new(key, AES.MODE_ECB)
    encrypted_text_bytes = binascii.unhexlify(encrypted_text)
    decrypted_text = des.decrypt(encrypted_text_bytes).decode('utf-8')
    return decrypted_text.rstrip()  # Remove padding spaces



# Example usage
"""
key = random_key(24)  # AES key must be 16, 24, 32 bytes long
plain_text = "Hello World"

print(f"Original text: {plain_text}")
print(f"Key: {binascii.hexlify(key).decode('utf-8')}")

encrypted_text = encrypt(plain_text, key)
print(f"Encrypted text: {encrypted_text}")

decrypted_text = decrypt(encrypted_text, key)
print(f"Decrypted text: {decrypted_text}")
"""