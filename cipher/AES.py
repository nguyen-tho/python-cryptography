from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

def generate_aes_key(length=32):
    """
    Generate a random AES key of specified length.
    Default length is 32 bytes (256 bits).
    """
    if length not in [16, 24, 32]:
        raise ValueError("Invalid key length. Choose 16, 24, or 32 bytes.")
    return get_random_bytes(length)

def encrypt_aes(key, plaintext):
    """
    Encrypt plaintext using AES algorithm with the given key.
    """
    # Create a new AES cipher object
    cipher = AES.new(key, AES.MODE_GCM)
    # Encrypt the plaintext
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    # Return the nonce, ciphertext, and tag, encoded in base64
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')

def decrypt_aes(key, ciphertext_base64):
    """
    Decrypt ciphertext using AES algorithm with the given key.
    """
    # Decode the base64 encoded ciphertext
    ciphertext = base64.b64decode(ciphertext_base64)
    # Extract the nonce, tag, and ciphertext
    nonce = ciphertext[:16]
    tag = ciphertext[16:32]
    ciphertext = ciphertext[32:]
    # Create a new AES cipher object
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    # Decrypt the ciphertext
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode('utf-8')