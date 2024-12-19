import rsa
import binascii
def generate_key(len_key):
    public_key, private_key = rsa.newkeys(len_key)
    return public_key, private_key

def encrypt(message, public_key):
    byte_message = message.encode("utf-8")
    encryption = rsa.encrypt(byte_message, public_key)
    return binascii.hexlify(encryption).decode('utf-8')

def decrypt(cipher_message, private_key):
    cipher_message_byte =  binascii.unhexlify(cipher_message)
    decrypttion_bytes = rsa.decrypt(cipher_message_byte, private_key)
    decryption = decrypttion_bytes.decode("utf-8")
    return decryption

#example
"""
public_key, private_key = generate_key(512)
print(public_key)
print(private_key)
message = "Hello, World!"
print(message)
encrypted_message = encrypt(message, public_key)
print(encrypted_message)
decrypted_message = decrypt(encrypted_message, private_key)
print(decrypted_message)
"""