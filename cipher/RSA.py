import rsa

def generate_key(len_key):
    public_key, private_key = rsa.newkeys(len_key)
    return public_key, private_key

def encrypt(message, public_key):
    byte_message = message.encode("utf-8")
    encryption = rsa.encrypt(byte_message, public_key)
    return encryption

def decrypt(cipher_message, private_key):
    decrypttion_bytes = rsa.decrypt(cipher_message, private_key)
    decryption = decrypttion_bytes.decode("utf-8")
    return decryption
    
