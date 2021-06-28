from cryptography.fernet import Fernet as fn

test_key = fn.generate_key()
print(test_key)
file = open('test_key.key', 'wb')
file.write(test_key)
file.close()

from cryptography.fernet import Fernet as ft

message = input("\n Set your message: \n").encode()

file = open('test_key.key', 'rb')
key = file.read()

f = ft(key)
encrypted_message = f.encrypt(message)
print("Your encrypted message: \n", encrypted_message)
file.close()


from cryptography.fernet import Fernet as ft

encypted_message = input("\n Set your encrypted message: \n").encode()

file = open('test_key.key', 'rb')
key = file.read()
f = ft(key)
decrypted_message = f.decrypt(encypted_message)
print("Your decrypted message: \n", decrypted_message)
file.close()