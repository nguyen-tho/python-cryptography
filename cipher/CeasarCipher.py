def encrypt (text, s):
    result = ""

    for i in range(len(text)):
        char= text[i]
        if (char.isupper()):
            result+=chr((ord(char) + s-65) % 26 + 65) 
  
 
        else: 
            result += chr((ord(char) + s - 97) % 26 + 97) 
  
    return result 
   
def decrypt(text, shift):
    """Decrypts a text encrypted with the Caesar cipher with the given shift value.

    Args:
        text: The encrypted text to decrypt (str).
        shift: The number of positions used to shift letters during encryption (int).

    Returns:
        The decrypted text (str).
    """

    return encrypt(text, -shift)  # Decrypt by shifting back by the negative shift

text = input("\nSet your text\n")
shift = int(input("\nSet your shift\n"))

print("Text : " + text)
print("Shift: " + str(shift))

print("Cipher: " + encrypt(text, shift))
print("Decrypted: " + decrypt(text, shift))
