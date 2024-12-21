import hashlib

def md5_hash(data):
    """
    Calculates the MD5 hash of the given data.

    Args:
        data: The data to be hashed (can be a string or bytes).

    Returns:
        The MD5 hash of the data as a hexadecimal string.
    """

    if isinstance(data, str):
        data = data.encode('utf-8')  # Encode string to bytes if necessary

    hash_object = hashlib.md5(data)
    hex_digest = hash_object.hexdigest()

    return hex_digest
"""
# Example usage:
data_to_hash = "Hello, world!"
md5_hash_value = md5_hash(data_to_hash)
print("MD5 Hash:", md5_hash_value)
"""