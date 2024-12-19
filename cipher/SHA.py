import hashlib
def hash_function(data, algo='sha256'):
    if algo == 'sha256':
        return hashlib.sha256(data.encode('utf-8')).hexdigest()
    elif algo == 'sha512':
        return hashlib.sha512(data.encode('utf-8')).hexdigest()
    elif algo == 'sha224':
        return hashlib.sha224(data.encode('utf-8')).hexdigest()
    elif algo == 'sha1':
        return hashlib.sha1(data.encode('utf-8')).hexdigest()
    elif algo == 'sha3_256':
        return hashlib.sha3_256(data.encode('utf-8')).hexdigest()
    else:
        return "Invalid algorithm"