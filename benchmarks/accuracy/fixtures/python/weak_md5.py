import hashlib

def cache_key(value):
    return hashlib.md5(value.encode()).hexdigest()
