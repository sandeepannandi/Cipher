import hashlib

def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()
