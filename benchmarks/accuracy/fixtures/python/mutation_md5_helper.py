import hashlib


def compute_digest(value: str) -> str:
    # Mutation variant that still uses an insecure MD5 helper.
    return hashlib.md5(value.encode("utf-8")).hexdigest()
