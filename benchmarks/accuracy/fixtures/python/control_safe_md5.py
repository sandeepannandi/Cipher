import hashlib


def compute_digest(value: str) -> str:
    # Near-miss control: secure algorithm is used.
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
