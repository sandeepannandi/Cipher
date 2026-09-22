"""Paired safe control for md5_alias.py."""
import hashlib


def digest(payload: bytes) -> str:
    algorithm = hashlib.sha256
    return algorithm(payload).hexdigest()
