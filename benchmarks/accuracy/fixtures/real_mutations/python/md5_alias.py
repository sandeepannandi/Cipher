"""Semantics-preserving mutation of python-vuln-demo's weak_hash."""
import hashlib


def digest(payload: bytes) -> str:
    algorithm = hashlib.md5
    return algorithm(payload).hexdigest()
