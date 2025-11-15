"""Helper signatures: now_ms, b64e, b64d, sha256_hex."""

import base64
import hashlib
import time
import hmac
from typing import Union


def now_ms() -> int:
    """Get current time in milliseconds since epoch."""
    return int(time.time() * 1000)


def b64e(b: bytes) -> str:
    """Encode bytes to base64 string."""
    return base64.b64encode(b).decode('ascii')


def b64d(s: str) -> bytes:
    """Decode base64 string to bytes."""
    return base64.b64decode(s.encode('ascii') if isinstance(s, str) else s)


def sha256_hex(data: Union[bytes, str]) -> str:
    """Compute SHA-256 hash and return as hex string."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).hexdigest()


def sha256_bytes(data: Union[bytes, str]) -> bytes:
    """Compute SHA-256 hash and return as bytes."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).digest()


def constant_time_compare(a: Union[bytes, str], b: Union[bytes, str]) -> bool:
    """Constant-time comparison to prevent timing attacks."""
    if isinstance(a, str):
        a = a.encode('utf-8')
    if isinstance(b, str):
        b = b.encode('utf-8')
    return hmac.compare_digest(a, b)


def cert_fingerprint(cert_pem: str) -> str:
    """Compute SHA-256 fingerprint of a certificate in PEM format."""
    # Remove PEM headers/footers and whitespace
    cert_data = cert_pem.replace('-----BEGIN CERTIFICATE-----', '')
    cert_data = cert_data.replace('-----END CERTIFICATE-----', '')
    cert_data = cert_data.replace('\n', '')
    cert_bytes = b64d(cert_data)
    return sha256_hex(cert_bytes)
