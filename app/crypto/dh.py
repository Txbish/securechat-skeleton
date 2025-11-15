"""Classic DH helpers + Trunc16(SHA256(Ks)) derivation."""

import os
import hashlib
from typing import Tuple


def dh_params(bits: int = 2048) -> Tuple[int, int]:
    """
    Generate safe DH parameters (p, g).
    
    For this assignment, we use standard well-known DH parameters.
    In production, these would be generated and verified as safe primes.
    
    Args:
        bits: key size (2048 typical for modern security)
        
    Returns:
        (p, g) tuple: p is prime, g is generator
    """
    # Using RFC 3526 2048-bit MODP Group
    p = int(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
        "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374"
        "FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE"
        "386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF", 16
    )
    g = 2
    return p, g


def dh_private(bits: int = 256) -> int:
    """
    Generate a random DH private exponent.
    
    Args:
        bits: size of private exponent in bits
        
    Returns:
        random private exponent a or b
    """
    # Generate a random number with specified bit length
    return int.from_bytes(os.urandom(bits // 8), byteorder='big')


def dh_public(g: int, private: int, p: int) -> int:
    """
    Compute DH public value: A = g^a mod p (or B = g^b mod p).
    
    Args:
        g: generator
        private: private exponent (a or b)
        p: prime modulus
        
    Returns:
        public value (A or B)
    """
    return pow(g, private, p)


def dh_shared_secret(peer_public: int, private: int, p: int) -> int:
    """
    Compute shared secret: Ks = B^a mod p (or A^b mod p).
    
    Args:
        peer_public: peer's public value (A or B)
        private: own private exponent (a or b)
        p: prime modulus
        
    Returns:
        shared secret Ks
    """
    return pow(peer_public, private, p)


def derive_session_key(shared_secret: int) -> bytes:
    """
    Derive AES-128 session key from DH shared secret.
    
    K = Trunc16(SHA256(big-endian(Ks)))
    
    Args:
        shared_secret: DH shared secret Ks
        
    Returns:
        16-byte AES key
    """
    # Convert shared secret to big-endian bytes
    # Ensure we have enough bytes by computing the byte length needed
    byte_length = (shared_secret.bit_length() + 7) // 8
    ks_bytes = shared_secret.to_bytes(byte_length, byteorder='big')
    
    # Compute SHA-256 and truncate to 16 bytes
    digest = hashlib.sha256(ks_bytes).digest()
    return digest[:16]
