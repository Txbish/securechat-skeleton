"""AES-128(ECB)+PKCS#7 helpers (use cryptography library)."""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """
    Encrypt plaintext using AES-128 in ECB mode with PKCS#7 padding.
    
    Args:
        key: 16-byte AES key
        plaintext: data to encrypt
        
    Returns:
        ciphertext (IV not needed for ECB)
    """
    if len(key) != 16:
        raise ValueError("AES key must be 16 bytes (128 bits)")
    
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # The encryptor handles PKCS#7 padding automatically
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext


def aes_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypt ciphertext using AES-128 in ECB mode with PKCS#7 padding.
    
    Args:
        key: 16-byte AES key
        ciphertext: encrypted data
        
    Returns:
        plaintext (PKCS#7 padding removed automatically)
    """
    if len(key) != 16:
        raise ValueError("AES key must be 16 bytes (128 bits)")
    
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # The decryptor handles PKCS#7 padding removal automatically
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext
