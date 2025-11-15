"""AES-128(ECB)+PKCS#7 helpers (use cryptography library)."""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
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
    
    # Apply PKCS#7 padding
    padder = padding.PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()
    
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
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
    
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove PKCS#7 padding
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext
