"""RSA PKCS#1 v1.5 SHA-256 sign/verify."""

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend


def rsa_sign(private_key_pem: str, data: bytes) -> bytes:
    """
    Sign data using RSA private key with PKCS#1 v1.5 padding and SHA-256.
    
    Args:
        private_key_pem: RSA private key in PEM format
        data: data to sign
        
    Returns:
        signature bytes
    """
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode('utf-8'),
        password=None,
        backend=default_backend()
    )
    
    signature = private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature


def rsa_verify(public_cert_pem: str, data: bytes, signature: bytes) -> bool:
    """
    Verify RSA signature using public key from certificate.
    
    Args:
        public_cert_pem: X.509 certificate in PEM format (contains public key)
        data: original data
        signature: signature to verify
        
    Returns:
        True if signature is valid, False otherwise
    """
    from cryptography import x509
    
    try:
        cert = x509.load_pem_x509_certificate(
            public_cert_pem.encode('utf-8'),
            backend=default_backend()
        )
        public_key = cert.public_key()
        
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


def rsa_generate_keypair(bits: int = 2048) -> tuple:
    """
    Generate an RSA keypair.
    
    Args:
        bits: key size in bits (default 2048)
        
    Returns:
        (private_key_pem, public_key_pem) tuple as PEM strings
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=bits,
        backend=default_backend()
    )
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    return private_pem, public_pem
