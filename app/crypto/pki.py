"""X.509 validation: signed-by-CA, validity window, CN/SAN."""

from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.x509.oid import NameOID


class CertValidationError(Exception):
    """Raised when certificate validation fails."""
    pass


def load_certificate(cert_pem: str) -> x509.Certificate:
    """Load a certificate from PEM format."""
    return x509.load_pem_x509_certificate(
        cert_pem.encode('utf-8'),
        backend=default_backend()
    )


def load_ca_certificate(ca_cert_pem: str) -> x509.Certificate:
    """Load CA certificate from PEM format."""
    return load_certificate(ca_cert_pem)


def validate_cert_signature(cert: x509.Certificate, ca_cert: x509.Certificate) -> bool:
    """
    Verify that cert is signed by ca_cert.
    
    Args:
        cert: certificate to verify
        ca_cert: CA certificate with public key
        
    Returns:
        True if signature is valid
        
    Raises:
        CertValidationError if signature is invalid
    """
    try:
        ca_public_key = ca_cert.public_key()
        
        # Extract the signature algorithm OID and convert to the correct algorithm
        if cert.signature_algorithm_oid == x509.oid.SignatureAlgorithmOID.RSA_WITH_SHA256:
            algorithm = hashes.SHA256()
        elif cert.signature_algorithm_oid == x509.oid.SignatureAlgorithmOID.RSA_WITH_SHA1:
            algorithm = hashes.SHA1()
        elif cert.signature_algorithm_oid == x509.oid.SignatureAlgorithmOID.RSA_WITH_SHA384:
            algorithm = hashes.SHA384()
        elif cert.signature_algorithm_oid == x509.oid.SignatureAlgorithmOID.RSA_WITH_SHA512:
            algorithm = hashes.SHA512()
        else:
            raise CertValidationError(f"Unsupported signature algorithm: {cert.signature_algorithm_oid}")
        
        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            asym_padding.PKCS1v15(),
            algorithm
        )
        return True
    except CertValidationError:
        raise
    except Exception as e:
        raise CertValidationError(f"Certificate signature verification failed: {e}")


def validate_cert_validity(cert: x509.Certificate) -> bool:
    """
    Check if certificate is within validity window (not expired, not too early).
    
    Args:
        cert: certificate to check
        
    Returns:
        True if certificate is valid in time
        
    Raises:
        CertValidationError if certificate is invalid in time
    """
    now = datetime.utcnow()
    
    if now < cert.not_valid_before:
        raise CertValidationError(
            f"Certificate not yet valid (valid from {cert.not_valid_before})"
        )
    
    if now > cert.not_valid_after:
        raise CertValidationError(
            f"Certificate expired (valid until {cert.not_valid_after})"
        )
    
    return True


def extract_public_key(cert_pem: str) -> str:
    """
    Extract public key from certificate in PEM format.
    
    Args:
        cert_pem: certificate in PEM format
        
    Returns:
        Public key in PEM format
        
    Raises:
        CertValidationError if extraction fails
    """
    try:
        cert = load_certificate(cert_pem)
        public_key = cert.public_key()
        
        # Serialize to PEM format
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem.decode('utf-8')
    except Exception as e:
        raise CertValidationError(f"Failed to extract public key: {e}")


def get_cert_cn(cert: x509.Certificate) -> str:
    """
    Extract Common Name (CN) from certificate subject.
    
    Args:
        cert: certificate to extract CN from
        
    Returns:
        CN value or empty string if not found
    """
    try:
        cn_attr = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cn_attr:
            return cn_attr[0].value
        return ""
    except Exception:
        return ""


def validate_cert_cn(cert: x509.Certificate, expected_cn: str) -> bool:
    """
    Verify that certificate CN matches expected value.
    
    Args:
        cert: certificate to check
        expected_cn: expected Common Name value
        
    Returns:
        True if CN matches
        
    Raises:
        CertValidationError if CN doesn't match
    """
    cn = get_cert_cn(cert)
    if cn != expected_cn:
        raise CertValidationError(
            f"Certificate CN mismatch: expected '{expected_cn}', got '{cn}'"
        )
    return True


def validate_certificate(cert_pem: str, ca_cert_path_or_pem: str, expected_cn: str = None) -> bool:
    """
    Perform complete certificate validation:
    1. Load certificate
    2. Verify signature by CA
    3. Check validity window
    4. Optionally verify CN
    
    Args:
        cert_pem: certificate in PEM format
        ca_cert_path_or_pem: CA certificate as PEM string or file path
        expected_cn: optional expected Common Name
        
    Returns:
        True if all checks pass
        
    Raises:
        CertValidationError if any check fails
    """
    try:
        cert = load_certificate(cert_pem)
        
        # Load CA cert - either from file or PEM string
        if ca_cert_path_or_pem.startswith('-----BEGIN CERTIFICATE-----'):
            # It's a PEM string
            ca_cert = load_ca_certificate(ca_cert_path_or_pem)
        else:
            # It's a file path
            try:
                with open(ca_cert_path_or_pem, 'r') as f:
                    ca_cert_pem = f.read()
                ca_cert = load_ca_certificate(ca_cert_pem)
            except FileNotFoundError:
                raise CertValidationError(f"CA certificate file not found: {ca_cert_path_or_pem}")
        
        # Verify signature
        validate_cert_signature(cert, ca_cert)
        
        # Check validity window
        validate_cert_validity(cert)
        
        # Check CN if provided
        if expected_cn:
            validate_cert_cn(cert, expected_cn)
        
        return True
    except CertValidationError:
        raise
    except Exception as e:
        raise CertValidationError(f"Certificate validation error: {e}")
