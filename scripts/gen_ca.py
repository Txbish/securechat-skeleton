"""Create Root CA (RSA + self-signed X.509) using cryptography library."""

import os
import sys
import argparse
from pathlib import Path
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


def generate_ca(ca_name: str, cert_path: str, key_path: str, valid_days: int = 3650):
    """
    Generate a self-signed Root CA certificate and private key.
    
    Args:
        ca_name: Common Name for CA (e.g., "FAST-NU Root CA")
        cert_path: output path for certificate PEM
        key_path: output path for private key PEM
        valid_days: validity period in days (default 10 years)
    """
    # Generate RSA private key (2048 bits)
    print("[*] Generating 2048-bit RSA private key...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Create certificate subject and issuer (self-signed)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Islamabad"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Islamabad"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"FAST-NUCES"),
        x509.NameAttribute(NameOID.COMMON_NAME, ca_name),
    ])
    
    # Create certificate
    print("[*] Creating self-signed certificate...")
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=valid_days)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_cert_sign=True,
            crl_sign=True,
            key_encipherment=False,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    ).sign(
        private_key,
        hashes.SHA256(),
        backend=default_backend()
    )
    
    # Create output directory if needed
    os.makedirs(os.path.dirname(cert_path) if os.path.dirname(cert_path) else ".", exist_ok=True)
    os.makedirs(os.path.dirname(key_path) if os.path.dirname(key_path) else ".", exist_ok=True)
    
    # Write certificate
    print(f"[*] Writing certificate to {cert_path}...")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    # Write private key (no password)
    print(f"[*] Writing private key to {key_path}...")
    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Restrict key file permissions
    os.chmod(key_path, 0o600)
    
    print("[+] Root CA created successfully!")
    print(f"    Certificate: {cert_path}")
    print(f"    Private Key: {key_path}")
    print(f"    Valid for {valid_days} days")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate a self-signed Root CA certificate"
    )
    parser.add_argument(
        "--name",
        default="FAST-NU Root CA",
        help="Common Name for CA (default: FAST-NU Root CA)"
    )
    parser.add_argument(
        "--cert",
        default="certs/ca_cert.pem",
        help="Output path for CA certificate (default: certs/ca_cert.pem)"
    )
    parser.add_argument(
        "--key",
        default="certs/ca_key.pem",
        help="Output path for CA private key (default: certs/ca_key.pem)"
    )
    parser.add_argument(
        "--days",
        type=int,
        default=3650,
        help="Validity period in days (default: 3650 = 10 years)"
    )
    
    args = parser.parse_args()
    
    try:
        generate_ca(args.name, args.cert, args.key, args.days)
    except Exception as e:
        print(f"[-] Error: {e}", file=sys.stderr)
        sys.exit(1)
