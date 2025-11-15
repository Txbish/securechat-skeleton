"""Issue server/client certificate signed by Root CA."""

import os
import sys
import argparse
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


def issue_certificate(
    ca_cert_path: str,
    ca_key_path: str,
    common_name: str,
    output_cert_path: str,
    output_key_path: str,
    valid_days: int = 365
):
    """
    Issue a certificate signed by the Root CA.
    
    Args:
        ca_cert_path: path to CA certificate (PEM)
        ca_key_path: path to CA private key (PEM)
        common_name: Common Name for entity (e.g., "server.local")
        output_cert_path: output path for entity certificate (PEM)
        output_key_path: output path for entity private key (PEM)
        valid_days: validity period in days
    """
    # Load CA certificate and key
    print("[*] Loading CA certificate and key...")
    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read(), backend=default_backend())
    
    with open(ca_key_path, "rb") as f:
        ca_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    
    # Generate entity's private key
    print("[*] Generating 2048-bit RSA private key...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Create certificate subject
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Islamabad"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Islamabad"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"FAST-NUCES"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    
    # Use CA subject as issuer
    issuer = ca_cert.issuer
    
    # Build certificate
    print(f"[*] Creating certificate for CN={common_name}...")
    cert_builder = x509.CertificateBuilder().subject_name(
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
    )
    
    # Add extensions
    cert_builder = cert_builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            content_commitment=True,
            key_cert_sign=False,
            crl_sign=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(common_name),
        ]),
        critical=False,
    )
    
    # Sign with CA key
    cert = cert_builder.sign(
        ca_key,
        hashes.SHA256(),
        backend=default_backend()
    )
    
    # Create output directory if needed
    os.makedirs(os.path.dirname(output_cert_path) if os.path.dirname(output_cert_path) else ".", exist_ok=True)
    os.makedirs(os.path.dirname(output_key_path) if os.path.dirname(output_key_path) else ".", exist_ok=True)
    
    # Write certificate
    print(f"[*] Writing certificate to {output_cert_path}...")
    with open(output_cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    # Write private key
    print(f"[*] Writing private key to {output_key_path}...")
    with open(output_key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Restrict key file permissions
    os.chmod(output_key_path, 0o600)
    
    print("[+] Certificate issued successfully!")
    print(f"    Certificate: {output_cert_path}")
    print(f"    Private Key: {output_key_path}")
    print(f"    Valid for {valid_days} days")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Issue a certificate signed by Root CA"
    )
    parser.add_argument(
        "--ca-cert",
        default="certs/ca_cert.pem",
        help="CA certificate path (default: certs/ca_cert.pem)"
    )
    parser.add_argument(
        "--ca-key",
        default="certs/ca_key.pem",
        help="CA private key path (default: certs/ca_key.pem)"
    )
    parser.add_argument(
        "--cn",
        required=True,
        help="Common Name for certificate (e.g., server.local, client.local)"
    )
    parser.add_argument(
        "--out",
        default="certs/entity",
        help="Output path prefix (cert: {out}_cert.pem, key: {out}_key.pem)"
    )
    parser.add_argument(
        "--days",
        type=int,
        default=365,
        help="Validity period in days (default: 365)"
    )
    
    args = parser.parse_args()
    
    cert_path = f"{args.out}_cert.pem"
    key_path = f"{args.out}_key.pem"
    
    try:
        issue_certificate(
            args.ca_cert,
            args.ca_key,
            args.cn,
            cert_path,
            key_path,
            args.days
        )
    except FileNotFoundError as e:
        print(f"[-] File not found: {e}", file=sys.stderr)
        print("[-] Make sure CA certificate and key exist. Run gen_ca.py first.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error: {e}", file=sys.stderr)
        sys.exit(1)
