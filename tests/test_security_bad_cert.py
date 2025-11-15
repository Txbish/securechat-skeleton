#!/usr/bin/env python3
"""
Security Test: BAD_CERT
Tests that server and client properly reject invalid certificates.

Test Cases:
1. Self-signed certificate (not signed by CA) -> BAD_CERT
2. Expired certificate -> BAD_CERT
3. Certificate with wrong CN -> BAD_CERT
4. Certificate not yet valid (future notBefore) -> BAD_CERT
"""

import sys
import os
import tempfile
import json
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from app.crypto import pki
from app.common import protocol, utils
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


def generate_self_signed_cert(cn="test.local"):
    """Generate a self-signed certificate (not trusted by CA)."""
    print(f"\n[STEP] Generating self-signed cert with CN={cn}...")
    
    # Generate RSA key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Build self-signed cert
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Punjab"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Lahore"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST-NU"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])
    
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(cn),
            ]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256(), default_backend())
    )
    
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()
    
    print(f"  ✓ Generated self-signed cert")
    return cert_pem, key_pem


def generate_expired_cert():
    """Generate a certificate that is already expired."""
    print(f"\n[STEP] Generating expired certificate...")
    
    # Generate RSA key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Build expired cert (valid from 2 years ago to 1 year ago)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Punjab"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Lahore"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST-NU"),
        x509.NameAttribute(NameOID.COMMON_NAME, "expired.local"),
    ])
    
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow() - timedelta(days=365*2))
        .not_valid_after(datetime.utcnow() - timedelta(days=365))  # Expired 1 year ago
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("expired.local"),
            ]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256(), default_backend())
    )
    
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()
    
    print(f"  ✓ Generated expired cert (expired 1 year ago)")
    return cert_pem, key_pem


def generate_future_cert():
    """Generate a certificate that is not yet valid."""
    print(f"\n[STEP] Generating future (not-yet-valid) certificate...")
    
    # Generate RSA key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Build cert valid in the future
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Punjab"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Lahore"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST-NU"),
        x509.NameAttribute(NameOID.COMMON_NAME, "future.local"),
    ])
    
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow() + timedelta(days=365))  # Valid 1 year from now
        .not_valid_after(datetime.utcnow() + timedelta(days=365*2))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("future.local"),
            ]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256(), default_backend())
    )
    
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()
    
    print(f"  ✓ Generated future cert (valid 1 year from now)")
    return cert_pem, key_pem


def test_self_signed_cert_rejection():
    """Test 1: Self-signed certificate should be rejected."""
    print("\n" + "=" * 70)
    print("TEST 1: Self-Signed Certificate Rejection")
    print("=" * 70)
    
    try:
        # Generate self-signed cert
        bad_cert_pem, _ = generate_self_signed_cert("malicious.local")
        
        # Load CA cert
        with open('certs/ca_cert.pem', 'r') as f:
            ca_cert_pem = f.read()
        
        # Try to validate self-signed cert against CA
        print("\n[TEST] Validating self-signed cert against CA...")
        try:
            pki.validate_certificate(bad_cert_pem, ca_cert_pem, "malicious.local")
            print("  ✗ FAILED: Self-signed cert was accepted (should be rejected)")
            return False
        except pki.CertValidationError as e:
            print(f"  ✓ PASSED: Self-signed cert rejected with error: {e}")
            return True
            
    except Exception as e:
        print(f"  ✗ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_expired_cert_rejection():
    """Test 2: Expired certificate should be rejected."""
    print("\n" + "=" * 70)
    print("TEST 2: Expired Certificate Rejection")
    print("=" * 70)
    
    try:
        # Generate expired cert
        expired_cert_pem, _ = generate_expired_cert()
        
        # Load CA cert
        with open('certs/ca_cert.pem', 'r') as f:
            ca_cert_pem = f.read()
        
        # Try to validate expired cert
        print("\n[TEST] Validating expired cert...")
        try:
            pki.validate_certificate(expired_cert_pem, ca_cert_pem, "expired.local")
            print("  ✗ FAILED: Expired cert was accepted (should be rejected)")
            return False
        except pki.CertValidationError as e:
            print(f"  ✓ PASSED: Expired cert rejected with error: {e}")
            return True
            
    except Exception as e:
        print(f"  ✗ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_future_cert_rejection():
    """Test 3: Certificate not yet valid should be rejected."""
    print("\n" + "=" * 70)
    print("TEST 3: Future Certificate (Not-Yet-Valid) Rejection")
    print("=" * 70)
    
    try:
        # Generate future cert
        future_cert_pem, _ = generate_future_cert()
        
        # Load CA cert
        with open('certs/ca_cert.pem', 'r') as f:
            ca_cert_pem = f.read()
        
        # Try to validate future cert
        print("\n[TEST] Validating future cert...")
        try:
            pki.validate_certificate(future_cert_pem, ca_cert_pem, "future.local")
            print("  ✗ FAILED: Future cert was accepted (should be rejected)")
            return False
        except pki.CertValidationError as e:
            print(f"  ✓ PASSED: Future cert rejected with error: {e}")
            return True
            
    except Exception as e:
        print(f"  ✗ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_cn_mismatch():
    """Test 4: Certificate CN mismatch should be rejected."""
    print("\n" + "=" * 70)
    print("TEST 4: Certificate CN Mismatch Rejection")
    print("=" * 70)
    
    try:
        # Load valid server cert
        with open('certs/server_cert.pem', 'r') as f:
            server_cert_pem = f.read()
        
        # Load CA cert
        with open('certs/ca_cert.pem', 'r') as f:
            ca_cert_pem = f.read()
        
        # Try to validate with wrong expected CN
        print("\n[TEST] Validating cert with wrong CN expectation...")
        print(f"  Server cert CN: server.local")
        print(f"  Expected CN: wrong.local")
        
        try:
            pki.validate_certificate(server_cert_pem, ca_cert_pem, "wrong.local")
            print("  ✗ FAILED: CN mismatch was accepted (should be rejected)")
            return False
        except pki.CertValidationError as e:
            print(f"  ✓ PASSED: CN mismatch rejected with error: {e}")
            return True
            
    except Exception as e:
        print(f"  ✗ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_valid_cert_acceptance():
    """Test 5: Valid certificate should be accepted."""
    print("\n" + "=" * 70)
    print("TEST 5: Valid Certificate Acceptance")
    print("=" * 70)
    
    try:
        # Load valid server cert
        with open('certs/server_cert.pem', 'r') as f:
            server_cert_pem = f.read()
        
        # Load CA cert
        with open('certs/ca_cert.pem', 'r') as f:
            ca_cert_pem = f.read()
        
        # Validate with correct CN
        print("\n[TEST] Validating valid server cert with correct CN...")
        try:
            pki.validate_certificate(server_cert_pem, ca_cert_pem, "server.local")
            print("  ✓ PASSED: Valid cert accepted")
            return True
        except pki.CertValidationError as e:
            print(f"  ✗ FAILED: Valid cert rejected with error: {e}")
            return False
            
    except Exception as e:
        print(f"  ✗ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all BAD_CERT security tests."""
    print("\n" + "=" * 70)
    print("SECURITY TEST SUITE: BAD_CERT (Certificate Validation)")
    print("=" * 70)
    
    tests = [
        ("Self-Signed Cert", test_self_signed_cert_rejection),
        ("Expired Cert", test_expired_cert_rejection),
        ("Future Cert", test_future_cert_rejection),
        ("CN Mismatch", test_cn_mismatch),
        ("Valid Cert", test_valid_cert_acceptance),
    ]
    
    results = {}
    for test_name, test_func in tests:
        try:
            results[test_name] = test_func()
        except Exception as e:
            print(f"\n✗ Test '{test_name}' crashed: {e}")
            import traceback
            traceback.print_exc()
            results[test_name] = False
    
    # Summary
    print("\n" + "=" * 70)
    print("TEST RESULTS SUMMARY")
    print("=" * 70)
    
    for test_name, passed in results.items():
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"  {status}: {test_name}")
    
    passed_count = sum(1 for p in results.values() if p)
    total_count = len(results)
    
    print(f"\nTotal: {passed_count}/{total_count} tests passed")
    
    if passed_count == total_count:
        print("\n✅ ALL BAD_CERT TESTS PASSED!")
        return True
    else:
        print(f"\n❌ {total_count - passed_count} test(s) failed")
        return False


if __name__ == '__main__':
    try:
        success = main()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n❌ FATAL ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
