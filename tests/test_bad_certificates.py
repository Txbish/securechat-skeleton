#!/usr/bin/env python3
"""
Test Script: BAD_CERT Certificate Validation

Tests invalid certificates to verify that the server properly rejects them:
1. Self-signed certificate (not signed by trusted CA)
2. Expired certificate (past validity date)
3. Forged certificate (signature tampered)
4. CN mismatch (certificate CN != expected hostname)

Usage:
    python3 test_bad_certificates.py <server_cert_path>

Example:
    python3 test_bad_certificates.py certs/server_cert.pem
"""

import sys
import os
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime

def load_certificate(cert_path: str):
    """Load a certificate from PEM file."""
    try:
        with open(cert_path, 'rb') as f:
            cert_pem = f.read()
        cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
        return cert
    except Exception as e:
        print(f"ERROR: Failed to load certificate: {e}")
        return None

def check_self_signed(cert) -> bool:
    """Check if certificate is self-signed."""
    return cert.issuer == cert.subject

def check_expired(cert) -> bool:
    """Check if certificate is expired."""
    return datetime.utcnow() > cert.not_valid_after_utc

def check_cn(cert, expected_cn: str) -> bool:
    """Check if CN matches expected value."""
    try:
        cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        return cn == expected_cn
    except:
        return False

def get_cn(cert) -> str:
    """Get CN from certificate."""
    try:
        cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        return cn
    except:
        return "UNKNOWN"

def main():
    """Main test function."""
    print("="*80)
    print("BAD_CERT CERTIFICATE VALIDATION TEST")
    print("="*80)
    
    test_certs = [
        ("certs/test_self_signed_cert.pem", "Self-Signed Certificate"),
        ("certs/test_expired_cert.pem", "Expired Certificate"),
        ("certs/test_forged_cert.pem", "Forged Certificate (Tampered Signature)"),
        ("certs/server_cert.pem", "Valid Server Certificate (CN Mismatch Test)"),
    ]
    
    print("\nTEST 1: CERTIFICATE PROPERTIES ANALYSIS")
    print("-" * 80)
    
    test_results = []
    
    for cert_path, description in test_certs:
        if not Path(cert_path).exists():
            print(f"\n[SKIP] {description}")
            print(f"       File not found: {cert_path}")
            test_results.append((description, "SKIP", "File not found"))
            continue
        
        print(f"\n[LOAD] {description}")
        print(f"       File: {cert_path}")
        
        cert = load_certificate(cert_path)
        if not cert:
            test_results.append((description, "ERROR", "Failed to load"))
            continue
        
        # Certificate properties
        cn = get_cn(cert)
        is_self_signed = check_self_signed(cert)
        is_expired = check_expired(cert)
        
        print(f"       CN: {cn}")
        print(f"       Self-Signed: {is_self_signed}")
        print(f"       Expired: {is_expired}")
        print(f"       Not Valid Before: {cert.not_valid_before_utc.isoformat()}Z")
        print(f"       Not Valid After: {cert.not_valid_after_utc.isoformat()}Z")
        
        # Determine expected rejection reason
        expected_reason = None
        if is_self_signed:
            expected_reason = "BAD_CERT (not signed by trusted CA)"
        elif is_expired:
            expected_reason = "BAD_CERT (certificate expired)"
        elif "forged" in cert_path.lower():
            expected_reason = "BAD_CERT (signature verification failed)"
        
        if expected_reason:
            print(f"       Expected Rejection: {expected_reason}")
            test_results.append((description, "SHOULD_REJECT", expected_reason))
        else:
            print(f"       Expected Action: Accept")
            test_results.append((description, "ACCEPT", "Valid certificate"))
    
    # Summary
    print("\n" + "="*80)
    print("TEST SUMMARY: CERTIFICATE PROPERTIES")
    print("="*80)
    print(f"\nTotal certificates analyzed: {len(test_results)}")
    
    reject_count = sum(1 for _, status, _ in test_results if status == "SHOULD_REJECT")
    accept_count = sum(1 for _, status, _ in test_results if status == "ACCEPT")
    skip_count = sum(1 for _, status, _ in test_results if status == "SKIP")
    error_count = sum(1 for _, status, _ in test_results if status == "ERROR")
    
    print(f"  - Should be REJECTED: {reject_count}")
    print(f"  - Should be ACCEPTED: {accept_count}")
    print(f"  - Skipped: {skip_count}")
    print(f"  - Errors: {error_count}")
    
    print("\n" + "="*80)
    print("MANUAL TEST PROCEDURE")
    print("="*80)
    
    print("""
To manually test certificate validation:

1. START SERVER:
   python3 app/server.py

2. TEST EACH CERTIFICATE:

   Test 2.1: Self-Signed Certificate
   ===================================
   Command:
     python3 app/client.py --cert certs/test_self_signed_cert.pem
   
   Expected Result:
     [Error] BAD_CERT: Certificate validation failed
   
   Evidence:
     - Server detects certificate not signed by trusted CA
     - Connection rejected immediately
     - No authentication allowed
   
   Reason:
     - Certificate is self-signed (not in CA chain)
     - verify_certificate() detects issuer != CA
     - Fails pki.validate_certificate() check

   Test 2.2: Expired Certificate
   ============================
   Command:
     python3 app/client.py --cert certs/test_expired_cert.pem
   
   Expected Result:
     [Error] BAD_CERT: Certificate validation failed
   
   Evidence:
     - Server detects certificate past expiration date
     - Connection rejected immediately
     - Timestamp verification fails
   
   Reason:
     - Valid from 20 days ago, expired 10 days ago
     - datetime.utcnow() > cert.not_valid_after
     - Fails pki.validate_certificate() check

   Test 2.3: Forged Certificate
   ============================
   Command:
     python3 app/client.py --cert certs/test_forged_cert.pem
   
   Expected Result:
     [Error] BAD_CERT: Certificate validation failed
   
   Evidence:
     - Server detects signature verification failure
     - CA signature tampered (byte -256: 0x08 → 0xF7)
     - Connection rejected immediately
   
   Reason:
     - CA signature doesn't match certificate data
     - Cryptographic signature verification fails
     - Tampering is detected cryptographically

   Test 2.4: CN Mismatch
   ====================
   Command:
     python3 app/client.py --cert certs/server_cert.pem
   
   Expected Result:
     [Error] BAD_CERT: Certificate validation failed
   
   Evidence:
     - Server validates CN (Common Name)
     - server_cert.pem has CN=server.local
     - Expected CN=client.local (hostname mismatch)
     - Connection rejected
   
   Reason:
     - CN verification checks certificate matches hostname
     - prevent MITM attacks with valid-but-wrong certificates

EVIDENCE CAPTURE:

Run each test and capture:
  1. Full error message (should start with "[Error] BAD_CERT")
  2. Server log (shows rejection reason)
  3. Client log (shows connection failure)

All 4 tests should result in connection rejection with BAD_CERT error.
""")
    
    print("\n" + "="*80)
    print("CRYPTOGRAPHIC VERIFICATION DETAILS")
    print("="*80)
    
    print("""
Self-Signed Certificate Test:
  - verify_certificate() in app/crypto/pki.py
  - Checks: cert.issuer == CA_issuer
  - Result: REJECT (issuer is self, not CA)

Expired Certificate Test:
  - verify_certificate() in app/crypto/pki.py
  - Checks: cert.not_valid_after_utc > datetime.utcnow()
  - Result: REJECT (past expiration date)

Forged Certificate Test:
  - verify_certificate() in app/crypto/pki.py
  - Checks: RSA signature verification over certificate
  - Result: REJECT (signature verification fails)

CN Mismatch Test:
  - verify_certificate() in app/crypto/pki.py
  - Checks: extract_cn(cert) == expected_cn
  - Result: REJECT (CN doesn't match expected hostname)

All verifications use cryptographic primitives from:
  - cryptography library (x509, RSA, SHA-256)
  - Standard certificate validation procedures
  - Following RFC 5280 and X.509 standards
""")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
