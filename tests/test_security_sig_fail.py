#!/usr/bin/env python3
"""
Security Test: SIG_FAIL
Tests that tampering with messages is detected through signature verification failure.

Test Cases:
1. Tamper with ciphertext -> signature verification fails
2. Tamper with seqno -> signature verification fails
3. Tamper with timestamp -> signature verification fails
4. Tamper with signature itself -> verification fails
5. Original message verifies successfully
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from app.crypto import sign, aes
from app.common import utils
import json


def test_tamper_ciphertext():
    """Test 1: Tampering with ciphertext should cause signature verification to fail."""
    print("\n" + "=" * 70)
    print("TEST 1: Tamper with Ciphertext (SIG_FAIL)")
    print("=" * 70)
    
    try:
        # Load keys
        with open('certs/client_key.pem', 'r') as f:
            client_key_pem = f.read()
        with open('certs/client_cert.pem', 'r') as f:
            client_cert_pem = f.read()
        
        # Create a message
        seqno = 1
        ts = utils.now_ms()
        plaintext = "Hello, this is a test message"
        session_key = b"0123456789abcdef"  # 16 bytes
        
        # Encrypt
        ct_bytes = aes.aes_encrypt(session_key, plaintext.encode())
        ct_b64 = utils.b64e(ct_bytes)
        
        # Sign
        signed_data = f"{seqno}||{ts}||{ct_b64}".encode('utf-8')
        sig_bytes = sign.rsa_sign(client_key_pem, signed_data)
        sig_b64 = utils.b64e(sig_bytes)
        
        print(f"\n[ORIGINAL MESSAGE]")
        print(f"  seqno: {seqno}")
        print(f"  ts: {ts}")
        print(f"  ct: {ct_b64[:32]}...")
        print(f"  sig: {sig_b64[:32]}...")
        
        # Now tamper: flip a bit in ciphertext
        ct_bytes_tampered = bytearray(utils.b64d(ct_b64))
        ct_bytes_tampered[0] ^= 0x01  # Flip first bit
        ct_b64_tampered = utils.b64e(bytes(ct_bytes_tampered))
        
        print(f"\n[TAMPERED MESSAGE]")
        print(f"  Modified ct: {ct_b64_tampered[:32]}...")
        print(f"  sig: {sig_b64[:32]}... (unchanged)")
        
        # Try to verify tampered message with original signature
        print(f"\n[VERIFICATION]")
        tampered_data = f"{seqno}||{ts}||{ct_b64_tampered}".encode('utf-8')
        
        if sign.rsa_verify(client_cert_pem, tampered_data, sig_bytes):
            print(f"  ✗ FAILED: Tampered message was accepted!")
            return False
        else:
            print(f"  ✓ PASSED: Tampered ciphertext rejected (SIG_FAIL)")
            return True
            
    except Exception as e:
        print(f"  ✗ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_tamper_seqno():
    """Test 2: Tampering with sequence number should fail verification."""
    print("\n" + "=" * 70)
    print("TEST 2: Tamper with Sequence Number (SIG_FAIL)")
    print("=" * 70)
    
    try:
        # Load keys
        with open('certs/client_key.pem', 'r') as f:
            client_key_pem = f.read()
        with open('certs/client_cert.pem', 'r') as f:
            client_cert_pem = f.read()
        
        # Create a message
        seqno = 5
        ts = utils.now_ms()
        plaintext = "Test message for seqno tampering"
        session_key = b"0123456789abcdef"
        
        # Encrypt
        ct_bytes = aes.aes_encrypt(session_key, plaintext.encode())
        ct_b64 = utils.b64e(ct_bytes)
        
        # Sign
        signed_data = f"{seqno}||{ts}||{ct_b64}".encode('utf-8')
        sig_bytes = sign.rsa_sign(client_key_pem, signed_data)
        sig_b64 = utils.b64e(sig_bytes)
        
        print(f"\n[ORIGINAL MESSAGE]")
        print(f"  seqno: {seqno}")
        print(f"  ts: {ts}")
        print(f"  sig: {sig_b64[:32]}...")
        
        # Tamper: change seqno
        seqno_tampered = 99
        print(f"\n[TAMPERED MESSAGE]")
        print(f"  seqno: {seqno_tampered} (changed from {seqno})")
        print(f"  sig: {sig_b64[:32]}... (unchanged)")
        
        # Try to verify
        print(f"\n[VERIFICATION]")
        tampered_data = f"{seqno_tampered}||{ts}||{ct_b64}".encode('utf-8')
        
        if sign.rsa_verify(client_cert_pem, tampered_data, sig_bytes):
            print(f"  ✗ FAILED: Tampered seqno was accepted!")
            return False
        else:
            print(f"  ✓ PASSED: Tampered seqno rejected (SIG_FAIL)")
            return True
            
    except Exception as e:
        print(f"  ✗ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_tamper_timestamp():
    """Test 3: Tampering with timestamp should fail verification."""
    print("\n" + "=" * 70)
    print("TEST 3: Tamper with Timestamp (SIG_FAIL)")
    print("=" * 70)
    
    try:
        # Load keys
        with open('certs/client_key.pem', 'r') as f:
            client_key_pem = f.read()
        with open('certs/client_cert.pem', 'r') as f:
            client_cert_pem = f.read()
        
        # Create a message
        seqno = 2
        ts = utils.now_ms()
        plaintext = "Test message for timestamp tampering"
        session_key = b"0123456789abcdef"
        
        # Encrypt
        ct_bytes = aes.aes_encrypt(session_key, plaintext.encode())
        ct_b64 = utils.b64e(ct_bytes)
        
        # Sign
        signed_data = f"{seqno}||{ts}||{ct_b64}".encode('utf-8')
        sig_bytes = sign.rsa_sign(client_key_pem, signed_data)
        sig_b64 = utils.b64e(sig_bytes)
        
        print(f"\n[ORIGINAL MESSAGE]")
        print(f"  seqno: {seqno}")
        print(f"  ts: {ts}")
        print(f"  sig: {sig_b64[:32]}...")
        
        # Tamper: change timestamp
        ts_tampered = ts + 10000
        print(f"\n[TAMPERED MESSAGE]")
        print(f"  seqno: {seqno}")
        print(f"  ts: {ts_tampered} (changed from {ts})")
        print(f"  sig: {sig_b64[:32]}... (unchanged)")
        
        # Try to verify
        print(f"\n[VERIFICATION]")
        tampered_data = f"{seqno}||{ts_tampered}||{ct_b64}".encode('utf-8')
        
        if sign.rsa_verify(client_cert_pem, tampered_data, sig_bytes):
            print(f"  ✗ FAILED: Tampered timestamp was accepted!")
            return False
        else:
            print(f"  ✓ PASSED: Tampered timestamp rejected (SIG_FAIL)")
            return True
            
    except Exception as e:
        print(f"  ✗ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_tamper_signature():
    """Test 4: Tampering with the signature itself should fail verification."""
    print("\n" + "=" * 70)
    print("TEST 4: Tamper with Signature (SIG_FAIL)")
    print("=" * 70)
    
    try:
        # Load keys
        with open('certs/client_key.pem', 'r') as f:
            client_key_pem = f.read()
        with open('certs/client_cert.pem', 'r') as f:
            client_cert_pem = f.read()
        
        # Create a message
        seqno = 3
        ts = utils.now_ms()
        plaintext = "Test message for signature tampering"
        session_key = b"0123456789abcdef"
        
        # Encrypt
        ct_bytes = aes.aes_encrypt(session_key, plaintext.encode())
        ct_b64 = utils.b64e(ct_bytes)
        
        # Sign
        signed_data = f"{seqno}||{ts}||{ct_b64}".encode('utf-8')
        sig_bytes = sign.rsa_sign(client_key_pem, signed_data)
        
        print(f"\n[ORIGINAL MESSAGE]")
        print(f"  seqno: {seqno}")
        print(f"  ts: {ts}")
        print(f"  sig: {utils.b64e(sig_bytes)[:32]}...")
        
        # Tamper: flip a bit in signature
        sig_bytes_tampered = bytearray(sig_bytes)
        sig_bytes_tampered[0] ^= 0x01
        sig_bytes_tampered = bytes(sig_bytes_tampered)
        
        print(f"\n[TAMPERED MESSAGE]")
        print(f"  seqno: {seqno}")
        print(f"  ts: {ts}")
        print(f"  sig: {utils.b64e(sig_bytes_tampered)[:32]}... (bit flipped)")
        
        # Try to verify
        print(f"\n[VERIFICATION]")
        if sign.rsa_verify(client_cert_pem, signed_data, sig_bytes_tampered):
            print(f"  ✗ FAILED: Tampered signature was accepted!")
            return False
        else:
            print(f"  ✓ PASSED: Tampered signature rejected (SIG_FAIL)")
            return True
            
    except Exception as e:
        print(f"  ✗ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_original_message_valid():
    """Test 5: Original unmodified message should verify successfully."""
    print("\n" + "=" * 70)
    print("TEST 5: Original Message Verification (Should PASS)")
    print("=" * 70)
    
    try:
        # Load keys
        with open('certs/client_key.pem', 'r') as f:
            client_key_pem = f.read()
        with open('certs/client_cert.pem', 'r') as f:
            client_cert_pem = f.read()
        
        # Create a message
        seqno = 10
        ts = utils.now_ms()
        plaintext = "This is an authentic message"
        session_key = b"0123456789abcdef"
        
        # Encrypt
        ct_bytes = aes.aes_encrypt(session_key, plaintext.encode())
        ct_b64 = utils.b64e(ct_bytes)
        
        # Sign
        signed_data = f"{seqno}||{ts}||{ct_b64}".encode('utf-8')
        sig_bytes = sign.rsa_sign(client_key_pem, signed_data)
        sig_b64 = utils.b64e(sig_bytes)
        
        print(f"\n[MESSAGE]")
        print(f"  seqno: {seqno}")
        print(f"  ts: {ts}")
        print(f"  ct: {ct_b64[:32]}...")
        print(f"  sig: {sig_b64[:32]}...")
        
        # Verify original message
        print(f"\n[VERIFICATION]")
        if not sign.rsa_verify(client_cert_pem, signed_data, sig_bytes):
            print(f"  ✗ FAILED: Original message verification failed!")
            return False
        else:
            print(f"  ✓ PASSED: Original message verified successfully")
            return True
            
    except Exception as e:
        print(f"  ✗ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all SIG_FAIL security tests."""
    print("\n" + "=" * 70)
    print("SECURITY TEST SUITE: SIG_FAIL (Signature Verification & Tampering)")
    print("=" * 70)
    
    tests = [
        ("Tamper Ciphertext", test_tamper_ciphertext),
        ("Tamper Seqno", test_tamper_seqno),
        ("Tamper Timestamp", test_tamper_timestamp),
        ("Tamper Signature", test_tamper_signature),
        ("Original Message Valid", test_original_message_valid),
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
        print("\n✅ ALL SIG_FAIL TESTS PASSED!")
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
