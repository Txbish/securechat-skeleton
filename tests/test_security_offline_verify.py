#!/usr/bin/env python3
"""
Security Test: Offline Receipt Verification
Tests that session receipts can be verified offline without running the server.

Test Cases:
1. Generate transcript and receipt
2. Verify receipt signature offline
3. Tamper with transcript -> verification fails
4. Tamper with receipt signature -> verification fails
5. Re-verify same receipt multiple times
"""

import sys
import os
import json
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from app.storage import transcript
from app.crypto import sign
from app.common import utils


def test_offline_verification_basic():
    """Test 1: Basic offline receipt verification."""
    print("\n" + "=" * 70)
    print("TEST 1: Basic Offline Receipt Verification")
    print("=" * 70)
    
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create transcript
            tx_file = os.path.join(tmpdir, "session.txt")
            tx = transcript.Transcript(tx_file)
            
            cert_fp = utils.sha256_hex(b"test_cert")[:16]
            
            # Log some messages
            tx.log_message(1, 1000, "ct1", "sig1", cert_fp)
            tx.log_message(2, 2000, "ct2", "sig2", cert_fp)
            tx.log_message(3, 3000, "ct3", "sig3", cert_fp)
            
            print(f"\n[CREATE] Logged 3 messages")
            
            # Compute hash
            tx_hash_hex = tx.compute_hash()
            print(f"[HASH] {tx_hash_hex[:16]}...")
            
            # Sign
            with open('certs/server_key.pem', 'r') as f:
                server_key = f.read()
            
            tx_hash_bytes = bytes.fromhex(tx_hash_hex)
            sig_bytes = sign.rsa_sign(server_key, tx_hash_bytes)
            sig_b64 = utils.b64e(sig_bytes)
            
            print(f"[SIGN] RSA-SHA256 signature created")
            
            # Save receipt
            receipt_file = os.path.join(tmpdir, "receipt.json")
            receipt_data = {
                'type': 'receipt',
                'peer': 'server',
                'first_seq': 1,
                'last_seq': 3,
                'transcript_sha256': tx_hash_hex,
                'sig': sig_b64
            }
            with open(receipt_file, 'w') as f:
                json.dump(receipt_data, f)
            
            print(f"[SAVE] Receipt saved")
            
            # Offline verification: load receipt and transcript
            print(f"\n[OFFLINE VERIFY]")
            with open(receipt_file, 'r') as f:
                receipt_loaded = json.load(f)
            
            with open(tx_file, 'r') as f:
                lines = [line.rstrip('\n') for line in f.readlines() if line.strip()]
            
            # Recompute hash (same as Transcript.compute_hash: concatenate without newlines)
            recomputed_hash = utils.sha256_hex(''.join(lines).encode('utf-8'))
            
            if recomputed_hash != receipt_loaded['transcript_sha256']:
                print(f"  ✗ Hash mismatch!")
                return False
            
            print(f"  ✓ Transcript hash verified")
            
            # Verify signature
            with open('certs/server_cert.pem', 'r') as f:
                server_cert = f.read()
            
            receipt_sig_bytes = utils.b64d(receipt_loaded['sig'])
            if not sign.rsa_verify(server_cert, tx_hash_bytes, receipt_sig_bytes):
                print(f"  ✗ Signature verification failed!")
                return False
            
            print(f"  ✓ Receipt signature verified")
            print(f"\n[PASS] Offline verification successful")
            return True
            
    except Exception as e:
        print(f"  ✗ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_tampered_transcript_detection():
    """Test 2: Tampered transcript detected."""
    print("\n" + "=" * 70)
    print("TEST 2: Tampered Transcript Detection")
    print("=" * 70)
    
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create and sign transcript
            tx_file = os.path.join(tmpdir, "session.txt")
            tx = transcript.Transcript(tx_file)
            
            cert_fp = utils.sha256_hex(b"test_cert")[:16]
            tx.log_message(1, 1000, "ct1", "sig1", cert_fp)
            tx.log_message(2, 2000, "ct2", "sig2", cert_fp)
            
            original_hash = tx.compute_hash()
            
            with open('certs/server_key.pem', 'r') as f:
                server_key = f.read()
            
            tx_hash_bytes = bytes.fromhex(original_hash)
            sig_bytes = sign.rsa_sign(server_key, tx_hash_bytes)
            sig_b64 = utils.b64e(sig_bytes)
            
            print(f"\n[CREATE] Original transcript (2 messages)")
            print(f"[HASH] {original_hash[:16]}...")
            
            # Tamper: add extra message
            with open(tx_file, 'a') as f:
                f.write(f"99|9999|tampered_ct|tampered_sig|tampered_fp\n")
            
            print(f"\n[TAMPER] Added extra message to transcript")
            
            # Try to verify
            print(f"\n[OFFLINE VERIFY]")
            with open(tx_file, 'r') as f:
                lines = [line.rstrip('\n') for line in f.readlines() if line.strip()]
            
            tampered_hash = utils.sha256_hex(''.join(lines).encode('utf-8'))
            print(f"[HASH] {tampered_hash[:16]}... (changed)")
            
            if tampered_hash == original_hash:
                print(f"  ✗ Hash should have changed!")
                return False
            
            # Try to verify with original signature (should fail)
            with open('certs/server_cert.pem', 'r') as f:
                server_cert = f.read()
            
            # Verify against NEW hash will fail since signature is for old hash
            if sign.rsa_verify(server_cert, tampered_hash, sig_bytes):
                print(f"  ✗ Tampered transcript was accepted!")
                return False
            
            print(f"  ✓ Tampered transcript rejected")
            print(f"\n[PASS] Tamper detection working")
            return True
            
    except Exception as e:
        print(f"  ✗ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_tampered_signature_detection():
    """Test 3: Tampered signature detected."""
    print("\n" + "=" * 70)
    print("TEST 3: Tampered Signature Detection")
    print("=" * 70)
    
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create and sign transcript
            tx_file = os.path.join(tmpdir, "session.txt")
            tx = transcript.Transcript(tx_file)
            
            cert_fp = utils.sha256_hex(b"test_cert")[:16]
            tx.log_message(1, 1000, "ct1", "sig1", cert_fp)
            
            tx_hash_hex = tx.compute_hash()
            
            with open('certs/server_key.pem', 'r') as f:
                server_key = f.read()
            
            tx_hash_bytes = bytes.fromhex(tx_hash_hex)
            sig_bytes = sign.rsa_sign(server_key, tx_hash_bytes)
            sig_b64 = utils.b64e(sig_bytes)
            
            print(f"\n[CREATE] Original receipt")
            print(f"[HASH] {tx_hash_hex[:16]}...")
            print(f"[SIG] {sig_b64[:32]}...")
            
            # Tamper: flip a bit in signature
            sig_bytes_tampered = bytearray(sig_bytes)
            sig_bytes_tampered[0] ^= 0x01
            sig_bytes_tampered = bytes(sig_bytes_tampered)
            sig_b64_tampered = utils.b64e(sig_bytes_tampered)
            
            print(f"\n[TAMPER] Flipped bit in signature")
            print(f"[SIG] {sig_b64_tampered[:32]}...")
            
            # Try to verify
            print(f"\n[OFFLINE VERIFY]")
            with open('certs/server_cert.pem', 'r') as f:
                server_cert = f.read()
            
            if sign.rsa_verify(server_cert, tx_hash_bytes, sig_bytes_tampered):
                print(f"  ✗ Tampered signature was accepted!")
                return False
            
            print(f"  ✓ Tampered signature rejected")
            print(f"\n[PASS] Signature tamper detection working")
            return True
            
    except Exception as e:
        print(f"  ✗ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_multiple_verifications():
    """Test 4: Same receipt can be verified multiple times."""
    print("\n" + "=" * 70)
    print("TEST 4: Multiple Verifications of Same Receipt")
    print("=" * 70)
    
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create transcript
            tx_file = os.path.join(tmpdir, "session.txt")
            tx = transcript.Transcript(tx_file)
            
            cert_fp = utils.sha256_hex(b"test_cert")[:16]
            tx.log_message(1, 1000, "ct1", "sig1", cert_fp)
            tx.log_message(2, 2000, "ct2", "sig2", cert_fp)
            
            tx_hash_hex = tx.compute_hash()
            
            with open('certs/server_key.pem', 'r') as f:
                server_key = f.read()
            
            tx_hash_bytes = bytes.fromhex(tx_hash_hex)
            sig_bytes = sign.rsa_sign(server_key, tx_hash_bytes)
            sig_b64 = utils.b64e(sig_bytes)
            
            print(f"\n[CREATE] Receipt for offline verification")
            
            # Verify multiple times
            with open('certs/server_cert.pem', 'r') as f:
                server_cert = f.read()
            
            for i in range(1, 4):
                print(f"\n[VERIFY #{i}]")
                if not sign.rsa_verify(server_cert, tx_hash_bytes, sig_bytes):
                    print(f"  ✗ Verification #{i} failed!")
                    return False
                print(f"  ✓ Passed")
            
            print(f"\n[PASS] Multiple verifications successful")
            return True
            
    except Exception as e:
        print(f"  ✗ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_client_and_server_receipts():
    """Test 5: Both client and server receipts can be verified."""
    print("\n" + "=" * 70)
    print("TEST 5: Client and Server Receipt Verification")
    print("=" * 70)
    
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            # Server transcript
            server_tx_file = os.path.join(tmpdir, "server.txt")
            server_tx = transcript.Transcript(server_tx_file)
            
            cert_fp = utils.sha256_hex(b"server_cert")[:16]
            server_tx.log_message(1, 1000, "ct1", "sig1", cert_fp)
            server_tx.log_message(2, 2000, "ct2", "sig2", cert_fp)
            
            server_hash = server_tx.compute_hash()
            
            with open('certs/server_key.pem', 'r') as f:
                server_key = f.read()
            
            server_sig = sign.rsa_sign(server_key, bytes.fromhex(server_hash))
            
            # Client transcript
            client_tx_file = os.path.join(tmpdir, "client.txt")
            client_tx = transcript.Transcript(client_tx_file)
            
            cert_fp = utils.sha256_hex(b"client_cert")[:16]
            client_tx.log_message(1, 1100, "ct1", "sig1", cert_fp)
            client_tx.log_message(2, 1200, "ct2", "sig2", cert_fp)
            client_tx.log_message(3, 1300, "ct3", "sig3", cert_fp)
            
            client_hash = client_tx.compute_hash()
            
            with open('certs/client_key.pem', 'r') as f:
                client_key = f.read()
            
            client_sig = sign.rsa_sign(client_key, bytes.fromhex(client_hash))
            
            print(f"\n[SERVER] Hash: {server_hash[:16]}...")
            print(f"[CLIENT] Hash: {client_hash[:16]}...")
            
            # Verify server receipt
            print(f"\n[VERIFY] Server receipt...")
            with open('certs/server_cert.pem', 'r') as f:
                server_cert = f.read()
            
            if not sign.rsa_verify(server_cert, bytes.fromhex(server_hash), server_sig):
                print(f"  ✗ Server receipt failed")
                return False
            print(f"  ✓ Server receipt verified")
            
            # Verify client receipt
            print(f"\n[VERIFY] Client receipt...")
            with open('certs/client_cert.pem', 'r') as f:
                client_cert = f.read()
            
            if not sign.rsa_verify(client_cert, bytes.fromhex(client_hash), client_sig):
                print(f"  ✗ Client receipt failed")
                return False
            print(f"  ✓ Client receipt verified")
            
            print(f"\n[PASS] Both receipts verified successfully")
            return True
            
    except Exception as e:
        print(f"  ✗ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all offline verification tests."""
    print("\n" + "=" * 70)
    print("SECURITY TEST SUITE: Offline Receipt Verification")
    print("=" * 70)
    
    tests = [
        ("Basic Offline Verification", test_offline_verification_basic),
        ("Tampered Transcript", test_tampered_transcript_detection),
        ("Tampered Signature", test_tampered_signature_detection),
        ("Multiple Verifications", test_multiple_verifications),
        ("Client & Server Receipts", test_client_and_server_receipts),
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
        print("\n✅ ALL OFFLINE VERIFICATION TESTS PASSED!")
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
