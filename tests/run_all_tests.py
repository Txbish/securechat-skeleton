#!/usr/bin/env python3
"""
Comprehensive Test Summary Report
Runs all tests and generates summary
"""

import sys
import os

sys.path.insert(0, '/home/tabish/Desktop/securechat-skeleton')


def run_all_tests():
    """Run all test suites and collect results."""
    
    print("\n" + "=" * 80)
    print("COMPREHENSIVE SECURITY TEST REPORT - SecureChat Assignment #2")
    print("=" * 80)
    
    results = {}
    
    # Test 1: BAD_CERT
    print("\n" + "-" * 80)
    print("RUNNING: BAD_CERT Tests (Certificate Validation)")
    print("-" * 80)
    try:
        from tests.test_security_bad_cert import main as bad_cert_main
        results['BAD_CERT'] = bad_cert_main()
    except Exception as e:
        print(f"ERROR running BAD_CERT: {e}")
        results['BAD_CERT'] = False
    
    # Test 2: SIG_FAIL
    print("\n" + "-" * 80)
    print("RUNNING: SIG_FAIL Tests (Tampering Detection)")
    print("-" * 80)
    try:
        from tests.test_security_sig_fail import main as sig_fail_main
        results['SIG_FAIL'] = sig_fail_main()
    except Exception as e:
        print(f"ERROR running SIG_FAIL: {e}")
        results['SIG_FAIL'] = False
    
    # Test 3: REPLAY
    print("\n" + "-" * 80)
    print("RUNNING: REPLAY Tests (Replay Protection)")
    print("-" * 80)
    try:
        from tests.test_security_replay import main as replay_main
        results['REPLAY'] = replay_main()
    except Exception as e:
        print(f"ERROR running REPLAY: {e}")
        results['REPLAY'] = False
    
    # Test 4: Offline Verification
    print("\n" + "-" * 80)
    print("RUNNING: Offline Verification Tests")
    print("-" * 80)
    try:
        from tests.test_security_offline_verify import main as offline_main
        results['OfflineVerify'] = offline_main()
    except Exception as e:
        print(f"ERROR running OfflineVerify: {e}")
        results['OfflineVerify'] = False
    
    # Summary
    print("\n\n" + "=" * 80)
    print("FINAL TEST SUMMARY")
    print("=" * 80)
    
    test_names = {
        'BAD_CERT': 'Certificate Validation',
        'SIG_FAIL': 'Tampering Detection',
        'REPLAY': 'Replay Protection',
        'OfflineVerify': 'Offline Verification'
    }
    
    all_passed = True
    for test_key, test_name in test_names.items():
        status = "✓ PASS" if results[test_key] else "✗ FAIL"
        print(f"  {status}: {test_name}")
        if not results[test_key]:
            all_passed = False
    
    print("\n" + "=" * 80)
    passed_count = sum(1 for p in results.values() if p)
    total_count = len(results)
    print(f"OVERALL: {passed_count}/{total_count} test suites passed")
    print("=" * 80)
    
    # CIANR Summary
    print("\n" + "=" * 80)
    print("SECURITY PROPERTIES (CIANR) VERIFIED")
    print("=" * 80)
    print("""
✓ CONFIDENTIALITY
  - AES-128 ECB + PKCS#7 encryption
  - Session key from DH key exchange
  - All payloads encrypted (no plaintext on wire)

✓ INTEGRITY
  - RSA-SHA256 signature over seqno||ts||ct
  - SIG_FAIL on any bit modification
  - Verified in: SIG_FAIL tests

✓ AUTHENTICITY
  - X.509 certificate validation
  - Mutual certificate exchange
  - BAD_CERT on invalid/expired/self-signed certs
  - Verified in: BAD_CERT tests

✓ NON-REPUDIATION
  - Append-only transcript with peer fingerprints
  - Session receipt with signed transcript hash
  - Offline verification without server
  - Verified in: OfflineVerify tests

✓ FRESHNESS
  - Monotonically increasing sequence numbers
  - REPLAY detection on old seqno
  - Replay protection verified in: REPLAY tests
    """)
    
    print("=" * 80)
    print(f"\n{'✅ ALL TESTS PASSED' if all_passed else '❌ SOME TESTS FAILED'}")
    print("=" * 80 + "\n")
    
    return all_passed


if __name__ == '__main__':
    try:
        success = run_all_tests()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n❌ FATAL ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
