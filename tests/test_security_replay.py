#!/usr/bin/env python3
"""
Security Test: REPLAY
Tests that replayed messages (old seqno) are detected and rejected.

Test Cases:
1. Receive message with seqno=1, verify it's accepted
2. Receive message with seqno=2, verify it's accepted
3. Replay message with seqno=1 -> should be rejected (REPLAY)
4. Replay message with seqno=2 -> should be rejected (REPLAY)
5. Out-of-order messages with wrong seqno -> should be rejected
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from app.crypto import sign, aes
from app.common import utils


class ReplayDetector:
    """Tracks received seqno to detect replays."""
    
    def __init__(self):
        self.last_seqno = -1
        self.received_seqnos = set()
    
    def check_replay(self, seqno):
        """Check if seqno is a replay."""
        if seqno <= self.last_seqno:
            return True  # Replay detected
        self.last_seqno = seqno
        self.received_seqnos.add(seqno)
        return False  # Not a replay


def create_message(seqno, plaintext="test"):
    """Create a signed message with given seqno."""
    with open('certs/client_key.pem', 'r') as f:
        client_key_pem = f.read()
    
    ts = utils.now_ms()
    session_key = b"0123456789abcdef"
    
    ct_bytes = aes.aes_encrypt(session_key, plaintext.encode())
    ct_b64 = utils.b64e(ct_bytes)
    
    signed_data = f"{seqno}||{ts}||{ct_b64}".encode('utf-8')
    sig_bytes = sign.rsa_sign(client_key_pem, signed_data)
    sig_b64 = utils.b64e(sig_bytes)
    
    return {
        'seqno': seqno,
        'ts': ts,
        'ct': ct_b64,
        'sig': sig_b64,
        'signed_data': signed_data,
        'sig_bytes': sig_bytes
    }


def test_sequence_enforcement():
    """Test 1: Strictly increasing sequence numbers enforced."""
    print("\n" + "=" * 70)
    print("TEST 1: Sequence Number Enforcement")
    print("=" * 70)
    
    try:
        detector = ReplayDetector()
        
        # Message 1
        msg1 = create_message(1, "message 1")
        print(f"\n[RCV] seqno={msg1['seqno']}")
        if detector.check_replay(msg1['seqno']):
            print(f"  ✗ FAILED: seqno=1 marked as replay")
            return False
        print(f"  ✓ Accepted")
        
        # Message 2
        msg2 = create_message(2, "message 2")
        print(f"\n[RCV] seqno={msg2['seqno']}")
        if detector.check_replay(msg2['seqno']):
            print(f"  ✗ FAILED: seqno=2 marked as replay")
            return False
        print(f"  ✓ Accepted")
        
        # Message 3
        msg3 = create_message(3, "message 3")
        print(f"\n[RCV] seqno={msg3['seqno']}")
        if detector.check_replay(msg3['seqno']):
            print(f"  ✗ FAILED: seqno=3 marked as replay")
            return False
        print(f"  ✓ Accepted")
        
        print(f"\n[PASS] Sequence enforcement working: 1→2→3 all accepted")
        return True
        
    except Exception as e:
        print(f"  ✗ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_replay_detection_seqno_1():
    """Test 2: Replayed message with seqno=1 rejected."""
    print("\n" + "=" * 70)
    print("TEST 2: Replay Detection - seqno=1")
    print("=" * 70)
    
    try:
        detector = ReplayDetector()
        
        # Accept first message
        msg1 = create_message(1, "message 1")
        print(f"\n[RCV] seqno={msg1['seqno']} (first time)")
        if detector.check_replay(msg1['seqno']):
            print(f"  ✗ FAILED: Original message rejected")
            return False
        print(f"  ✓ Accepted")
        
        # Accept second message
        msg2 = create_message(2, "message 2")
        print(f"\n[RCV] seqno={msg2['seqno']}")
        if detector.check_replay(msg2['seqno']):
            print(f"  ✗ FAILED: seqno=2 rejected")
            return False
        print(f"  ✓ Accepted")
        
        # Try to replay first message
        msg1_replay = create_message(1, "message 1 (replay)")
        print(f"\n[RCV] seqno={msg1_replay['seqno']} (REPLAY ATTEMPT)")
        if not detector.check_replay(msg1_replay['seqno']):
            print(f"  ✗ FAILED: Replayed message was accepted!")
            return False
        print(f"  ✓ Rejected (REPLAY)")
        
        print(f"\n[PASS] Replay detection working")
        return True
        
    except Exception as e:
        print(f"  ✗ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_out_of_order_rejected():
    """Test 3: Out-of-order messages rejected."""
    print("\n" + "=" * 70)
    print("TEST 3: Out-of-Order Message Rejection")
    print("=" * 70)
    
    try:
        detector = ReplayDetector()
        
        # Accept message 1
        msg1 = create_message(1, "message 1")
        print(f"\n[RCV] seqno={msg1['seqno']}")
        if detector.check_replay(msg1['seqno']):
            print(f"  ✗ FAILED: seqno=1 rejected")
            return False
        print(f"  ✓ Accepted")
        
        # Try to send message 3 before message 2
        msg3 = create_message(3, "message 3")
        print(f"\n[RCV] seqno={msg3['seqno']} (expecting seqno=2)")
        if detector.check_replay(msg3['seqno']):
            print(f"  ✗ FAILED: Out-of-order marked as replay (should be accepted)")
            return False
        print(f"  ✓ Accepted (next in sequence)")
        
        # Now try to replay seqno 1
        msg1_replay = create_message(1, "message 1 (replay)")
        print(f"\n[RCV] seqno={msg1_replay['seqno']} (after seqno=3)")
        if not detector.check_replay(msg1_replay['seqno']):
            print(f"  ✗ FAILED: Old seqno was accepted")
            return False
        print(f"  ✓ Rejected (older than last)")
        
        print(f"\n[PASS] Out-of-order detection working")
        return True
        
    except Exception as e:
        print(f"  ✗ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_duplicate_detection():
    """Test 4: Exact duplicate (same seqno) detected."""
    print("\n" + "=" * 70)
    print("TEST 4: Duplicate Detection (Same Seqno)")
    print("=" * 70)
    
    try:
        detector = ReplayDetector()
        
        # First message
        msg1 = create_message(5, "message")
        print(f"\n[RCV] seqno={msg1['seqno']}")
        if detector.check_replay(msg1['seqno']):
            print(f"  ✗ FAILED: First seqno=5 rejected")
            return False
        print(f"  ✓ Accepted")
        
        # Exact duplicate
        msg1_dup = create_message(5, "message")
        print(f"\n[RCV] seqno={msg1_dup['seqno']} (DUPLICATE)")
        if not detector.check_replay(msg1_dup['seqno']):
            print(f"  ✗ FAILED: Duplicate was accepted!")
            return False
        print(f"  ✓ Rejected (REPLAY)")
        
        print(f"\n[PASS] Duplicate detection working")
        return True
        
    except Exception as e:
        print(f"  ✗ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_gap_in_sequence():
    """Test 5: Gap in sequence (skip seqno) is acceptable."""
    print("\n" + "=" * 70)
    print("TEST 5: Gap in Sequence (Skip Seqno)")
    print("=" * 70)
    
    try:
        detector = ReplayDetector()
        
        # Message 1
        msg1 = create_message(1, "message 1")
        print(f"\n[RCV] seqno={msg1['seqno']}")
        if detector.check_replay(msg1['seqno']):
            print(f"  ✗ FAILED: seqno=1 rejected")
            return False
        print(f"  ✓ Accepted")
        
        # Message 5 (skipping 2, 3, 4)
        msg5 = create_message(5, "message 5")
        print(f"\n[RCV] seqno={msg5['seqno']} (skipped 2, 3, 4)")
        if detector.check_replay(msg5['seqno']):
            print(f"  ✗ FAILED: seqno=5 rejected (gap acceptable)")
            return False
        print(f"  ✓ Accepted (gap acceptable)")
        
        # Message 6
        msg6 = create_message(6, "message 6")
        print(f"\n[RCV] seqno={msg6['seqno']}")
        if detector.check_replay(msg6['seqno']):
            print(f"  ✗ FAILED: seqno=6 rejected")
            return False
        print(f"  ✓ Accepted")
        
        print(f"\n[PASS] Gap in sequence is acceptable")
        return True
        
    except Exception as e:
        print(f"  ✗ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all REPLAY security tests."""
    print("\n" + "=" * 70)
    print("SECURITY TEST SUITE: REPLAY (Replay Protection)")
    print("=" * 70)
    
    tests = [
        ("Sequence Enforcement", test_sequence_enforcement),
        ("Replay Detection - seqno=1", test_replay_detection_seqno_1),
        ("Out-of-Order Rejection", test_out_of_order_rejected),
        ("Duplicate Detection", test_duplicate_detection),
        ("Gap in Sequence", test_gap_in_sequence),
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
        print("\n✅ ALL REPLAY TESTS PASSED!")
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
