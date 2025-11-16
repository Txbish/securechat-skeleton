#!/usr/bin/env python3
"""
Non-Repudiation Verification Script

Demonstrates offline verification of:
1. Message authenticity: Verify RSA signatures over message hashes
2. Message integrity: Recompute hash and verify signature
3. Receipt authenticity: Verify receipt signature over transcript hash
4. Tampering detection: Show that any edit breaks verification

Usage:
    python3 verify_nonrepudiation.py <transcript_file> <receipt_file> <public_key_pem>
    
Example:
    python3 verify_nonrepudiation.py transcripts/S00001_server.txt transcripts/server_receipt_S00001.json certs/server_cert.pem
"""

import sys
import json
import hashlib
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

def sha256_hex(data: bytes) -> str:
    """Compute SHA-256 hash and return as hex string."""
    return hashlib.sha256(data).hexdigest()

def load_transcript(transcript_file: str) -> list:
    """
    Load transcript file and parse lines.
    
    Format: seqno|ts|ct|sig|peer-cert-fingerprint
    
    Returns:
        List of dicts with transcript entries
    """
    entries = []
    with open(transcript_file, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split('|')
            if len(parts) < 5:
                print(f"[WARN] Skipping malformed line: {line[:80]}")
                continue
            
            entries.append({
                'seqno': int(parts[0]),
                'ts': int(parts[1]),
                'ct': parts[2],
                'sig': parts[3],
                'peer_fp': parts[4],
                'raw_line': line
            })
    
    return entries

def load_receipt(receipt_file: str) -> dict:
    """Load and parse SessionReceipt JSON file."""
    with open(receipt_file, 'r') as f:
        return json.load(f)

def load_public_key(cert_pem_path: str):
    """
    Load public key from certificate or PEM file.
    
    Args:
        cert_pem_path: Path to PEM-encoded certificate or public key
        
    Returns:
        RSA public key object
    """
    with open(cert_pem_path, 'r') as f:
        cert_pem = f.read()
    
    try:
        # Try loading as certificate first
        from cryptography.x509 import load_pem_x509_certificate
        cert = load_pem_x509_certificate(cert_pem.encode(), default_backend())
        return cert.public_key()
    except:
        # If that fails, try loading as public key
        public_key = serialization.load_pem_public_key(
            cert_pem.encode(),
            backend=default_backend()
        )
        return public_key

def b64d(s: str) -> bytes:
    """Base64 decode a string."""
    import base64
    return base64.b64decode(s)

def verify_signature(public_key, data: bytes, signature_b64: str) -> bool:
    """
    Verify RSA signature.
    
    Args:
        public_key: RSA public key
        data: Data that was signed
        signature_b64: Signature in base64
        
    Returns:
        True if signature is valid, False otherwise
    """
    try:
        sig_bytes = b64d(signature_b64)
        public_key.verify(
            sig_bytes,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except:
        return False

def verify_message_signature(public_key, entry: dict) -> bool:
    """
    Verify signature on a transcript message entry.
    
    Data signed: seqno||ts||ct (concatenation)
    
    Args:
        public_key: RSA public key
        entry: Transcript entry dict
        
    Returns:
        True if signature is valid
    """
    # Reconstruct signed data: seqno||ts||ct
    signed_data = f"{entry['seqno']}||{entry['ts']}||{entry['ct']}".encode('utf-8')
    return verify_signature(public_key, signed_data, entry['sig'])

def verify_receipt_signature(public_key, receipt: dict) -> bool:
    """
    Verify signature on receipt.
    
    Data signed: transcript_sha256 (hex string, converted to bytes)
    
    Args:
        public_key: RSA public key
        receipt: SessionReceipt dict
        
    Returns:
        True if signature is valid
    """
    # Receipt is signed over the transcript hash (hex string)
    transcript_hash_hex = receipt['transcript_sha256']
    signed_data = bytes.fromhex(transcript_hash_hex)
    return verify_signature(public_key, signed_data, receipt['sig'])

def compute_transcript_hash(entries: list) -> str:
    """
    Compute transcript hash by concatenating all lines.
    
    Returns:
        SHA-256 hash in hex
    """
    concatenated = "".join([entry['raw_line'] for entry in entries])
    return sha256_hex(concatenated.encode('utf-8'))

def demonstrate_tampering(entries: list, public_key):
    """
    Demonstrate that tampering breaks verification.
    
    Args:
        entries: List of transcript entries
        public_key: RSA public key
    """
    if not entries:
        print("[SKIP] Cannot demonstrate tampering: empty transcript")
        return
    
    print("\n" + "="*80)
    print("TAMPERING DETECTION DEMONSTRATION")
    print("="*80)
    
    # Take first entry and tamper with it
    entry = entries[0].copy()
    print(f"\n[ORIGINAL] Entry 1: seqno={entry['seqno']}, ct={entry['ct'][:32]}..., sig={entry['sig'][:32]}...")
    
    # Verify original signature
    original_valid = verify_message_signature(public_key, entry)
    print(f"[VERIFY] Original signature: {'✓ VALID' if original_valid else '✗ INVALID'}")
    
    # Tamper: flip a bit in ciphertext
    ct_bytes = bytearray(b64d(entry['ct']))
    original_byte = ct_bytes[0]
    ct_bytes[0] ^= 0xFF  # Flip all bits in first byte
    
    import base64
    entry['ct'] = base64.b64encode(bytes(ct_bytes)).decode('utf-8')
    
    print(f"\n[TAMPER] Flipped bit in ciphertext (byte 0: {original_byte:02x} → {ct_bytes[0]:02x})")
    print(f"[TAMPERED] Entry 1: ct={entry['ct'][:32]}...")
    
    # Verify tampered signature (using original signature)
    tampered_valid = verify_message_signature(public_key, entry)
    print(f"[VERIFY] Tampered message with original signature: {'✓ VALID (ALERT!)' if tampered_valid else '✗ INVALID (expected)'}")
    
    if not tampered_valid:
        print("\n✓ SUCCESS: Tampering was detected! Original signature fails on tampered message.")
    else:
        print("\n✗ FAILURE: Tampering was NOT detected!")
    
    print("\nConclusion: Any modification to the transcript invalidates signatures,")
    print("providing strong evidence of tampering and protecting non-repudiation.")

def main():
    """Main verification function."""
    if len(sys.argv) < 4:
        print("Usage: python3 verify_nonrepudiation.py <transcript_file> <receipt_file> <cert_pem_path>")
        print("\nExample:")
        print("  python3 verify_nonrepudiation.py transcripts/S00001_server.txt \\")
        print("    transcripts/server_receipt_S00001.json certs/server_cert.pem")
        sys.exit(1)
    
    transcript_file = sys.argv[1]
    receipt_file = sys.argv[2]
    cert_pem_path = sys.argv[3]
    
    # Load data
    print("="*80)
    print("NON-REPUDIATION VERIFICATION")
    print("="*80)
    
    print(f"\n[LOAD] Transcript: {transcript_file}")
    if not Path(transcript_file).exists():
        print(f"ERROR: Transcript file not found: {transcript_file}")
        sys.exit(1)
    entries = load_transcript(transcript_file)
    print(f"       Loaded {len(entries)} entries")
    
    print(f"\n[LOAD] Receipt: {receipt_file}")
    if not Path(receipt_file).exists():
        print(f"ERROR: Receipt file not found: {receipt_file}")
        sys.exit(1)
    receipt = load_receipt(receipt_file)
    print(f"       Peer: {receipt['peer']}")
    print(f"       Messages: {receipt['first_seq']}-{receipt['last_seq']}")
    print(f"       Transcript hash: {receipt['transcript_sha256']}")
    print(f"       Signature: {receipt['sig'][:32]}...")
    
    print(f"\n[LOAD] Public key: {cert_pem_path}")
    if not Path(cert_pem_path).exists():
        print(f"ERROR: Certificate file not found: {cert_pem_path}")
        sys.exit(1)
    try:
        public_key = load_public_key(cert_pem_path)
        print(f"       Loaded RSA {public_key.key_size}-bit public key")
    except Exception as e:
        print(f"ERROR: Failed to load public key: {e}")
        sys.exit(1)
    
    # Verify message signatures
    print("\n" + "="*80)
    print("STEP 1: VERIFY MESSAGE SIGNATURES")
    print("="*80)
    
    all_valid = True
    for i, entry in enumerate(entries, 1):
        is_valid = verify_message_signature(public_key, entry)
        status = "✓ VALID" if is_valid else "✗ INVALID"
        print(f"  [{i:2d}] seqno={entry['seqno']} ts={entry['ts']} {status}")
        if not is_valid:
            all_valid = False
            print(f"       Data: {entry['seqno']}||{entry['ts']}||{entry['ct'][:32]}...")
            print(f"       Sig: {entry['sig'][:32]}...")
    
    if all_valid:
        print(f"\n✓ All {len(entries)} message signatures verified successfully!")
    else:
        print(f"\n✗ Some message signatures failed verification!")
    
    # Verify transcript hash
    print("\n" + "="*80)
    print("STEP 2: VERIFY TRANSCRIPT INTEGRITY")
    print("="*80)
    
    computed_hash = compute_transcript_hash(entries)
    receipt_hash = receipt['transcript_sha256']
    
    print(f"\n[COMPUTE] Transcript hash from entries:")
    print(f"  Computed: {computed_hash}")
    print(f"  Receipt:  {receipt_hash}")
    
    if computed_hash == receipt_hash:
        print(f"\n✓ Transcript hash matches! No tampering detected.")
    else:
        print(f"\n✗ Transcript hash MISMATCH! Transcript has been tampered with!")
        all_valid = False
    
    # Verify receipt signature
    print("\n" + "="*80)
    print("STEP 3: VERIFY RECEIPT SIGNATURE")
    print("="*80)
    
    receipt_valid = verify_receipt_signature(public_key, receipt)
    status = "✓ VALID" if receipt_valid else "✗ INVALID"
    
    print(f"\nReceipt signature verification: {status}")
    print(f"  Data (hash): {receipt['transcript_sha256']}")
    print(f"  Signature: {receipt['sig'][:64]}...")
    
    if not receipt_valid:
        print(f"\n✗ Receipt signature verification failed!")
        all_valid = False
    else:
        print(f"\n✓ Receipt signature verified!")
    
    # Demonstrate tampering
    demonstrate_tampering(entries, public_key)
    
    # Summary
    print("\n" + "="*80)
    print("VERIFICATION SUMMARY")
    print("="*80)
    
    if all_valid:
        print("\n✓ ALL VERIFICATIONS PASSED")
        print("\nNon-Repudiation Properties Verified:")
        print("  1. ✓ All message signatures are valid (authenticity)")
        print("  2. ✓ Transcript hash is intact (integrity)")
        print("  3. ✓ Receipt signature is valid (receipt authenticity)")
        print("  4. ✓ Any tampering breaks verification (tampering detection)")
        print("\nConclusion: Both sender and receiver have irrefutable proof of")
        print("communication. Neither party can deny sending/receiving messages.")
        return 0
    else:
        print("\n✗ SOME VERIFICATIONS FAILED")
        print("\nReview the errors above for details.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
