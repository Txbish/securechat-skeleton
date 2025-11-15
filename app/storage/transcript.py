"""Append-only transcript logging + TranscriptHash computation."""

import os
import hashlib
from typing import List
from app.common.utils import sha256_hex


class Transcript:
    """
    Append-only transcript for recording session messages.
    Each line contains: seqno | ts | ct | sig | peer-cert-fingerprint
    """
    
    def __init__(self, file_path: str):
        """
        Initialize transcript file.
        
        Args:
            file_path: path to transcript file
        """
        self.file_path = file_path
        self.lines: List[str] = []
        
        # Create directory if needed
        os.makedirs(os.path.dirname(file_path) if os.path.dirname(file_path) else ".", exist_ok=True)
        
        # Initialize or load existing transcript
        if os.path.exists(file_path):
            self._load_transcript()
    
    def _load_transcript(self):
        """Load existing transcript lines from file."""
        try:
            with open(self.file_path, 'r') as f:
                self.lines = [line.rstrip('\n') for line in f if line.strip()]
        except IOError:
            self.lines = []
    
    def append(self, seqno: int, ts: int, ct: str, sig: str, peer_cert_fingerprint: str):
        """
        Append a message entry to transcript.
        
        Args:
            seqno: message sequence number
            ts: message timestamp (ms)
            ct: ciphertext (base64)
            sig: signature (base64)
            peer_cert_fingerprint: peer's cert SHA-256 fingerprint
        """
        # Format: seqno | ts | ct | sig | peer-cert-fingerprint
        line = f"{seqno}|{ts}|{ct}|{sig}|{peer_cert_fingerprint}"
        self.lines.append(line)
        
        # Append to file
        try:
            with open(self.file_path, 'a') as f:
                f.write(line + '\n')
        except IOError as e:
            raise IOError(f"Failed to write to transcript: {e}")
    
    def get_lines(self) -> List[str]:
        """
        Get all transcript lines.
        
        Returns:
            list of transcript lines
        """
        return self.lines.copy()
    
    def compute_hash(self) -> str:
        """
        Compute transcript hash: SHA256(concatenation of all lines).
        
        Returns:
            hex-encoded SHA-256 hash of concatenated transcript
        """
        if not self.lines:
            # Hash of empty string
            return sha256_hex("")
        
        # Concatenate all lines (no separator)
        concatenated = "".join(self.lines)
        return sha256_hex(concatenated)
    
    def get_seqno_range(self) -> tuple:
        """
        Get range of sequence numbers in transcript.
        
        Returns:
            (first_seqno, last_seqno) or (None, None) if empty
        """
        if not self.lines:
            return None, None
        
        try:
            first_seqno = int(self.lines[0].split('|')[0])
            last_seqno = int(self.lines[-1].split('|')[0])
            return first_seqno, last_seqno
        except (IndexError, ValueError):
            return None, None
    
    def clear(self):
        """Clear transcript from memory and file."""
        self.lines = []
        try:
            if os.path.exists(self.file_path):
                os.remove(self.file_path)
        except IOError:
            pass
    
    def __len__(self) -> int:
        """Return number of lines in transcript."""
        return len(self.lines)
    
    def __repr__(self) -> str:
        return f"Transcript({self.file_path}, {len(self.lines)} lines)"
