"""
SecureChat Client - Interactive client for secure messaging.

Handles:
1. Certificate loading from PEM file
2. Server certificate validation
3. Registration/Login flow with DH key exchange
4. Interactive message sending/receiving
5. Session receipt verification
"""

import socket
import threading
import logging
import json
import os
import sys
from typing import Optional
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.common import protocol, utils
from app.crypto import aes, dh, sign, pki
from app.storage import transcript

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [CLIENT] %(message)s'
)
logger = logging.getLogger(__name__)

# Client configuration
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 5555
CA_CERT_PATH = 'certs/ca_cert.pem'
CLIENT_KEY_PATH = 'certs/client_key.pem'


class SecureClient:
    """Client for secure chat application."""
    
    def __init__(self, cert_path: str, key_path: str):
        """
        Initialize the client.
        
        Args:
            cert_path: Path to client X.509 certificate (PEM)
            key_path: Path to client private key (PEM)
        """
        self.cert_path = cert_path
        self.key_path = key_path
        self.socket: Optional[socket.socket] = None
        
        # Authentication state
        self.cert_pem: Optional[str] = None
        self.private_key_pem: Optional[str] = None
        self.is_authenticated = False
        
        # Cryptographic state
        self.temp_dh_key: Optional[bytes] = None
        self.session_key: Optional[bytes] = None
        self.server_cert_pem: Optional[str] = None
        
        # Message tracking
        self.seqno = 1
        self.transcript: Optional[transcript.Transcript] = None
        self.session_id: Optional[str] = None
        
    def load_credentials(self) -> bool:
        """
        Load client certificate and private key from PEM files.
        
        Returns:
            True if successful, False otherwise
        """
        try:
            with open(self.cert_path, 'r') as f:
                self.cert_pem = f.read()
            
            with open(self.key_path, 'r') as f:
                self.private_key_pem = f.read()
            
            logger.info("Credentials loaded successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to load credentials: {e}")
            return False
    
    def send_message(self, msg: protocol.BaseModel) -> bool:
        """
        Send a protocol message to the server.
        
        Args:
            msg: Pydantic model to send
            
        Returns:
            True if successful, False otherwise
        """
        try:
            json_str = protocol.serialize_message(msg)
            self.socket.sendall((json_str + '\n').encode('utf-8'))
            logger.info(f"Sent {msg.type}: {json_str[:100]}")
            return True
        except Exception as e:
            logger.error(f"Failed to send message: {e}")
            return False
    
    def recv_message(self, timeout: float = 30.0) -> Optional[protocol.BaseModel]:
        """
        Receive a protocol message from the server.
        
        Args:
            timeout: Socket timeout in seconds
            
        Returns:
            Parsed protocol message or None if failed
        """
        try:
            self.socket.settimeout(timeout)
            data = b''
            while b'\n' not in data:
                chunk = self.socket.recv(4096)
                if not chunk:
                    logger.warning("Connection closed by server")
                    return None
                data += chunk
            
            json_str = data.split(b'\n')[0].decode('utf-8')
            msg = protocol.parse_message(json_str)
            logger.info(f"Received {msg.type}: {json_str[:100]}")
            return msg
        except socket.timeout:
            logger.error("Socket timeout")
            return None
        except Exception as e:
            logger.error(f"Failed to receive message: {e}")
            return None
    
    def connect(self) -> bool:
        """
        Connect to the secure chat server.
        
        Protocol flow:
        1. Send HelloMessage with certificate
        2. Receive ServerHelloMessage
        3. DH exchange for temporary key
        4. Send encrypted register or login message
        5. Establish session key via second DH exchange
        
        Returns:
            True if successfully authenticated, False otherwise
        """
        try:
            # Load credentials
            if not self.load_credentials():
                return False
            
            # Create socket and connect
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((SERVER_HOST, SERVER_PORT))
            logger.info(f"Connected to {SERVER_HOST}:{SERVER_PORT}")
            
            # Step 1: Send hello message
            logger.info("Step 1: Sending hello message")
            client_nonce = utils.b64e(os.urandom(16))
            hello_msg = protocol.HelloMessage(
                client_cert=self.cert_pem,
                nonce=client_nonce
            )
            
            if not self.send_message(hello_msg):
                return False
            
            # Step 2: Receive server hello
            server_hello = self.recv_message()
            if not isinstance(server_hello, protocol.ServerHelloMessage):
                logger.error("Expected ServerHelloMessage")
                return False
            
            logger.info("Step 2: Received server hello")
            self.server_cert_pem = server_hello.server_cert
            
            # Validate server certificate
            try:
                pki.validate_certificate(self.server_cert_pem, CA_CERT_PATH)
                logger.info("Server certificate validated")
            except Exception as e:
                logger.error(f"Server certificate validation failed: {e}")
                return False
            
            # Step 3: DH exchange for temporary key
            logger.info("Step 3: DH key exchange for credential encryption")
            dh_msg = self.recv_message()
            if not isinstance(dh_msg, protocol.DHClientMessage):
                logger.error("Expected DHClientMessage")
                return False
            
            # Compute shared secret
            g = dh_msg.g
            p = dh_msg.p
            A = dh_msg.A
            
            b = dh.dh_private()
            B = dh.dh_public(g, b, p)
            
            Ks = dh.dh_shared_secret(A, b, p)
            self.temp_dh_key = dh.derive_session_key(Ks)
            
            # Send DH response
            dh_response = protocol.DHServerMessage(B=B)
            if not self.send_message(dh_response):
                return False
            
            logger.info("Temporary encryption key established")
            
            # Step 4: Send encrypted register or login message
            auth_type = self.get_auth_type()
            if auth_type == 'register':
                if not self.register():
                    return False
            elif auth_type == 'login':
                if not self.login():
                    return False
            else:
                logger.error("Unknown auth type")
                return False
            
            # Step 5: Session key establishment via second DH exchange
            logger.info("Step 5: DH key exchange for session key")
            dh_msg = self.recv_message()
            if not isinstance(dh_msg, protocol.DHClientMessage):
                logger.error("Expected DHClientMessage for session key")
                return False
            
            g = dh_msg.g
            p = dh_msg.p
            A = dh_msg.A
            
            b = dh.dh_private()
            B = dh.dh_public(g, b, p)
            
            Ks = dh.dh_shared_secret(A, b, p)
            self.session_key = dh.derive_session_key(Ks)
            
            dh_response = protocol.DHServerMessage(B=B)
            if not self.send_message(dh_response):
                return False
            
            logger.info("Session key established")
            self.is_authenticated = True
            
            # Initialize transcript
            transcript_dir = Path('transcripts')
            transcript_dir.mkdir(exist_ok=True)
            self.session_id = utils.b64e(os.urandom(8))
            transcript_file = transcript_dir / f"{self.session_id}_client.txt"
            self.transcript = transcript.Transcript(str(transcript_file))
            
            return True
            
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            return False
    
    def get_auth_type(self) -> str:
        """
        Ask user whether to register or login.
        
        Returns:
            'register' or 'login'
        """
        while True:
            choice = input("\nAuthentication Type (register/login): ").strip().lower()
            if choice in ('register', 'login'):
                return choice
            print("Invalid choice. Please enter 'register' or 'login'.")
    
    def register(self) -> bool:
        """
        Handle client registration.
        
        Steps:
        1. Get email, username from user
        2. Generate random salt
        3. Hash password with salt
        4. Create RegisterMessage
        5. Encrypt with temp_dh_key
        6. Send EncryptedMessage
        7. Receive AuthSuccessMessage
        
        Returns:
            True if registration successful, False otherwise
        """
        try:
            logger.info("Registration flow started")
            
            email = input("Email: ").strip()
            username = input("Username: ").strip()
            password = input("Password: ").strip()
            
            # Generate salt (server will store this and use it for verification)
            salt_bytes = os.urandom(16)
            salt = utils.b64e(salt_bytes)
            # Compute hash: base64(SHA256(salt_bytes + password_bytes))
            # This matches what server will compute during login verification
            pwd_hash_bytes = utils.sha256_bytes(salt_bytes + password.encode('utf-8'))
            pwd_hash = utils.b64e(pwd_hash_bytes)
            
            # Create register message
            reg_msg = protocol.RegisterMessage(
                type='register',
                email=email,
                username=username,
                pwd=pwd_hash,
                salt=salt
            )
            
            # Encrypt the message
            plaintext_json = protocol.serialize_message(reg_msg)
            plaintext_bytes = plaintext_json.encode('utf-8')
            ct_bytes = aes.aes_encrypt(self.temp_dh_key, plaintext_bytes)
            ct_b64 = utils.b64e(ct_bytes)
            
            # Send encrypted message
            encrypted_msg = protocol.EncryptedMessage(
                seqno=1,
                ts=utils.now_ms(),
                ct=ct_b64,
                sig=''  # Signature will be added in Task 11
            )
            
            if not self.send_message(encrypted_msg):
                return False
            
            # Wait for response
            response = self.recv_message()
            if isinstance(response, protocol.AuthSuccessMessage):
                logger.info(f"Registration successful: {response.message}")
                return True
            elif isinstance(response, protocol.ErrorMessage):
                logger.error(f"Registration failed: {response.message}")
                return False
            else:
                logger.error(f"Unexpected response: {response.type}")
                return False
                
        except Exception as e:
            logger.error(f"Registration error: {e}")
            return False
    
    def login(self) -> bool:
        """
        Handle client login.
        
        Steps:
        1. Get email and password from user
        2. Hash password (server has salt stored)
        3. Create LoginMessage
        4. Encrypt with temp_dh_key
        5. Send EncryptedMessage
        6. Receive AuthSuccessMessage
        
        Returns:
            True if login successful, False otherwise
        """
        try:
            logger.info("Login flow started")
            
            email = input("Email: ").strip()
            password = input("Password: ").strip()
            
            # Create login message (salt is stored on server)
            # Send plaintext password - server will hash it with the stored salt
            login_msg = protocol.LoginMessage(
                type='login',
                email=email,
                pwd=password,  # Server will compute hash with stored salt
                nonce=utils.b64e(os.urandom(16))
            )
            
            # Encrypt the message
            plaintext_json = protocol.serialize_message(login_msg)
            plaintext_bytes = plaintext_json.encode('utf-8')
            ct_bytes = aes.aes_encrypt(self.temp_dh_key, plaintext_bytes)
            ct_b64 = utils.b64e(ct_bytes)
            
            # Send encrypted message
            encrypted_msg = protocol.EncryptedMessage(
                seqno=1,
                ts=utils.now_ms(),
                ct=ct_b64,
                sig=''  # Signature will be added in Task 11
            )
            
            if not self.send_message(encrypted_msg):
                return False
            
            # Wait for response
            response = self.recv_message()
            if isinstance(response, protocol.AuthSuccessMessage):
                logger.info(f"Login successful: {response.message}")
                return True
            elif isinstance(response, protocol.ErrorMessage):
                logger.error(f"Login failed: {response.message}")
                return False
            else:
                logger.error(f"Unexpected response: {response.type}")
                return False
                
        except Exception as e:
            logger.error(f"Login error: {e}")
            return False
    
    def _process_encrypted_message(self, msg: protocol.EncryptedMessage) -> bool:
        """
        Process an encrypted message from server with signature verification.
        
        Protocol:
        1. Check seqno is strictly increasing (replay protection)
        2. Verify RSA signature over SHA256(seqno||ts||ct)
        3. Decrypt ciphertext using session key
        4. Remove PKCS#7 padding
        5. Display plaintext
        
        Args:
            msg: EncryptedMessage to process
            
        Returns:
            True if successful, False if replay/verification failed
        """
        try:
            # Step 1: Replay protection - check strictly increasing seqno
            if msg.seqno < self.expected_server_seqno:
                logger.warning(f"REPLAY: seqno={msg.seqno}, expected>={self.expected_server_seqno}")
                return False
            
            self.expected_server_seqno = msg.seqno + 1
            
            # Step 2: Signature verification
            # Load server certificate from initial hello exchange
            from app.crypto import pki as pki_module
            
            # Reconstruct the data that was signed: seqno||ts||ct
            signed_data = f"{msg.seqno}||{msg.ts}||{msg.ct}".encode('utf-8')
            sig_bytes = utils.b64d(msg.sig)
            
            # We need server's certificate - load from file if available
            try:
                with open('certs/server_cert.pem', 'r') as f:
                    server_cert_pem = f.read()
            except FileNotFoundError:
                logger.error("Server certificate not found")
                return False
            
            if not sign.rsa_verify(server_cert_pem, signed_data, sig_bytes):
                logger.warning(f"SIG_FAIL: Signature verification failed for seqno={msg.seqno}")
                return False
            
            logger.info(f"Signature verified for seqno={msg.seqno}")
            
            # Step 3: Decrypt ciphertext
            ct_bytes = utils.b64d(msg.ct)
            plaintext_bytes = aes.aes_decrypt(self.session_key, ct_bytes)
            
            # Step 4: Remove PKCS#7 padding and display
            plaintext = plaintext_bytes.decode('utf-8')
            logger.info(f"<<< [From Server] seqno={msg.seqno}: {plaintext}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error processing server message: {e}")
            return False
    
    def interactive_chat(self):
        """
        Interactive chat mode after authentication.
        
        Allows user to:
        - Send encrypted, signed messages
        - Receive and verify signed messages
        - Type 'quit' to exit and request session receipt
        """
        if not self.is_authenticated:
            logger.error("Not authenticated")
            return
        
        logger.info("Entering interactive chat mode. Type 'quit' to exit.")
        
        # Initialize message sequence number for this session
        self.seqno = 1
        self.expected_server_seqno = 1
        
        # Initialize local transcript for non-repudiation
        # Format: seqno|ts|ct|sig|peer_fingerprint (one per line)
        from pathlib import Path
        import tempfile
        transcripts_dir = Path("transcripts")
        transcripts_dir.mkdir(exist_ok=True)
        # Client-side transcript: logged messages we send
        timestamp = utils.now_ms()
        client_transcript_file = transcripts_dir / f"client_{timestamp}.txt"
        self.client_transcript = transcript.Transcript(str(client_transcript_file))
        self.first_seqno = None
        self.last_seqno = None
        
        # Start receive thread
        def receive_loop():
            while True:
                msg = self.recv_message(timeout=None)
                if msg is None:
                    break
                
                if isinstance(msg, protocol.EncryptedMessage):
                    # Verify and decrypt server message
                    self._process_encrypted_message(msg)
                elif isinstance(msg, protocol.ErrorMessage):
                    logger.error(f"[Error] {msg.code}: {msg.message}")
                elif isinstance(msg, protocol.SessionReceipt):
                    logger.info(f"[Receipt from server]")
                    logger.info(f"  Messages: {msg.first_seq}-{msg.last_seq}")
                    logger.info(f"  Transcript hash: {msg.transcript_sha256}")
                    logger.info(f"  Signature (b64): {msg.sig[:32]}...")
                else:
                    logger.info(f"[{msg.type}] {msg}")
        
        receive_thread = threading.Thread(target=receive_loop, daemon=True)
        receive_thread.start()
        
        try:
            while True:
                msg_text = input("\nMessage (or 'quit'): ").strip()
                
                if msg_text.lower() == 'quit':
                    logger.info("Exiting chat, generating and sending client receipt")
                    
                    # Generate client receipt if any messages were sent
                    if self.first_seqno is not None and self.last_seqno is not None:
                        # Compute transcript hash
                        transcript_hash_hex = self.client_transcript.compute_hash()
                        
                        # Sign with client private key
                        with open(CLIENT_KEY_PATH, 'r') as f:
                            client_key_pem = f.read()
                        
                        transcript_hash_bytes = bytes.fromhex(transcript_hash_hex)
                        sig_bytes = sign.rsa_sign(client_key_pem, transcript_hash_bytes)
                        sig_b64 = utils.b64e(sig_bytes)
                        
                        # Send client receipt
                        client_receipt = protocol.SessionReceipt(
                            peer='client',
                            first_seq=self.first_seqno,
                            last_seq=self.last_seqno,
                            transcript_sha256=transcript_hash_hex,
                            sig=sig_b64
                        )
                        logger.info(f"Sending client receipt: {self.first_seqno}-{self.last_seqno}")
                        self.send_message(client_receipt)
                    
                    break
                
                if not msg_text:
                    continue
                
                # Encrypt plaintext message
                plaintext_bytes = msg_text.encode('utf-8')
                ct_bytes = aes.aes_encrypt(self.session_key, plaintext_bytes)
                ct_b64 = utils.b64e(ct_bytes)
                
                # Sign the message: RSA_SIGN(SHA256(seqno||ts||ct))
                ts = utils.now_ms()
                signed_data = f"{self.seqno}||{ts}||{ct_b64}".encode('utf-8')
                
                with open(CLIENT_KEY_PATH, 'r') as f:
                    client_key_pem = f.read()
                
                from app.crypto import sign
                sig_bytes = sign.rsa_sign(client_key_pem, signed_data)
                sig_b64 = utils.b64e(sig_bytes)
                
                # Create and send signed encrypted message
                encrypted_msg = protocol.EncryptedMessage(
                    seqno=self.seqno,
                    ts=ts,
                    ct=ct_b64,
                    sig=sig_b64
                )
                
                # Track first and last seqno
                if self.first_seqno is None:
                    self.first_seqno = self.seqno
                self.last_seqno = self.seqno
                
                # Log to client transcript for non-repudiation
                server_cert_fp = utils.sha256_hex(self.server_cert_pem.encode('utf-8'))[:16] if hasattr(self, 'server_cert_pem') else "unknown"
                self.client_transcript.log_message(
                    seqno=self.seqno,
                    timestamp=ts,
                    ciphertext=ct_b64,
                    signature=sig_b64,
                    peer_fingerprint=server_cert_fp
                )
                
                logger.info(f">>> [To Server] seqno={self.seqno}: {msg_text}")
                self.send_message(encrypted_msg)
                self.seqno += 1
                
        except KeyboardInterrupt:
            logger.info("Chat interrupted")
        except Exception as e:
            logger.error(f"Chat error: {e}")
    
    def run(self):
        """Main client workflow."""
        try:
            # Connect and authenticate
            if not self.connect():
                logger.error("Failed to connect and authenticate")
                return
            
            logger.info("Successfully authenticated!")
            
            # Enter interactive mode
            self.interactive_chat()
            
        except Exception as e:
            logger.error(f"Client error: {e}")
        finally:
            if self.socket:
                self.socket.close()
                logger.info("Connection closed")


def main():
    """Entry point for client."""
    try:
        # Get certificate paths
        print("SecureChat Client")
        print("-" * 50)
        cert_path = input("Certificate path (default: certs/client_cert.pem): ").strip() or "certs/client_cert.pem"
        key_path = input("Key path (default: certs/client_key.pem): ").strip() or "certs/client_key.pem"
        
        # Verify files exist
        if not os.path.exists(cert_path):
            print(f"Error: Certificate not found: {cert_path}")
            sys.exit(1)
        
        if not os.path.exists(key_path):
            print(f"Error: Key not found: {key_path}")
            sys.exit(1)
        
        # Create and run client
        client = SecureClient(cert_path, key_path)
        client.run()
        
    except KeyboardInterrupt:
        logger.info("Client interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
