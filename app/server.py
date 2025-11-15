"""
SecureChat Server - TCP-based secure messaging server.

Handles:
1. Client certificate validation
2. Registration/Login flow with DH key exchange
3. Encrypted message processing with signature verification
4. Session management and transcript logging
5. Session receipt generation
"""

import socket
import threading
import logging
import json
import os
import sys
from typing import Optional, Dict, Tuple
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.common import protocol, utils
from app.crypto import aes, dh, sign, pki
from app.storage import db, transcript

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)

# Server configuration
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 5555
SERVER_CERT_PATH = 'certs/server_cert.pem'
SERVER_KEY_PATH = 'certs/server_key.pem'
CA_CERT_PATH = 'certs/ca_cert.pem'


class ClientSession:
    """Manages a single client-server session."""
    
    def __init__(self, conn: socket.socket, addr: Tuple[str, int], session_id: str):
        """
        Initialize a client session.
        
        Args:
            conn: Client socket connection
            addr: Client address tuple (host, port)
            session_id: Unique session identifier
        """
        self.conn = conn
        self.addr = addr
        self.session_id = session_id
        
        # Authentication state
        self.client_cert_pem: Optional[str] = None
        self.client_email: Optional[str] = None
        self.client_username: Optional[str] = None
        self.is_authenticated = False
        
        # Cryptographic state
        self.temp_dh_key: Optional[bytes] = None  # For credential encryption
        self.session_key: Optional[bytes] = None  # For message encryption
        self.client_nonce: Optional[str] = None
        self.server_nonce: Optional[str] = None
        
        # Message tracking
        self.expected_seqno = 1
        self.transcript: Optional[transcript.Transcript] = None
        self.client_public_key_pem: Optional[str] = None
        
    def send_message(self, msg: protocol.BaseModel) -> bool:
        """
        Send a protocol message to the client.
        
        Args:
            msg: Pydantic model to send
            
        Returns:
            True if successful, False otherwise
        """
        try:
            json_str = protocol.serialize_message(msg)
            self.conn.sendall((json_str + '\n').encode('utf-8'))
            logger.info(f"[{self.session_id}] Sent {msg.type}: {json_str[:100]}")
            return True
        except Exception as e:
            logger.error(f"[{self.session_id}] Failed to send message: {e}")
            return False
    
    def recv_message(self, timeout: float = 30.0) -> Optional[protocol.BaseModel]:
        """
        Receive a protocol message from the client.
        
        Args:
            timeout: Socket timeout in seconds
            
        Returns:
            Parsed protocol message or None if failed
        """
        try:
            self.conn.settimeout(timeout)
            data = b''
            while b'\n' not in data:
                chunk = self.conn.recv(4096)
                if not chunk:
                    logger.warning(f"[{self.session_id}] Connection closed by client")
                    return None
                data += chunk
            
            json_str = data.split(b'\n')[0].decode('utf-8')
            msg = protocol.parse_message(json_str)
            logger.info(f"[{self.session_id}] Received {msg.type}: {json_str[:100]}")
            return msg
        except socket.timeout:
            logger.error(f"[{self.session_id}] Socket timeout")
            return None
        except Exception as e:
            logger.error(f"[{self.session_id}] Failed to receive message: {e}")
            return None
    
    def handle_hello(self, msg: protocol.HelloMessage) -> bool:
        """
        Handle client hello message.
        
        Steps:
        1. Validate client certificate (signature, validity, CN)
        2. Extract client public key from certificate
        3. Send server hello with own certificate
        4. Initiate DH exchange for temporary key
        
        Args:
            msg: HelloMessage from client
            
        Returns:
            True if successful, False otherwise
        """
        try:
            logger.info(f"[{self.session_id}] Processing hello from {self.addr}")
            
            # Validate client certificate
            try:
                pki.validate_certificate(msg.client_cert, CA_CERT_PATH)
            except Exception as e:
                logger.error(f"[{self.session_id}] Certificate validation failed: {e}")
                error_msg = protocol.ErrorMessage(
                    code="BAD_CERT",
                    message=f"Certificate validation failed: {e}"
                )
                self.send_message(error_msg)
                return False
            
            # Store client certificate and extract public key
            self.client_cert_pem = msg.client_cert
            self.client_nonce = msg.nonce
            
            # Extract public key from certificate for later signature verification
            try:
                self.client_public_key_pem = pki.extract_public_key(msg.client_cert)
            except Exception as e:
                logger.error(f"[{self.session_id}] Failed to extract public key: {e}")
                error_msg = protocol.ErrorMessage(
                    code="BAD_CERT",
                    message="Failed to extract public key from certificate"
                )
                self.send_message(error_msg)
                return False
            
            # Generate server hello
            self.server_nonce = utils.b64e(os.urandom(16))
            
            try:
                with open(SERVER_CERT_PATH, 'r') as f:
                    server_cert = f.read()
            except Exception as e:
                logger.error(f"[{self.session_id}] Failed to load server certificate: {e}")
                error_msg = protocol.ErrorMessage(
                    code="SERVER_ERROR",
                    message="Failed to load server certificate"
                )
                self.send_message(error_msg)
                return False
            
            server_hello = protocol.ServerHelloMessage(
                server_cert=server_cert,
                nonce=self.server_nonce
            )
            
            if not self.send_message(server_hello):
                return False
            
            # Initiate DH exchange for temporary key (for credential encryption)
            p, g = dh.dh_params()
            a = dh.dh_private()
            A = dh.dh_public(g, a, p)
            
            # Store for later shared secret computation
            self.dh_private_exp = a
            self.dh_prime = p
            self.dh_generator = g
            
            dh_msg = protocol.DHClientMessage(g=g, p=p, A=A)
            if not self.send_message(dh_msg):
                return False
            
            # Receive client's DH response
            dh_response = self.recv_message()
            if not isinstance(dh_response, protocol.DHServerMessage):
                logger.error(f"[{self.session_id}] Expected DHServerMessage")
                error_msg = protocol.ErrorMessage(
                    code="PROTOCOL_ERROR",
                    message="Expected DHServerMessage"
                )
                self.send_message(error_msg)
                return False
            
            # Compute shared secret
            B = dh_response.B
            Ks = dh.dh_shared_secret(B, a, p)
            self.temp_dh_key = dh.derive_session_key(Ks)
            
            logger.info(f"[{self.session_id}] DH temporary key established")
            return True
            
        except Exception as e:
            logger.error(f"[{self.session_id}] Error in handle_hello: {e}")
            error_msg = protocol.ErrorMessage(
                code="SERVER_ERROR",
                message=str(e)
            )
            self.send_message(error_msg)
            return False
    
    def handle_register(self, msg: protocol.EncryptedMessage) -> bool:
        """
        Handle encrypted registration message.
        
        Steps:
        1. Decrypt EncryptedMessage using temp_dh_key
        2. Parse as RegisterMessage
        3. Generate random salt (if not provided)
        4. Call db.register_user()
        5. Send auth success or error
        
        Args:
            msg: EncryptedMessage containing RegisterMessage
            
        Returns:
            True if successful, False otherwise
        """
        try:
            logger.info(f"[{self.session_id}] Processing registration")
            
            if not self.temp_dh_key:
                logger.error(f"[{self.session_id}] No DH key for decryption")
                error_msg = protocol.ErrorMessage(
                    code="PROTOCOL_ERROR",
                    message="No DH key established"
                )
                self.send_message(error_msg)
                return False
            
            # Decrypt ciphertext
            try:
                ct_bytes = utils.b64d(msg.ct)
                plaintext_bytes = aes.aes_decrypt(self.temp_dh_key, ct_bytes)
                plaintext_json = plaintext_bytes.decode('utf-8')
                reg_data = json.loads(plaintext_json)
            except Exception as e:
                logger.error(f"[{self.session_id}] Decryption failed: {e}")
                error_msg = protocol.ErrorMessage(
                    code="CRYPTO_ERROR",
                    message=f"Decryption failed: {e}"
                )
                self.send_message(error_msg)
                return False
            
            # Parse registration data
            try:
                reg_msg = protocol.RegisterMessage(**reg_data)
            except Exception as e:
                logger.error(f"[{self.session_id}] Invalid registration data: {e}")
                error_msg = protocol.ErrorMessage(
                    code="INVALID_REQUEST",
                    message=f"Invalid registration data: {e}"
                )
                self.send_message(error_msg)
                return False
            
            # Store credentials
            self.client_email = reg_msg.email
            self.client_username = reg_msg.username
            
            # Decode salt from base64
            salt_bytes = utils.b64d(reg_msg.salt)
            
            # Register user in database with pre-hashed password
            try:
                db.register_user(
                    email=reg_msg.email,
                    username=reg_msg.username,
                    pwd_hash=reg_msg.pwd,
                    salt=salt_bytes
                )
                logger.info(f"[{self.session_id}] User registered: {reg_msg.email}")
            except Exception as e:
                logger.error(f"[{self.session_id}] Registration failed: {e}")
                error_msg = protocol.ErrorMessage(
                    code="AUTH_FAIL",
                    message=f"Registration failed: {e}"
                )
                self.send_message(error_msg)
                return False
            
            # Send success
            self.is_authenticated = True
            success_msg = protocol.AuthSuccessMessage(
                message=f"Registration successful: {reg_msg.username}"
            )
            return self.send_message(success_msg)
            
        except Exception as e:
            logger.error(f"[{self.session_id}] Error in handle_register: {e}")
            error_msg = protocol.ErrorMessage(
                code="SERVER_ERROR",
                message=str(e)
            )
            self.send_message(error_msg)
            return False
    
    def handle_login(self, msg: protocol.EncryptedMessage) -> bool:
        """
        Handle encrypted login message.
        
        Steps:
        1. Decrypt EncryptedMessage using temp_dh_key
        2. Parse as LoginMessage
        3. Call db.verify_login()
        4. Send auth success or error
        
        Args:
            msg: EncryptedMessage containing LoginMessage
            
        Returns:
            True if successful, False otherwise
        """
        try:
            logger.info(f"[{self.session_id}] Processing login")
            
            if not self.temp_dh_key:
                logger.error(f"[{self.session_id}] No DH key for decryption")
                error_msg = protocol.ErrorMessage(
                    code="PROTOCOL_ERROR",
                    message="No DH key established"
                )
                self.send_message(error_msg)
                return False
            
            # Decrypt ciphertext
            try:
                ct_bytes = utils.b64d(msg.ct)
                plaintext_bytes = aes.aes_decrypt(self.temp_dh_key, ct_bytes)
                plaintext_json = plaintext_bytes.decode('utf-8')
                login_data = json.loads(plaintext_json)
            except Exception as e:
                logger.error(f"[{self.session_id}] Decryption failed: {e}")
                error_msg = protocol.ErrorMessage(
                    code="CRYPTO_ERROR",
                    message=f"Decryption failed: {e}"
                )
                self.send_message(error_msg)
                return False
            
            # Parse login data
            try:
                login_msg = protocol.LoginMessage(**login_data)
            except Exception as e:
                logger.error(f"[{self.session_id}] Invalid login data: {e}")
                error_msg = protocol.ErrorMessage(
                    code="INVALID_REQUEST",
                    message=f"Invalid login data: {e}"
                )
                self.send_message(error_msg)
                return False
            
            # Verify login credentials
            try:
                user_data = db.verify_login(
                    email=login_msg.email,
                    password=login_msg.pwd
                )
                if not user_data:
                    logger.warning(f"[{self.session_id}] Login failed for {login_msg.email}")
                    error_msg = protocol.ErrorMessage(
                        code="AUTH_FAIL",
                        message="Invalid email or password"
                    )
                    self.send_message(error_msg)
                    return False
                
                logger.info(f"[{self.session_id}] Login successful: {login_msg.email}")
            except Exception as e:
                logger.error(f"[{self.session_id}] Login verification failed: {e}")
                error_msg = protocol.ErrorMessage(
                    code="AUTH_FAIL",
                    message=f"Login verification failed: {e}"
                )
                self.send_message(error_msg)
                return False
            
            # Store credentials
            self.client_email = login_msg.email
            self.client_username = user_data.get('username', '')
            
            # Send success
            self.is_authenticated = True
            success_msg = protocol.AuthSuccessMessage(
                message=f"Login successful: {self.client_username}"
            )
            return self.send_message(success_msg)
            
        except Exception as e:
            logger.error(f"[{self.session_id}] Error in handle_login: {e}")
            error_msg = protocol.ErrorMessage(
                code="SERVER_ERROR",
                message=str(e)
            )
            self.send_message(error_msg)
            return False
    
    def _process_encrypted_message(self, msg: protocol.EncryptedMessage) -> Optional[str]:
        """
        Process an encrypted chat message with signature verification.
        
        Protocol:
        1. Check seqno is strictly increasing (replay protection)
        2. Verify RSA signature over SHA256(seqno||ts||ct)
        3. Decrypt ciphertext using session key
        4. Remove PKCS#7 padding
        5. Log to transcript
        6. Display plaintext to server console
        
        Args:
            msg: EncryptedMessage to process
            
        Returns:
            Error code if processing failed, None if successful
        """
        try:
            # Step 1: Replay protection - check strictly increasing seqno
            if msg.seqno < self.expected_seqno:
                logger.warning(f"[{self.session_id}] Replay detected: seqno={msg.seqno}, expected>={self.expected_seqno}")
                return "REPLAY"
            
            self.expected_seqno = msg.seqno + 1
            
            # Step 2: Signature verification
            # Reconstruct the data that was signed: seqno||ts||ct
            signed_data = f"{msg.seqno}||{msg.ts}||{msg.ct}".encode('utf-8')
            sig_bytes = utils.b64d(msg.sig)
            
            if not sign.rsa_verify(self.client_cert_pem, signed_data, sig_bytes):
                logger.warning(f"[{self.session_id}] Signature verification failed for seqno={msg.seqno}")
                return "SIG_FAIL"
            
            logger.info(f"[{self.session_id}] Signature verified for seqno={msg.seqno}")
            
            # Step 3: Decrypt ciphertext
            ct_bytes = utils.b64d(msg.ct)
            plaintext_bytes = aes.aes_decrypt(self.session_key, ct_bytes)
            
            # Step 4: Remove PKCS#7 padding
            plaintext = plaintext_bytes.decode('utf-8')
            logger.info(f"[{self.session_id}] <<< [Client] seqno={msg.seqno}: {plaintext}")
            
            # Step 5: Log to transcript (for non-repudiation)
            peer_cert_fp = utils.sha256_hex(self.client_cert_pem.encode('utf-8'))[:16]
            self.transcript.log_message(
                seqno=msg.seqno,
                timestamp=msg.ts,
                ciphertext=msg.ct,
                signature=msg.sig,
                peer_fingerprint=peer_cert_fp
            )
            
            return None  # Success
            
        except Exception as e:
            logger.error(f"[{self.session_id}] Error processing encrypted message: {e}")
            return "SERVER_ERROR"
    
    def _generate_and_send_receipt(self, first_seqno: int, last_seqno: int) -> bool:
        """
        Generate and send session receipt for non-repudiation.
        
        Args:
            first_seqno: First message sequence number
            last_seqno: Last message sequence number
            
        Returns:
            True if receipt sent successfully, False otherwise
        """
        try:
            # Compute transcript hash
            transcript_hash_hex = self.transcript.compute_hash()
            
            # Sign the transcript hash with server's private key
            with open(SERVER_KEY_PATH, 'r') as f:
                server_key_pem = f.read()
            
            transcript_hash_bytes = bytes.fromhex(transcript_hash_hex)
            sig_bytes = sign.rsa_sign(server_key_pem, transcript_hash_bytes)
            sig_b64 = utils.b64e(sig_bytes)
            
            # Create and send receipt
            receipt = protocol.SessionReceipt(
                peer="server",
                first_seq=first_seqno,
                last_seq=last_seqno,
                transcript_sha256=transcript_hash_hex,
                sig=sig_b64
            )
            
            logger.info(f"[{self.session_id}] Sending SessionReceipt: {first_seqno}-{last_seqno}")
            return self.send_message(receipt)
            
        except Exception as e:
            logger.error(f"[{self.session_id}] Error generating receipt: {e}")
            return False
    
    def send_signed_message(self, plaintext: str) -> bool:
        """
        Send a signed message to the client.
        
        Protocol: Create EncryptedMessage with:
        - Encrypt plaintext with session_key
        - Sign with server's RSA private key: RSA_SIGN(SHA256(seqno||ts||ct))
        - Send to client
        
        Args:
            plaintext: Message text to send
            
        Returns:
            True if sent successfully, False otherwise
        """
        try:
            # Initialize server seqno tracking if needed
            if not hasattr(self, 'server_seqno'):
                self.server_seqno = 1
            
            # Encrypt message
            plaintext_bytes = plaintext.encode('utf-8')
            ct_bytes = aes.aes_encrypt(self.session_key, plaintext_bytes)
            ct_b64 = utils.b64e(ct_bytes)
            
            # Sign the message: RSA_SIGN(SHA256(seqno||ts||ct))
            ts = utils.now_ms()
            signed_data = f"{self.server_seqno}||{ts}||{ct_b64}".encode('utf-8')
            
            with open(SERVER_KEY_PATH, 'r') as f:
                server_key_pem = f.read()
            
            sig_bytes = sign.rsa_sign(server_key_pem, signed_data)
            sig_b64 = utils.b64e(sig_bytes)
            
            # Create and send message
            encrypted_msg = protocol.EncryptedMessage(
                seqno=self.server_seqno,
                ts=ts,
                ct=ct_b64,
                sig=sig_b64
            )
            
            # Log to server's transcript for non-repudiation
            peer_cert_fp = utils.sha256_hex(self.client_cert_pem.encode('utf-8'))[:16]
            self.transcript.log_message(
                seqno=self.server_seqno,
                timestamp=ts,
                ciphertext=ct_b64,
                signature=sig_b64,
                peer_fingerprint=peer_cert_fp
            )
            
            logger.info(f"[{self.session_id}] >>> [To Client] seqno={self.server_seqno}: {plaintext}")
            self.server_seqno += 1
            return self.send_message(encrypted_msg)
            
        except Exception as e:
            logger.error(f"[{self.session_id}] Error sending signed message: {e}")
            return False
    
    def handle_client(self):
        """
        Main client connection handler.
        
        Protocol flow:
        1. Receive and process HelloMessage
        2. DH exchange for temporary key
        3. Receive and process RegisterMessage or LoginMessage
        4. Establish session key via second DH exchange (if authenticated)
        5. Message loop for encrypted communication
        6. Generate session receipt on disconnect
        """
        try:
            logger.info(f"[{self.session_id}] New connection from {self.addr}")
            
            # Step 1: Handle hello and certificate validation
            hello_msg = self.recv_message()
            if not isinstance(hello_msg, protocol.HelloMessage):
                logger.error(f"[{self.session_id}] Expected HelloMessage")
                self.conn.close()
                return
            
            if not self.handle_hello(hello_msg):
                self.conn.close()
                return
            
            # Step 2: Receive encrypted register or login message
            auth_msg = self.recv_message()
            if not isinstance(auth_msg, protocol.EncryptedMessage):
                logger.error(f"[{self.session_id}] Expected EncryptedMessage for auth")
                error_msg = protocol.ErrorMessage(
                    code="PROTOCOL_ERROR",
                    message="Expected EncryptedMessage"
                )
                self.send_message(error_msg)
                self.conn.close()
                return
            
            # Decrypt to determine if registration or login
            try:
                ct_bytes = utils.b64d(auth_msg.ct)
                plaintext_bytes = aes.aes_decrypt(self.temp_dh_key, ct_bytes)
                plaintext_json = plaintext_bytes.decode('utf-8')
                auth_data = json.loads(plaintext_json)
                auth_type = auth_data.get('type', '')
            except Exception as e:
                logger.error(f"[{self.session_id}] Failed to decrypt auth message: {e}")
                error_msg = protocol.ErrorMessage(
                    code="CRYPTO_ERROR",
                    message="Failed to decrypt auth message"
                )
                self.send_message(error_msg)
                self.conn.close()
                return
            
            # Route to register or login handler
            if auth_type == 'register':
                if not self.handle_register(auth_msg):
                    self.conn.close()
                    return
            elif auth_type == 'login':
                if not self.handle_login(auth_msg):
                    self.conn.close()
                    return
            else:
                logger.error(f"[{self.session_id}] Unknown auth type: {auth_type}")
                error_msg = protocol.ErrorMessage(
                    code="PROTOCOL_ERROR",
                    message=f"Unknown auth type: {auth_type}"
                )
                self.send_message(error_msg)
                self.conn.close()
                return
            
            # Step 3: Establish session key via second DH exchange
            logger.info(f"[{self.session_id}] Establishing session key")
            p, g = dh.dh_params()
            a = dh.dh_private()
            A = dh.dh_public(g, a, p)
            
            dh_msg = protocol.DHClientMessage(g=g, p=p, A=A)
            if not self.send_message(dh_msg):
                self.conn.close()
                return
            
            # Receive client's DH response for session key
            dh_response = self.recv_message()
            if not isinstance(dh_response, protocol.DHServerMessage):
                logger.error(f"[{self.session_id}] Expected DHServerMessage for session key")
                error_msg = protocol.ErrorMessage(
                    code="PROTOCOL_ERROR",
                    message="Expected DHServerMessage"
                )
                self.send_message(error_msg)
                self.conn.close()
                return
            
            # Compute session key
            B = dh_response.B
            Ks = dh.dh_shared_secret(B, a, p)
            self.session_key = dh.derive_session_key(Ks)
            logger.info(f"[{self.session_id}] Session key established")
            
            # Step 4: Initialize transcript logging
            transcript_dir = Path('transcripts')
            transcript_dir.mkdir(exist_ok=True)
            transcript_file = transcript_dir / f"{self.session_id}_server.txt"
            self.transcript = transcript.Transcript(str(transcript_file))
            
            # Step 5: Message loop
            logger.info(f"[{self.session_id}] Entering message loop for {self.client_email}")
            first_seqno = None
            last_seqno = None
            
            while True:
                msg = self.recv_message()
                if msg is None:
                    break
                
                if isinstance(msg, protocol.EncryptedMessage):
                    # Track message sequence numbers for receipt
                    if first_seqno is None:
                        first_seqno = msg.seqno
                    last_seqno = msg.seqno
                    
                    # Process encrypted message with signature verification
                    error_code = self._process_encrypted_message(msg)
                    if error_code:
                        error_msg = protocol.ErrorMessage(
                            code=error_code,
                            message=f"Message processing failed: {error_code}"
                        )
                        self.send_message(error_msg)
                        
                elif isinstance(msg, protocol.SessionReceipt):
                    logger.info(f"[{self.session_id}] Client requesting session receipt")
                    break
                else:
                    logger.warning(f"[{self.session_id}] Unexpected message type: {msg.type}")
            
            # Generate and send session receipt
            if first_seqno is not None and last_seqno is not None:
                self._generate_and_send_receipt(first_seqno, last_seqno)
            
            logger.info(f"[{self.session_id}] Session complete for {self.client_email}")
            
        except Exception as e:
            logger.error(f"[{self.session_id}] Error handling client: {e}")
        finally:
            self.conn.close()
            logger.info(f"[{self.session_id}] Connection closed")


class SecureServer:
    """Main secure chat server."""
    
    def __init__(self, host: str = SERVER_HOST, port: int = SERVER_PORT):
        """
        Initialize the server.
        
        Args:
            host: Server bind address
            port: Server bind port
        """
        self.host = host
        self.port = port
        self.running = False
        self.session_counter = 0
        self.sessions: Dict[str, ClientSession] = {}
    
    def start(self):
        """Start the server and listen for connections."""
        try:
            # Create server socket
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((self.host, self.port))
            server_socket.listen(5)
            
            self.running = True
            logger.info(f"Server listening on {self.host}:{self.port}")
            
            while self.running:
                try:
                    conn, addr = server_socket.accept()
                    self.session_counter += 1
                    session_id = f"S{self.session_counter:05d}"
                    
                    # Create session and handle in thread
                    session = ClientSession(conn, addr, session_id)
                    self.sessions[session_id] = session
                    
                    thread = threading.Thread(
                        target=session.handle_client,
                        daemon=True
                    )
                    thread.start()
                    
                except KeyboardInterrupt:
                    logger.info("Server shutting down...")
                    self.running = False
                    break
                except Exception as e:
                    logger.error(f"Error accepting connection: {e}")
            
            server_socket.close()
            logger.info("Server stopped")
            
        except Exception as e:
            logger.error(f"Server error: {e}")
            raise


def main():
    """Entry point for server."""
    try:
        # Verify certificates exist
        if not os.path.exists(SERVER_CERT_PATH):
            logger.error(f"Server certificate not found: {SERVER_CERT_PATH}")
            logger.error("Run: python scripts/gen_ca.py && python scripts/gen_cert.py --cn server.local --out certs/server")
            sys.exit(1)
        
        if not os.path.exists(CA_CERT_PATH):
            logger.error(f"CA certificate not found: {CA_CERT_PATH}")
            sys.exit(1)
        
        server = SecureServer()
        server.start()
        
    except KeyboardInterrupt:
        logger.info("Server interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
