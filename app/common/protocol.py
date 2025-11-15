"""Pydantic models for SecureChat protocol messages."""

from typing import Optional
from pydantic import BaseModel, Field
import json


class HelloMessage(BaseModel):
    """Client hello: sends certificate and nonce for freshness."""
    type: str = Field(default="hello")
    client_cert: str  # PEM-encoded certificate
    nonce: str  # base64-encoded random bytes


class ServerHelloMessage(BaseModel):
    """Server hello: sends certificate and nonce."""
    type: str = Field(default="server_hello")
    server_cert: str  # PEM-encoded certificate
    nonce: str  # base64-encoded random bytes


class RegisterMessage(BaseModel):
    """Registration: encrypted email, username, password hash, salt."""
    type: str = Field(default="register")
    email: str
    username: str
    pwd: str  # base64(sha256(salt || password))
    salt: str  # base64-encoded 16-byte salt


class LoginMessage(BaseModel):
    """Login: encrypted email and password hash."""
    type: str = Field(default="login")
    email: str
    pwd: str  # plaintext password (server will compute hash with stored salt)
    nonce: str  # base64-encoded random bytes for freshness


class DHClientMessage(BaseModel):
    """DH client initiates key exchange: sends p, g, and public value A."""
    type: str = Field(default="dh_client")
    g: int  # generator
    p: int  # prime
    A: int  # public value g^a mod p


class DHServerMessage(BaseModel):
    """DH server responds: sends public value B."""
    type: str = Field(default="dh_server")
    B: int  # public value g^b mod p


class EncryptedMessage(BaseModel):
    """Encrypted chat message with signature."""
    type: str = Field(default="msg")
    seqno: int  # sequence number (replay protection)
    ts: int  # timestamp in ms (freshness)
    ct: str  # base64-encoded ciphertext
    sig: str  # base64-encoded RSA signature


class SessionReceipt(BaseModel):
    """Session receipt: proof of communication for non-repudiation."""
    type: str = Field(default="receipt")
    peer: str  # "client" or "server"
    first_seq: int  # first message sequence number
    last_seq: int  # last message sequence number
    transcript_sha256: str  # hex-encoded SHA-256 of transcript
    sig: str  # base64-encoded RSA signature over transcript hash


class ErrorMessage(BaseModel):
    """Error response."""
    type: str = Field(default="error")
    code: str  # e.g., "BAD_CERT", "SIG_FAIL", "REPLAY", "AUTH_FAIL"
    message: str  # human-readable description


class AuthSuccessMessage(BaseModel):
    """Authentication success acknowledgment."""
    type: str = Field(default="auth_success")
    message: str


class ProtocolMessage(BaseModel):
    """Union-like wrapper for polymorphic deserialization."""
    # We'll use a factory method instead
    pass


def parse_message(json_str: str) -> BaseModel:
    """
    Parse a JSON message string and return appropriate Pydantic model instance.
    
    Args:
        json_str: JSON string message
        
    Returns:
        Pydantic model instance
        
    Raises:
        ValueError if message type is unknown or JSON is invalid
    """
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON: {e}")
    
    msg_type = data.get("type")
    
    if msg_type == "hello":
        return HelloMessage(**data)
    elif msg_type == "server_hello":
        return ServerHelloMessage(**data)
    elif msg_type == "register":
        return RegisterMessage(**data)
    elif msg_type == "login":
        return LoginMessage(**data)
    elif msg_type == "dh_client":
        return DHClientMessage(**data)
    elif msg_type == "dh_server":
        return DHServerMessage(**data)
    elif msg_type == "msg":
        return EncryptedMessage(**data)
    elif msg_type == "receipt":
        return SessionReceipt(**data)
    elif msg_type == "error":
        return ErrorMessage(**data)
    elif msg_type == "auth_success":
        return AuthSuccessMessage(**data)
    else:
        raise ValueError(f"Unknown message type: {msg_type}")


def serialize_message(msg: BaseModel) -> str:
    """
    Serialize a Pydantic model to JSON string.
    
    Args:
        msg: Pydantic model instance
        
    Returns:
        JSON string
    """
    return msg.model_dump_json(exclude_none=True)
