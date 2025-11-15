"""PostgreSQL users table + salted SHA-256 hashing (no chat message storage)."""

import os
import sys
import hashlib
import psycopg2
from psycopg2 import sql
from typing import Optional, Dict
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", "5432"))
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
DB_NAME = os.getenv("DB_NAME", "securechat")


class DatabaseError(Exception):
    """Raised when database operations fail."""
    pass


def get_connection():
    """
    Establish PostgreSQL connection.
    
    Returns:
        psycopg2 connection
        
    Raises:
        DatabaseError if connection fails
    """
    try:
        conn = psycopg2.connect(
            host=DB_HOST,
            port=DB_PORT,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME
        )
        return conn
    except psycopg2.Error as e:
        raise DatabaseError(f"Failed to connect to PostgreSQL: {e}")


def init_database():
    """
    Initialize database schema (create users table if not exists).
    """
    conn = None
    try:
        conn = get_connection()
        cursor = conn.cursor()
        
        # Create users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                username VARCHAR(255) UNIQUE NOT NULL,
                salt BYTEA NOT NULL,
                pwd_hash CHAR(64) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        conn.commit()
        print("[+] Database initialized successfully")
        
    except psycopg2.Error as e:
        raise DatabaseError(f"Failed to initialize database: {e}")
    finally:
        if conn:
            conn.close()


def user_exists(email: str = None, username: str = None) -> bool:
    """
    Check if user exists by email or username.
    
    Args:
        email: email address to check
        username: username to check
        
    Returns:
        True if user exists, False otherwise
    """
    if not email and not username:
        raise ValueError("Must provide email or username")
    
    conn = None
    try:
        conn = get_connection()
        cursor = conn.cursor()
        
        if email:
            cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
        else:
            cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
        
        result = cursor.fetchone()
        return result is not None
        
    except psycopg2.Error as e:
        raise DatabaseError(f"Failed to check user existence: {e}")
    finally:
        if conn:
            conn.close()


def register_user(email: str, username: str, password: str = None, salt: bytes = None, pwd_hash: str = None) -> bool:
    """
    Register a new user with salted password hash.
    
    Args:
        email: user email
        username: username
        password: plaintext password (will be hashed with salt)
        salt: 16-byte random salt
        pwd_hash: pre-computed password hash (alternative to password)
        
    Returns:
        True if registration successful
        
    Raises:
        DatabaseError if user already exists or DB error
    """
    if user_exists(email=email) or user_exists(username=username):
        raise DatabaseError("Email or username already registered")
    
    # Compute pwd_hash if not provided
    if pwd_hash is None:
        if password is None:
            raise ValueError("Must provide either password or pwd_hash")
        pwd_bytes = password.encode('utf-8')
        hash_input = salt + pwd_bytes
        pwd_hash = hashlib.sha256(hash_input).hexdigest()
    
    # If password is provided but pwd_hash isn't, use the computed hash
    # If pwd_hash is provided, use it directly
    
    conn = None
    try:
        conn = get_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s)",
            (email, username, salt, pwd_hash)
        )
        conn.commit()
        return True
        
    except psycopg2.Error as e:
        raise DatabaseError(f"Failed to register user: {e}")
    finally:
        if conn:
            conn.close()


def verify_login(email: str, password: str = None, pwd_hash: str = None) -> Optional[dict]:
    """
    Verify user login by email and password (either plaintext or pre-hashed).
    
    Args:
        email: user email
        password: plaintext password
        pwd_hash: pre-computed password hash (alternative to password)
        
    Returns:
        dict with user info if login successful, None otherwise
        
    Raises:
        DatabaseError if DB error
    """
    if password is None and pwd_hash is None:
        raise ValueError("Must provide either password or pwd_hash")
    
    conn = None
    try:
        conn = get_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT id, username, salt, pwd_hash FROM users WHERE email = %s", (email,))
        result = cursor.fetchone()
        
        if not result:
            return None
        
        user_id, username, stored_salt, stored_hash = result
        
        # Compute hash to verify
        if pwd_hash is not None:
            # Direct comparison of pre-hashed password
            computed_hash = pwd_hash
        else:
            # Recompute hash from plaintext password
            pwd_bytes = password.encode('utf-8')
            computed_hash = hashlib.sha256(stored_salt + pwd_bytes).hexdigest()
        
        # Constant-time comparison
        import hmac
        match = hmac.compare_digest(computed_hash, stored_hash)
        
        if match:
            return {
                "id": user_id,
                "email": email,
                "username": username,
                "salt": stored_salt
            }
        else:
            return None
            
    except psycopg2.Error as e:
        raise DatabaseError(f"Failed to verify login: {e}")
    finally:
        if conn:
            conn.close()


def get_user(email: str = None, username: str = None) -> Optional[dict]:
    """
    Retrieve user info by email or username.
    
    Args:
        email: user email
        username: username
        
    Returns:
        dict with user info, or None if not found
    """
    if not email and not username:
        raise ValueError("Must provide email or username")
    
    conn = None
    try:
        conn = get_connection()
        cursor = conn.cursor()
        
        if email:
            cursor.execute(
                "SELECT id, email, username, created_at FROM users WHERE email = %s",
                (email,)
            )
        else:
            cursor.execute(
                "SELECT id, email, username, created_at FROM users WHERE username = %s",
                (username,)
            )
        
        result = cursor.fetchone()
        if result:
            return {
                "id": result[0],
                "email": result[1],
                "username": result[2],
                "created_at": result[3],
            }
        return None
        
    except psycopg2.Error as e:
        raise DatabaseError(f"Failed to get user: {e}")
    finally:
        if conn:
            conn.close()


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Database utilities")
    parser.add_argument("--init", action="store_true", help="Initialize database schema")
    args = parser.parse_args()
    
    if args.init:
        try:
            init_database()
        except DatabaseError as e:
            print(f"[-] Error: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        parser.print_help()
