"""MySQL users table + salted SHA-256 hashing (no chat message storage)."""

import os
import sys
import hashlib
import pymysql
from typing import Optional, Tuple
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", "3306"))
DB_USER = os.getenv("DB_USER", "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
DB_NAME = os.getenv("DB_NAME", "securechat")


class DatabaseError(Exception):
    """Raised when database operations fail."""
    pass


def get_connection():
    """
    Establish MySQL connection.
    
    Returns:
        pymysql connection
        
    Raises:
        DatabaseError if connection fails
    """
    try:
        conn = pymysql.connect(
            host=DB_HOST,
            port=DB_PORT,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME,
            autocommit=False
        )
        return conn
    except pymysql.Error as e:
        raise DatabaseError(f"Failed to connect to MySQL: {e}")


def init_database():
    """
    Initialize database schema (create users table if not exists).
    """
    try:
        conn = get_connection()
        cursor = conn.cursor()
        
        # Create users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                username VARCHAR(255) UNIQUE NOT NULL,
                salt VARBINARY(16) NOT NULL,
                pwd_hash CHAR(64) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        conn.commit()
        print("[+] Database initialized successfully")
        
    except pymysql.Error as e:
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
    
    try:
        conn = get_connection()
        cursor = conn.cursor()
        
        if email:
            cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
        else:
            cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
        
        result = cursor.fetchone()
        return result is not None
        
    except pymysql.Error as e:
        raise DatabaseError(f"Failed to check user existence: {e}")
    finally:
        if conn:
            conn.close()


def register_user(email: str, username: str, password: str, salt: bytes) -> bool:
    """
    Register a new user with salted password hash.
    
    Args:
        email: user email
        username: username
        password: plaintext password
        salt: 16-byte random salt
        
    Returns:
        True if registration successful
        
    Raises:
        DatabaseError if user already exists or DB error
    """
    if user_exists(email=email) or user_exists(username=username):
        raise DatabaseError("Email or username already registered")
    
    # Compute pwd_hash = hex(SHA256(salt || password))
    pwd_bytes = password.encode('utf-8')
    hash_input = salt + pwd_bytes
    pwd_hash = hashlib.sha256(hash_input).hexdigest()
    
    try:
        conn = get_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s)",
            (email, username, salt, pwd_hash)
        )
        conn.commit()
        return True
        
    except pymysql.Error as e:
        raise DatabaseError(f"Failed to register user: {e}")
    finally:
        if conn:
            conn.close()


def verify_login(email: str, password: str) -> Tuple[bool, Optional[bytes]]:
    """
    Verify user login by email and password.
    
    Args:
        email: user email
        password: plaintext password
        
    Returns:
        (success: bool, salt: bytes or None)
        
    Raises:
        DatabaseError if DB error
    """
    try:
        conn = get_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT salt, pwd_hash FROM users WHERE email = %s", (email,))
        result = cursor.fetchone()
        
        if not result:
            return False, None
        
        stored_salt, stored_hash = result
        
        # Recompute hash
        pwd_bytes = password.encode('utf-8')
        computed_hash = hashlib.sha256(stored_salt + pwd_bytes).hexdigest()
        
        # Constant-time comparison
        import hmac
        match = hmac.compare_digest(computed_hash, stored_hash)
        
        if match:
            return True, stored_salt
        else:
            return False, None
            
    except pymysql.Error as e:
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
        
    except pymysql.Error as e:
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
