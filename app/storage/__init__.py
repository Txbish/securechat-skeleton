"""Storage layer: database and transcript management."""

from .db import (
    get_connection,
    init_database,
    user_exists,
    register_user,
    verify_login,
    get_user,
    DatabaseError,
)
from .transcript import Transcript

__all__ = [
    "get_connection",
    "init_database",
    "user_exists",
    "register_user",
    "verify_login",
    "get_user",
    "DatabaseError",
    "Transcript",
]
