"""Small authentication module used for the DevOps TP N°3."""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from typing import Any

MAX_ATTEMPTS = 3
LOCKOUT_SECONDS = 300
PBKDF2_ITERATIONS = 200_000

# username -> stored password value
users: dict[str, str] = {}

# username -> number of consecutive failed attempts
attempts: dict[str, int] = {}

# username -> Unix timestamp at which the lockout expires
blocked_until: dict[str, float] = {}

GENERIC_ERROR = "Identifiants incorrects"


def _valid_username(username: Any) -> bool:
    if not isinstance(username, str):
        return False
    if not (3 <= len(username) <= 32):
        return False
    return all(ch.isalnum() or ch in "._-" for ch in username)


def _valid_password(password: Any) -> bool:
    return isinstance(password, str) and 12 <= len(password) <= 128


def _hash_password(password: str) -> str:
    """Hash the password with PBKDF2-SHA256 and a random salt."""
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
    )
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


def _verify_password(password: str, encoded_hash: str) -> bool:
    try:
        algo, iterations, salt_hex, digest_hex = encoded_hash.split("$")
        if algo != "pbkdf2_sha256":
            return False
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
        candidate = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, int(iterations)
        )
    except ValueError:
        return False
    return hmac.compare_digest(candidate, expected)


def register_user(username: Any, password: Any) -> bool:
    """Register a user. Return False for invalid or duplicate credentials."""
    if not _valid_username(username) or not _valid_password(password):
        return False
    if username in users:
        return False

    users[username] = _hash_password(password)
    attempts.pop(username, None)
    blocked_until.pop(username, None)
    return True


def authenticate(username: Any, password: Any) -> dict[str, Any]:
    """Authenticate a user and return a result dictionary."""
    # Reject malformed input.
    if not _valid_username(username) or not isinstance(password, str):
        return {"success": False, "message": GENERIC_ERROR}

    now = time.time()
    if blocked_until.get(username, 0) > now:
        return {"success": False, "message": GENERIC_ERROR}

    encoded_hash = users.get(username)

    if encoded_hash is None:
        return {"success": False, "message": GENERIC_ERROR}

    if not _verify_password(password, encoded_hash):
        _record_failure(username, now)
        return {"success": False, "message": GENERIC_ERROR}

    attempts.pop(username, None)
    blocked_until.pop(username, None)
    return {"success": True, "message": "Connexion reussie"}


def _record_failure(username: str, now: float) -> None:
    attempts[username] = attempts.get(username, 0) + 1
    if attempts[username] >= MAX_ATTEMPTS:
        blocked_until[username] = now + LOCKOUT_SECONDS


def reset_attempts() -> None:
    """Clear lockout state. Intended for tests and controlled administration."""
    attempts.clear()
    blocked_until.clear()


def reset_state() -> None:
    """Clear all in-memory state. Intended for isolated automated tests."""
    users.clear()
    reset_attempts()