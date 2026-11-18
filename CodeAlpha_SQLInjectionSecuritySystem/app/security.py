
from argon2 import PasswordHasher
from argon2.exceptions import (
    VerifyMismatchError,
    VerificationError,
    InvalidHashError
)

password_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    """
    Securely hash a password using Argon2.
    """

    if not isinstance(password, str) or len(password) < 8:
        raise ValueError("Password must contain at least 8 characters.")

    return password_hasher.hash(password)


def verify_password(
    plain_password: str,
    stored_hash: str
) -> bool:
    """
    Verify a password against its stored Argon2 hash.
    """

    try:
        return password_hasher.verify(
            stored_hash,
            plain_password
        )

    except (
        VerifyMismatchError,
        VerificationError,
        InvalidHashError
    ):
        return False
