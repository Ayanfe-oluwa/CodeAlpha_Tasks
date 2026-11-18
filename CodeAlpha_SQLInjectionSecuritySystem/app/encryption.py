
import os
import base64

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def get_encryption_key() -> bytes:
    key_string = os.getenv("ENCRYPTION_KEY")

    if not key_string:
        raise RuntimeError(
            "ENCRYPTION_KEY is missing. Configure it in your environment."
        )

    try:
        key = base64.urlsafe_b64decode(key_string)
    except Exception as exc:
        raise RuntimeError("Invalid encryption key encoding.") from exc

    if len(key) != 32:
        raise RuntimeError(
            "AES-256 requires an encryption key of exactly 32 bytes."
        )

    return key


def encrypt_data(plaintext: str) -> str:
    key = get_encryption_key()
    aesgcm = AESGCM(key)

    nonce = os.urandom(12)

    ciphertext = aesgcm.encrypt(
        nonce,
        plaintext.encode("utf-8"),
        None
    )

    encrypted_value = nonce + ciphertext

    return base64.urlsafe_b64encode(
        encrypted_value
    ).decode("utf-8")


def decrypt_data(encrypted_value: str) -> str:
    key = get_encryption_key()
    aesgcm = AESGCM(key)

    try:
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_value)

        if len(encrypted_bytes) < 29:
            raise ValueError("Invalid encrypted data.")

        nonce = encrypted_bytes[:12]
        ciphertext = encrypted_bytes[12:]

        plaintext = aesgcm.decrypt(
            nonce,
            ciphertext,
            None
        )

        return plaintext.decode("utf-8")

    except Exception as exc:
        raise ValueError(
            "Unable to decrypt data. The key or encrypted data may be invalid."
        ) from exc
