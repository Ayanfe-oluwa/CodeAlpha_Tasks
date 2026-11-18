
import os
from datetime import datetime, timedelta, timezone

import jwt
from jwt.exceptions import InvalidTokenError


ALGORITHM = "HS256"


def get_jwt_secret() -> str:
    secret = os.getenv("JWT_SECRET_KEY")

    if not secret or len(secret) < 32:
        raise RuntimeError(
            "JWT_SECRET_KEY is missing or too short. "
            "Configure a strong secret in your .env file."
        )

    return secret


def create_access_token(user_id: int) -> str:
    try:
        expiry_minutes = int(
            os.getenv("TOKEN_EXPIRE_MINUTES", "30")
        )
    except ValueError as exc:
        raise RuntimeError(
            "TOKEN_EXPIRE_MINUTES must be an integer."
        ) from exc

    if not 1 <= expiry_minutes <= 1440:
        raise RuntimeError(
            "TOKEN_EXPIRE_MINUTES must be between 1 and 1440."
        )

    now = datetime.now(timezone.utc)

    payload = {
        "user_id": user_id,
        "iat": now,
        "exp": now + timedelta(minutes=expiry_minutes)
    }

    return jwt.encode(
        payload,
        get_jwt_secret(),
        algorithm=ALGORITHM
    )


def decode_access_token(token: str):
    try:
        payload = jwt.decode(
            token,
            get_jwt_secret(),
            algorithms=[ALGORITHM],
            options={"require": ["exp", "iat", "user_id"]}
        )

        user_id = payload.get("user_id")

        if not isinstance(user_id, int) or user_id <= 0:
            return None

        return payload

    except (InvalidTokenError, TypeError, ValueError):
        return None
