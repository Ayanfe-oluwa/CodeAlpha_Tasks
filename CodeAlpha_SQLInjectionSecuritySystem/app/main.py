
import os
from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from app.database import Base, engine, get_db
from app.models import User, SecurityEvent
from app.schemas import UserRegister, UserLogin, SecurityScanRequest
from app.security import hash_password, verify_password
from app.encryption import encrypt_data, decrypt_data
from app.detection import detect_sql_injection




security_scheme = HTTPBearer()


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title="SecureGuard",
    description="SQL Injection Detection and Data Protection System",
    version="1.0.0",
    lifespan=lifespan
)

STATIC_DIR = BASE_DIR / "static"

app.mount(
    "/static",
    StaticFiles(directory=STATIC_DIR),
    name="static"
)


def log_security_event(
    db: Session,
    event_type: str,
    severity: str,
    description: str,
    user_id=None
):
    event = SecurityEvent(
        user_id=user_id,
        event_type=event_type,
        severity=severity,
        description=description
    )

    db.add(event)
    db.commit()


def inspect_input(db: Session, value: str):
    result = detect_sql_injection(value)

    if result["is_suspicious"]:
        log_security_event(
            db,
            "SQL_INJECTION_ATTEMPT",
            "HIGH",
            "Suspicious input pattern detected."
        )

        raise HTTPException(
            status_code=400,
            detail="Suspicious input detected. Request rejected."
        )


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
    db: Session = Depends(get_db)
):
    from app.auth_tokens import decode_access_token

    payload = decode_access_token(credentials.credentials)

    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired authentication token."
        )

    user = db.query(User).filter(
        User.id == payload["user_id"]
    ).first()

    if not user:
        raise HTTPException(
            status_code=401,
            detail="User account not found."
        )

    return user


@app.get("/")
def home():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health")
def health():
    return {"status": "healthy", "application": "SecureGuard"}


@app.post("/register", status_code=201)
def register_user(
    data: UserRegister,
    db: Session = Depends(get_db)
):
    inspect_input(db, data.email)
    inspect_input(db, data.sensitive_data)

    existing_user = db.query(User).filter(
        User.email == data.email
    ).first()

    if existing_user:
        raise HTTPException(
            status_code=409,
            detail="An account with this email already exists."
        )

    user = User(
        email=data.email,
        password_hash=hash_password(data.password),
        encrypted_data=encrypt_data(data.sensitive_data)
    )

    try:
        db.add(user)
        db.commit()
        db.refresh(user)

    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="An account with this email already exists."
        )

    log_security_event(
        db,
        "USER_REGISTERED",
        "LOW",
        "New user account registered.",
        user.id
    )

    return {
        "message": "Account created successfully.",
        "user_id": user.id
    }


@app.post("/login")
def login_user(
    data: UserLogin,
    db: Session = Depends(get_db)
):
    inspect_input(db, data.email)

    user = db.query(User).filter(
        User.email == data.email
    ).first()

    if not user or not verify_password(
        data.password,
        user.password_hash
    ):
        log_security_event(
            db,
            "LOGIN_FAILED",
            "MEDIUM",
            "Invalid login attempt."
        )

        raise HTTPException(
            status_code=401,
            detail="Invalid email or password."
        )

    from app.auth_tokens import create_access_token

    token = create_access_token(user.id)

    log_security_event(
        db,
        "LOGIN_SUCCESS",
        "LOW",
        "User logged in successfully.",
        user.id
    )

    return {
        "access_token": token,
        "token_type": "bearer"
    }


@app.get("/my-data")
def get_my_data(
    current_user: User = Depends(get_current_user)
):
    sensitive_data = decrypt_data(current_user.encrypted_data)

    return {
        "email": current_user.email,
        "sensitive_data": sensitive_data
    }


@app.get("/security-events")
def get_security_events(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    events = db.query(SecurityEvent).filter(
    SecurityEvent.user_id == current_user.id
).order_by(
    SecurityEvent.created_at.desc()
).limit(100).all()

    return [
        {
            "id": event.id,
            "event_type": event.event_type,
            "severity": event.severity,
            "description": event.description,
            "created_at": event.created_at
        }
        for event in events
    ]

@app.post("/security-check")
def security_check(
    data: SecurityScanRequest,
    db: Session = Depends(get_db)
):
    result = detect_sql_injection(data.input)

    if result["is_suspicious"]:
        log_security_event(
            db=db,
            event_type="SQL_INJECTION_ATTEMPT",
            severity="HIGH",
            description=(
                "Suspicious SQL injection patterns detected. "
                f"Matched {len(result['matched_patterns'])} pattern(s)."
            )
        )

        return {
            "is_suspicious": True,
            "message": "Potential SQL injection patterns detected.",
            "matched_patterns": len(result["matched_patterns"])
        }

    return {
        "is_suspicious": False,
        "message": "No suspicious SQL injection patterns detected.",
        "matched_patterns": 0
    }
