
from pydantic import BaseModel, EmailStr, Field, ConfigDict


class UserRegister(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    sensitive_data: str = Field(min_length=1, max_length=500)


class UserLogin(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class UserResponse(BaseModel):
    id: int
    email: EmailStr

    model_config = ConfigDict(from_attributes=True)


class SecurityEventResponse(BaseModel):
    id: int
    event_type: str
    severity: str
    description: str

    model_config = ConfigDict(from_attributes=True)


class SecurityScanRequest(BaseModel):
    input: str = Field(
        min_length=1,
        max_length=2000,
        description="Text to inspect for suspicious SQL injection patterns."
    )
