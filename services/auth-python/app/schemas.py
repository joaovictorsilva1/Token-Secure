from pydantic import BaseModel, EmailStr
class RegisterIn(BaseModel):
    email: EmailStr
    password: str
class LoginIn(BaseModel):
    email: EmailStr
    password: str
    totp: str | None = None
class TokenOut(BaseModel):
    access_token: str
    refresh_token: str | None = None
    token_type: str = "bearer"
class MeOut(BaseModel):
    id: int
    email: EmailStr
    role: str
    totp_enabled: bool