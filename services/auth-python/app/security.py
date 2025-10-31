import hashlib, datetime
from passlib.context import CryptContext
import jwt
pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")
def hash_password(p: str) -> str:
    return pwd.hash(p)
def verify_password(p: str, h: str) -> bool:
    return pwd.verify(p, h)
def sha256_hex(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()
def mint_access(user_id: int, email: str, role: str, secret: str, minutes: int) -> str:
    now = datetime.datetime.utcnow()
    payload = {"sub": str(user_id), "email": email, "role": role, "aud": "tokensecure", "iat": now, "exp": now + datetime.timedelta(minutes=minutes), "type": "access"}
    return jwt.encode(payload, secret, algorithm="HS256")
def mint_refresh(user_id: int, secret: str, days: int) -> str:
    now = datetime.datetime.utcnow()
    payload = {"sub": str(user_id), "iat": now, "exp": now + datetime.timedelta(days=days), "type": "refresh"}
    return jwt.encode(payload, secret, algorithm="HS256")