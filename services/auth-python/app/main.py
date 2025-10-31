from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
import jwt, pyotp
from .config import settings
from .models import Base, User, RefreshToken
from .deps import engine, get_db
from .schemas import RegisterIn, LoginIn, TokenOut, MeOut
from .security import hash_password, verify_password, mint_access, mint_refresh, sha256_hex
Base.metadata.create_all(bind=engine)
app = FastAPI(title="TokenSecure Auth API")
app.add_middleware(CORSMiddleware, allow_origins=[o.strip() for o in settings.CORS_ORIGINS.split(',')], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
@app.get("/")
def root():
    return {"name": "TokenSecure Auth API", "status": "ok"}
@app.post("/auth/register", response_model=MeOut)
def register(body: RegisterIn, db: Session = Depends(get_db)):
    if db.query(User).filter_by(email=body.email).first():
        raise HTTPException(status_code=409, detail="Email já registrado")
    u = User(email=body.email, password_hash=hash_password(body.password))
    db.add(u); db.commit(); db.refresh(u)
    return MeOut(id=u.id, email=u.email, role=u.role, totp_enabled=u.totp_enabled)
@app.post("/auth/login", response_model=TokenOut)
def login(body: LoginIn, db: Session = Depends(get_db)):
    u = db.query(User).filter_by(email=body.email).first()
    if not u or not verify_password(body.password, u.password_hash):
        raise HTTPException(status_code=401, detail="Credenciais inválidas")
    if u.totp_enabled:
        if not body.totp or not pyotp.TOTP(u.totp_secret).verify(body.totp, valid_window=1):
            raise HTTPException(status_code=401, detail="TOTP inválido ou ausente")
    access = mint_access(u.id, u.email, u.role, settings.JWT_SECRET, settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    refresh = mint_refresh(u.id, settings.JWT_REFRESH_SECRET, settings.REFRESH_TOKEN_EXPIRE_DAYS)
    rt = RefreshToken(user_id=u.id, token_hash=sha256_hex(refresh), expires_at=datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS))
    db.add(rt); db.commit()
    return TokenOut(access_token=access, refresh_token=refresh)
@app.post("/auth/refresh", response_model=TokenOut)
def refresh(authorization: str = Header(None), db: Session = Depends(get_db)):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Bearer refresh token obrigatório")
    token = authorization.split()[1]
    try:
        payload = jwt.decode(token, settings.JWT_REFRESH_SECRET, algorithms=["HS256"])
        if payload.get("type") != "refresh": raise Exception("Tipo errado")
    except Exception:
        raise HTTPException(status_code=401, detail="Refresh inválido")
    user_id = int(payload["sub"]); token_hash = sha256_hex(token)
    stored = db.query(RefreshToken).filter_by(token_hash=token_hash, user_id=user_id, revoked=False).first()
    if not stored or stored.expires_at < datetime.utcnow():
        raise HTTPException(status_code=401, detail="Refresh expirado ou revogado")
    stored.revoked = True; db.add(stored)
    u = db.query(User).get(user_id)
    access = mint_access(u.id, u.email, u.role, settings.JWT_SECRET, settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    new_refresh = mint_refresh(u.id, settings.JWT_REFRESH_SECRET, settings.REFRESH_TOKEN_EXPIRE_DAYS)
    from datetime import timedelta as _td
    new_rt = RefreshToken(user_id=u.id, token_hash=sha256_hex(new_refresh), expires_at=datetime.utcnow() + _td(days=settings.REFRESH_TOKEN_EXPIRE_DAYS))
    db.add(new_rt); db.commit()
    return TokenOut(access_token=access, refresh_token=new_refresh)
@app.post("/auth/logout")
def logout(authorization: str = Header(None), db: Session = Depends(get_db)):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Bearer refresh token obrigatório")
    token = authorization.split()[1]; h = sha256_hex(token)
    stored = db.query(RefreshToken).filter_by(token_hash=h, revoked=False).first()
    if stored: stored.revoked = True; db.add(stored); db.commit()
    return {"ok": True}
@app.post("/auth/totp/setup")
def totp_setup(authorization: str = Header(None), db: Session = Depends(get_db)):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Access token obrigatório")
    access = authorization.split()[1]
    try:
        payload = jwt.decode(access, settings.JWT_SECRET, algorithms=["HS256"], audience="tokensecure"); uid = int(payload['sub'])
    except Exception:
        raise HTTPException(status_code=401, detail="Access inválido")
    u = db.query(User).get(uid)
    if u.totp_enabled and u.totp_secret: return {"already_enabled": True}
    secret = pyotp.random_base32(); u.totp_secret = secret; db.add(u); db.commit()
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=u.email, issuer_name="TokenSecure")
    return {"secret": secret, "otpauth_uri": uri}
@app.post("/auth/totp/verify")
def totp_verify(code: str, authorization: str = Header(None), db: Session = Depends(get_db)):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Access token obrigatório")
    access = authorization.split()[1]
    try:
        payload = jwt.decode(access, settings.JWT_SECRET, algorithms=["HS256"], audience="tokensecure"); uid = int(payload['sub'])
    except Exception:
        raise HTTPException(status_code=401, detail="Access inválido")
    u = db.query(User).get(uid)
    if not u.totp_secret: raise HTTPException(status_code=400, detail="TOTP não iniciado")
    if pyotp.TOTP(u.totp_secret).verify(code, valid_window=1): u.totp_enabled = True; db.add(u); db.commit(); return {"enabled": True}
    raise HTTPException(status_code=400, detail="Código inválido")