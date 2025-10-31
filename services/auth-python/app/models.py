from sqlalchemy.orm import declarative_base
from sqlalchemy import Column, Integer, String, Enum, Boolean, DateTime, ForeignKey, func
Base = declarative_base()
class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    email = Column(String(190), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(Enum('user','admin', name='role_enum'), default='user', nullable=False)
    totp_secret = Column(String(64), nullable=True)
    totp_enabled = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, server_default=func.now())
class RefreshToken(Base):
    __tablename__ = 'refresh_tokens'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    token_hash = Column(String(64), index=True, nullable=False)
    revoked = Column(Boolean, default=False, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, server_default=func.now())