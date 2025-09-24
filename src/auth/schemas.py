# src/auth/schemas.py
from pydantic import BaseModel, EmailStr, Field

class LoginIn(BaseModel):
    """POST /auth/token, POST /auth/session 입력"""
    email: EmailStr
    # 필수값 누락은 전역 RequestValidationError 핸들러가 ERR_001로 처리하므로
    # 여기선 비어있는 문자열만 방지
    password: str = Field(min_length=1)

class TokenPair(BaseModel):
    """토큰 발급/갱신 응답 공통 형태"""
    access_token: str
    refresh_token: str

__all__ = ["LoginIn", "TokenPair"]
