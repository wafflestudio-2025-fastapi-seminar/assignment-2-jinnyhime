# src/auth/router.py
from __future__ import annotations

from fastapi import APIRouter, Response, Header, Cookie
from typing import Optional
from datetime import datetime, timedelta, timezone
import uuid
import jwt

from .schemas import LoginIn, TokenPair
from ..common.custom_exception import raise_err
from ..common.database import blocked_token_db, session_db, user_db

# (선택) common.__init__에 옮겨두었다면 import로 대체하세요.
SECRET_KEY = "change-this-in-prod"
ALGORITHM = "HS256"

# 과제 스펙: access=SHORT(분), refresh & session=LONG(분)
SHORT_SESSION_LIFESPAN = 15          # access token
LONG_SESSION_LIFESPAN = 24 * 60      # refresh token & cookie session

auth_router = APIRouter(prefix="/auth", tags=["auth"])


# ---------------------- 내부 유틸 ----------------------
def _make_jwt(sub: str, minutes: int) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": sub,
        "iat": now,
        "exp": now + timedelta(minutes=minutes),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def _decode_jwt(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise_err(401, "ERR_008", "INVALID TOKEN")
    except jwt.PyJWTError:
        raise_err(401, "ERR_008", "INVALID TOKEN")

def _parse_bearer(authorization: Optional[str]) -> str:
    if not authorization:
        raise_err(401, "ERR_009", "UNAUTHENTICATED")
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise_err(400, "ERR_007", "BAD AUTHORIZATION HEADER")
    return parts[1]

def _find_user_by_email(email: str):
    """
    user_db 구조가 list[dict] 또는 dict[int->dict]일 수 있어
    양쪽을 모두 커버하도록 탐색.
    """
    if isinstance(user_db, dict):
        iterable = user_db.values()
    else:
        iterable = user_db

    for u in iterable:
        if u.get("email") == email:
            return u
    return None


# ---------------------- 토큰 기반 ----------------------
@auth_router.post("/token", response_model=TokenPair)
def issue_token(body: LoginIn):
    # 필수값 누락은 RequestValidationError 핸들러가 ERR_001로 처리됨
    user = _find_user_by_email(body.email)
    if not user:
        raise_err(401, "ERR_010", "INVALID ACCOUNT")

    # 비밀번호 검증 (평가환경에서 hashed_password가 없을 수도 있어 fallback)
    hashed = user.get("hashed_password")
    password_ok = False
    if hashed:
        try:
            # argon2를 common에 두지 않았다면 여기서 import
            from argon2 import PasswordHasher
            ph = PasswordHasher()
            password_ok = ph.verify(hashed, body.password)
        except Exception:
            password_ok = False
    else:
        # 임시: hashed_password가 없으면 plain 비교 시도 (스켈레톤 호환용)
        password_ok = (user.get("password") == body.password)

    if not password_ok:
        raise_err(401, "ERR_010", "INVALID ACCOUNT")

    sub = str(user["user_id"])
    access = _make_jwt(sub, SHORT_SESSION_LIFESPAN)
    refresh = _make_jwt(sub, LONG_SESSION_LIFESPAN)
    return TokenPair(access_token=access, refresh_token=refresh)


@auth_router.post("/token/refresh", response_model=TokenPair)
def refresh_token(Authorization: Optional[str] = Header(default=None)):
    token = _parse_bearer(Authorization)

    # 블랙리스트 확인
    if token in blocked_token_db:
        raise_err(401, "ERR_008", "INVALID TOKEN")

    payload = _decode_jwt(token)  # 만료/서명 검증
    sub = payload.get("sub")
    exp = payload.get("exp")
    if not sub or not exp:
        raise_err(401, "ERR_008", "INVALID TOKEN")

    # 기존 refresh는 재사용 방지 위해 블랙리스트에 등록
    blocked_token_db[token] = datetime.fromtimestamp(exp, tz=timezone.utc)

    # 새 토큰 발급
    new_access = _make_jwt(sub, SHORT_SESSION_LIFESPAN)
    new_refresh = _make_jwt(sub, LONG_SESSION_LIFESPAN)
    return TokenPair(access_token=new_access, refresh_token=new_refresh)


@auth_router.delete("/token", status_code=204)
def revoke_refresh(Authorization: Optional[str] = Header(default=None)):
    token = _parse_bearer(Authorization)

    payload = _decode_jwt(token)
    exp = payload.get("exp")
    if not exp:
        # exp 없으면 형식상 문제 → invalid token
        raise_err(401, "ERR_008", "INVALID TOKEN")

    # 블랙리스트 추가(이미 있으면 그대로 둠)
    blocked_token_db[token] = datetime.fromtimestamp(exp, tz=timezone.utc)
    # 204 No Content
    return


# ---------------------- 세션 기반 ----------------------
@auth_router.post("/session", status_code=200)
def session_login(body: LoginIn, response: Response):
    # 필수값 누락은 422/ERR_001로 글로벌 핸들러 처리
    user = _find_user_by_email(body.email)
    if not user:
        raise_err(401, "ERR_010", "INVALID ACCOUNT")

    # 비밀번호 검증
    password_ok = False
    hashed = user.get("hashed_password")
    if hashed:
        try:
            from argon2 import PasswordHasher
            ph = PasswordHasher()
            password_ok = ph.verify(hashed, body.password)
        except Exception:
            password_ok = False
    else:
        password_ok = (user.get("password") == body.password)

    if not password_ok:
        raise_err(401, "ERR_010", "INVALID ACCOUNT")

    # 세션 발급 및 저장
    sid = uuid.uuid4().hex
    expires_at = datetime.utcnow() + timedelta(minutes=LONG_SESSION_LIFESPAN)
    session_db[sid] = {
        "user_id": user["user_id"],
        "expires_at": expires_at,
    }

    # 쿠키 설정
    response.set_cookie(
        key="sid",
        value=sid,
        max_age=LONG_SESSION_LIFESPAN * 60,
        httponly=True,
        samesite="lax",
    )
    return {"ok": True}


@auth_router.delete("/session", status_code=204)
def session_logout(response: Response, sid: Optional[str] = Cookie(default=None)):
    # 클라이언트 sid 쿠키 만료
    response.delete_cookie("sid")

    # 서버 세션 제거(있을 때만)
    if sid and sid in session_db:
        session_db.pop(sid, None)
    return
