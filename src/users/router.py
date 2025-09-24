# users/router.py
from __future__ import annotations

from typing import Optional
from datetime import datetime, timedelta, timezone
import jwt
from argon2 import PasswordHasher
from fastapi import APIRouter, Cookie, Header, status

from .schemas import CreateUserRequest, UserResponse
from ..common.database import blocked_token_db, session_db, user_db
from ..common import SECRET_KEY, ALGORITHM
from ..common.custom_exception import raise_err

user_router = APIRouter(prefix="/users", tags=["users"])

ph = PasswordHasher()

# ---- 내부 유틸 ----
def _next_user_id() -> int:
    if isinstance(user_db, dict):
        return (max(user_db.keys()) + 1) if user_db else 1
    # list인 경우도 방어
    return (max(u["user_id"] for u in user_db) + 1) if user_db else 1

def _email_exists(email: str) -> bool:
    if isinstance(user_db, dict):
        return any(u.get("email") == email for u in user_db.values())
    return any(u.get("email") == email for u in user_db)

def _parse_bearer(auth: Optional[str]) -> str:
    if not auth:
        raise_err(401, "ERR_009", "UNAUTHENTICATED")
    parts = auth.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise_err(400, "ERR_007", "BAD AUTHORIZATION HEADER")
    return parts[1]

def _decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise_err(401, "ERR_008", "INVALID TOKEN")
    except jwt.PyJWTError:
        raise_err(401, "ERR_008", "INVALID TOKEN")

def _get_user_by_id(uid: int) -> Optional[dict]:
    if isinstance(user_db, dict):
        return user_db.get(uid)
    return next((u for u in user_db if u.get("user_id") == uid), None)

# ---- 1) 회원가입: POST /api/users ----
@user_router.post("/", status_code=status.HTTP_201_CREATED, response_model=UserResponse)
def create_user(request: CreateUserRequest) -> UserResponse:
    # email 중복
    if _email_exists(request.email):
        raise_err(409, "ERR_005", "EMAIL ALREADY EXISTS")

    # 비밀번호는 해시로 저장
    hashed = ph.hash(request.password)

    uid = _next_user_id()
    record = {
        "user_id": uid,
        "email": request.email,
        "name": request.name,
        "hashed_password": hashed,
        "phone_number": request.phone_number,
        "height": request.height,
        "bio": request.bio,
    }

    if isinstance(user_db, dict):
        user_db[uid] = record
    else:
        user_db.append(record)

    return UserResponse(**{
        "user_id": uid,
        "email": record["email"],
        "name": record["name"],
        "phone_number": record["phone_number"],
        "height": record["height"],
        "bio": record["bio"],
    })

# ---- 2) 내 정보 조회: GET /api/users/me ----
@user_router.get("/me", response_model=UserResponse)
def get_user_info(
    sid: Optional[str] = Cookie(default=None),
    Authorization: Optional[str] = Header(default=None),
):
    """
    우선 순서:
      1) 세션 쿠키(sid)가 있으면 세션 기반으로 검증
      2) 아니면 Authorization: Bearer <access_token> 기반으로 검증
    둘 다 없는 경우 -> 401 ERR_009
    """
    # 2-1) 세션 기반
    if sid:
        sess = session_db.get(sid)
        if not sess:
            raise_err(401, "ERR_006", "INVALID SESSION")
        # expires_at 비교: dict or dataclass 모두 UTC naive 저장일 수 있어 처리
        expires_at = sess["expires_at"] if isinstance(sess, dict) else sess.expires_at
        # naive면 UTC로 간주
        now = datetime.utcnow()
        if isinstance(expires_at, datetime) and expires_at.tzinfo is not None:
            now = datetime.now(timezone.utc)
        if expires_at < now:
            # 만료 → 세션 제거
            session_db.pop(sid, None)
            raise_err(401, "ERR_006", "INVALID SESSION")

        user = _get_user_by_id(sess["user_id"] if isinstance(sess, dict) else sess.user_id)
        if not user:
            raise_err(401, "ERR_006", "INVALID SESSION")

        return UserResponse(
            user_id=user["user_id"],
            name=user["name"],
            email=user["email"],
            phone_number=user["phone_number"],
            bio=user.get("bio"),
            height=user["height"],
        )

    # 2-2) 토큰 기반
    if Authorization:
        token = _parse_bearer(Authorization)
        payload = _decode_token(token)
        sub = payload.get("sub")
        if not sub:
            raise_err(401, "ERR_008", "INVALID TOKEN")

        try:
            uid = int(sub)
        except ValueError:
            raise_err(401, "ERR_008", "INVALID TOKEN")

        user = _get_user_by_id(uid)
        if not user:
            raise_err(401, "ERR_008", "INVALID TOKEN")

        return UserResponse(
            user_id=user["user_id"],
            name=user["name"],
            email=user["email"],
            phone_number=user["phone_number"],
            bio=user.get("bio"),
            height=user["height"],
        )

    # 둘 다 없으면
    raise_err(401, "ERR_009", "UNAUTHENTICATED")
