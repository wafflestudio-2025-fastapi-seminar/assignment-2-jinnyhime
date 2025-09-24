# src/common/database.py
from datetime import datetime
from typing import Optional

user_db: list[dict] = []                     # [{user_id, email, hashed_password, name, phone_number, height, bio}]
session_db: dict[str, dict] = {}             # sid -> {"user_id": int, "expires_at": datetime}
blocked_token_db: dict[str, datetime] = {}   # refresh_jwt -> original_exp

_next_user_id = 1

def next_user_id() -> int:
    global _next_user_id
    uid = _next_user_id
    _next_user_id += 1
    return uid

def find_user_by_email(email: str) -> Optional[dict]:
    return next((u for u in user_db if u.get("email") == email), None)

def find_user_by_id(user_id: int) -> Optional[dict]:
    return next((u for u in user_db if u.get("user_id") == user_id), None)
