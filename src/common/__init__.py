# src/common/__init__.py
from .custom_exception import CustomException, raise_err

SECRET_KEY = "change-this-in-prod"
ALGORITHM = "HS256"
SHORT_SESSION_LIFESPAN_MIN = 15
LONG_SESSION_LIFESPAN_MIN  = 60 * 24 * 7

from argon2 import PasswordHasher
_ph = PasswordHasher()
def hash_password(p): return _ph.hash(p)
def verify_password(p, h):
    try: return _ph.verify(h, p)
    except Exception: return False

__all__ = ["CustomException","raise_err","SECRET_KEY","ALGORITHM",
           "SHORT_SESSION_LIFESPAN_MIN","LONG_SESSION_LIFESPAN_MIN",
           "hash_password","verify_password"]
