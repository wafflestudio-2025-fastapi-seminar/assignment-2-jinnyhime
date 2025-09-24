# src/common/custom_exception.py
from __future__ import annotations

from http import HTTPStatus

class CustomException(Exception):
    """
    과제 에러 포맷 전용 예외.
    전역 핸들러에서 {"error_code": "...", "error_msg": "..."} 로 응답하도록 쓰세요.
    """
    def __init__(
        self,
        status_code: int = 500,
        error_code: str = "ERR_000",
        error_message: str = "Unexpected error occurred",
    ):
        # status_code 유효성 보정
        try:
            HTTPStatus(status_code)
        except Exception:
            status_code = 500

        self.status_code = status_code
        self.error_code = error_code if isinstance(error_code, str) else "ERR_000"
        self.error_message = (
            error_message
            if isinstance(error_message, str)
            else HTTPStatus(self.status_code).description
        )

    def __str__(self) -> str:
        return f"[{self.status_code}] {self.error_code}: {self.error_message}"

def raise_err(status_code: int, error_code: str, error_message: str) -> None:
    """과제 포맷 예외를 간단히 던지는 헬퍼."""
    raise CustomException(status_code, error_code, error_message)
