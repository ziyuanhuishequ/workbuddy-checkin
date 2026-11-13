"""凭据落盘加密。

数据库里存的 accessToken / refreshToken 一律是 Fernet 密文。
密钥由 config.SECRET_KEY 派生（没有单独的密钥文件要额外保管）。
"""

from __future__ import annotations

import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken

from . import config

_fernet = Fernet(
    base64.urlsafe_b64encode(hashlib.sha256(config.SECRET_KEY.encode("utf-8")).digest())
)


def encrypt(plaintext: str) -> str:
    if not plaintext:
        return ""
    return _fernet.encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt(ciphertext: str) -> str:
    if not ciphertext:
        return ""
    try:
        return _fernet.decrypt(ciphertext.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError):
        # 密钥被换过 → 旧密文解不开。当作凭据失效处理，不要炸整个服务。
        return ""


def mask(token: str, keep: int = 6) -> str:
    """脱敏展示：只保留首尾少量字符。"""
    if not token:
        return ""
    if len(token) <= keep * 2:
        return "*" * len(token)
    return f"{token[:keep]}...{token[-keep:]}"
