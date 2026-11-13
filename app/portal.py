"""用户自助页的登录凭据。

设计取舍：
* **一个 WorkBuddy 账号 = 一套前端账号密码**，用户登录后只能看到自己那一个号。
* 密码存两份：``portal_password`` 是 pbkdf2 哈希（登录校验用），
  ``portal_secret`` 是 Fernet 加密的明文（**只有管理员能在控制台查看/转交**）。
  之所以留一份可解密的备份，是因为密码只在登录那一刻显示一次的话，
  用户盯着手机没看电脑就永远拿不回来了——这是实战踩出来的坑。
  两份都在同一个数据库里，和 WorkBuddy 令牌享受同样的加密保护。
* 用户名做成 wb001、wb002 这种可读序号，方便口头转达；
  真正的秘密是密码，用户名可预测不是问题。
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading

from . import db

# 去掉了容易看错的字符（0/O/1/l/I），方便用户手输
_ALPHABET = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789"
_ITERATIONS = 200_000
_lock = threading.RLock()


def generate_password(length: int = 10) -> str:
    return "".join(secrets.choice(_ALPHABET) for _ in range(length))


def hash_password(password: str, salt: str = "") -> str:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt), _ITERATIONS
    )
    return f"pbkdf2_sha256${_ITERATIONS}${salt}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    if not stored or not password:
        return False
    try:
        scheme, iterations, salt, expected = stored.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt), int(iterations)
        )
        return hmac.compare_digest(digest.hex(), expected)
    except (ValueError, TypeError):
        return False


def _next_username() -> str:
    """wb001、wb002……按已有最大序号往后排。"""
    highest = 0
    for name in db.portal_usernames():
        suffix = name[2:] if name.lower().startswith("wb") else ""
        if suffix.isdigit():
            highest = max(highest, int(suffix))
    return f"wb{highest + 1:03d}"


def ensure_credentials(account_id: int) -> dict[str, object]:
    """确保账号有一套前端凭据，并把明文一并带出来。

    已有凭据时也会尽力把明文取回来（老数据可能只有哈希、取不到，此时 password 为 None），
    这样重复登录、或者事后想再查一次，都能拿到账号密码。
    """
    with _lock:
        account = db.get_account(account_id)
        if account is None:
            raise ValueError(f"账号 {account_id} 不存在")

        username = str(account.get("portal_username") or "")
        row = db.query_one("SELECT portal_password FROM accounts WHERE id = ?", (account_id,))
        has_password = bool(row and row["portal_password"])
        if username and has_password:
            secret = db.get_portal_secret(account_id)
            return {
                "username": username,
                "password": secret.get("password") or None,
                "created": False,
            }

        # 用户名冲突就往后顺延（理论上不会，防并发）
        taken = set(db.portal_usernames())
        candidate = username or _next_username()
        while candidate in taken:
            candidate = _next_username()

        password = generate_password()
        db.set_portal_credentials(account_id, candidate, hash_password(password), password)
        return {"username": candidate, "password": password, "created": True}


def reveal(account_id: int) -> dict[str, object]:
    """管理员查看某个账号的前端登录信息（含明文密码）。"""
    account = db.get_account(account_id)
    if account is None:
        raise ValueError(f"账号 {account_id} 不存在")
    secret = db.get_portal_secret(account_id)
    return {
        "username": secret.get("username", ""),
        "password": secret.get("password", ""),
        "login_path": "/me",
        "pw_changed": bool(account.get("portal_pw_changed")),
        "last_login": account.get("portal_last_login") or 0,
    }


def reset_password(account_id: int) -> dict[str, object]:
    """管理员重置某账号的前端密码，返回新的明文密码。"""
    with _lock:
        account = db.get_account(account_id)
        if account is None:
            raise ValueError(f"账号 {account_id} 不存在")
        username = str(account.get("portal_username") or "")
        if not username:
            return ensure_credentials(account_id)
        password = generate_password()
        db.set_portal_password(account_id, hash_password(password), password)
        return {"username": username, "password": password, "created": True}


def authenticate(username: str, password: str) -> dict[str, object] | None:
    """校验前端登录。成功返回 {account_id, username}，失败返回 None。"""
    username = (username or "").strip()
    if not username or not password:
        return None
    credential = db.get_portal_credential(username)
    if credential is None:
        return None
    if not verify_password(password, str(credential["password_hash"])):
        return None
    db.touch_portal_login(int(credential["account_id"]))
    return {"account_id": int(credential["account_id"]), "username": credential["username"]}


def change_password(account_id: int, old_password: str, new_password: str) -> None:
    """用户自己改密码。旧密码不对 / 新密码太弱都抛 ValueError。"""
    row = db.query_one("SELECT portal_password FROM accounts WHERE id = ?", (account_id,))
    if row is None:
        raise ValueError("账号不存在")
    if not verify_password(old_password, str(row["portal_password"])):
        raise ValueError("当前密码不正确")
    new_password = (new_password or "").strip()
    if len(new_password) < 8:
        raise ValueError("新密码至少 8 位")
    if new_password == old_password:
        raise ValueError("新密码不能和旧密码相同")
    db.set_portal_password(account_id, hash_password(new_password), new_password)
