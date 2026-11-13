"""后台调度：令牌续期、每日签到、失败重试。

用一个轻量后台线程，避免引入 APScheduler 之类的额外依赖。
调度状态（今天是否已经跑过）写进 settings 表，重启后不会重复签或漏签。
"""

from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timedelta
from typing import Any, Optional

from . import config, db, service

logger = logging.getLogger("workbuddy.scheduler")

LAST_DAILY_KEY = "last_daily_run"
LAST_PRUNE_KEY = "last_log_prune"
LAST_CLEANUP_KEY = "last_cleanup_run"


class Scheduler:
    def __init__(self) -> None:
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._last_retry = time.time()
        self._last_refresh = 0.0
        self._last_keepalive = 0.0

    # ------------------------------------------------------------------ #
    # 生命周期
    # ------------------------------------------------------------------ #

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="wb-scheduler", daemon=True)
        self._thread.start()
        logger.info("后台调度已启动（每 %s 秒一次心跳）", config.TICK_SECONDS)

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _run(self) -> None:
        self._stop.wait(3)
        self._safe(self._startup_catchup)
        while not self._stop.is_set():
            self._safe(self._tick)
            self._stop.wait(config.TICK_SECONDS)

    @staticmethod
    def _safe(func) -> None:
        try:
            func()
        except Exception:  # 后台线程绝不能因为一次异常就退出
            logger.exception("调度任务执行失败：%s", getattr(func, "__name__", func))

    # ------------------------------------------------------------------ #
    # 单次心跳
    # ------------------------------------------------------------------ #

    def _tick(self) -> None:
        if db.get_bool_setting("auto_refresh", True):
            self._refresh_pass()
            self._keepalive_pass()
        self._daily_pass()
        self._retry_pass()
        self._cleanup_pass()
        self._prune_pass()

    def _cleanup_pass(self) -> None:
        """按设置自动清理「需重新登录」且已失效 N 天的账号（每天最多一次）。"""
        days = db.get_int_setting("auto_cleanup_days", 0)
        if days <= 0:
            return
        today = db.today_str()
        if db.get_setting(LAST_CLEANUP_KEY, "") == today:
            return
        db.set_setting(LAST_CLEANUP_KEY, today)
        result = service.cleanup_expired(days)
        if result.get("removed"):
            logger.info("自动清理失效账号 %s 个（失效超过 %s 天）", result["removed"], days)

    # ------------------------------------------------------------------ #

    def _startup_catchup(self) -> None:
        """服务启动时补签：重启/迁移后不用等到明天。"""
        if not db.get_bool_setting("startup_checkin", True):
            return
        # 先保活一轮：服务器停机期间令牌可能已经过期，先自动续上再谈签到
        try:
            service.keepalive_all()
        except Exception:
            logger.exception("启动时令牌保活失败")
        pending = [
            account
            for account in db.list_accounts()
            if account.get("enabled") and not db.success_today(int(account["id"]))
        ]
        if not pending:
            logger.info("启动检查：所有账号今天都已签到")
            return
        logger.info("启动补签：%s 个账号今天还没签到", len(pending))
        summary = service.checkin_all(trigger="startup")
        if not summary.get("failed"):
            db.set_setting(LAST_DAILY_KEY, db.today_str())

    def _daily_pass(self) -> None:
        now = datetime.now(config.TZ)
        today = db.today_str()
        if db.get_setting(LAST_DAILY_KEY, "") == today:
            return
        target = self._target_datetime(now)
        if now < target:
            return
        # 先占位再执行：避免多个心跳并发重复触发
        db.set_setting(LAST_DAILY_KEY, today)
        logger.info("到达每日签到时间 %s，开始批量签到", db.get_setting("checkin_time", "09:00"))
        service.checkin_all(trigger="daily")

    def _retry_pass(self) -> None:
        interval = max(60, db.get_int_setting("retry_interval_seconds", 1800))
        if time.time() - self._last_retry < interval:
            return
        self._last_retry = time.time()

        max_retries = max(0, db.get_int_setting("max_retries_per_day", 3))
        # 今天的定时任务是否已经跑过。跑过之后才需要惦记「今天新加进来的账号」。
        daily_done_today = db.get_setting(LAST_DAILY_KEY, "") == db.today_str()
        targets: list[dict[str, Any]] = []
        for account in db.list_accounts():
            if not account.get("enabled"):
                continue
            account_id = int(account["id"])
            if db.success_today(account_id):
                continue
            attempts = db.attempts_today(account_id)
            if attempts == 0 and not daily_done_today:
                # 今天还没到点，别在凌晨乱签——交给定时任务
                continue
            if attempts >= max_retries:
                continue
            targets.append(account)

        if not targets:
            return
        logger.info("重试签到：%s 个账号", len(targets))
        for account in targets:
            try:
                service.checkin_account(int(account["id"]), trigger="retry")
            except Exception:
                logger.exception("重试签到失败：%s", account.get("uid"))

    def _refresh_pass(self) -> None:
        # 续期是最贵的操作，5 分钟扫一次就够了
        if time.time() - self._last_refresh < 300:
            return
        self._last_refresh = time.time()
        for account in db.list_accounts(with_secrets=True):
            if not account.get("enabled") or not account.get("refresh_token"):
                continue
            if not service.token_expiring(account):
                continue
            try:
                result = service.refresh_account(int(account["id"]), notify=True)
                if not result.get("ok"):
                    logger.warning("账号 %s 续期失败：%s", account.get("uid"), result.get("message"))
            except Exception:
                logger.exception("续期异常：%s", account.get("uid"))

    def _keepalive_pass(self) -> None:
        """定时保活：提前续期 + 自动复活已失效账号。

        默认 2 小时一轮。refreshToken 是会滚动的，只要一直在有效期内换新，
        就能长期免扫码；停太久才会真的过期。
        """
        interval = db.get_int_setting("keepalive_seconds", 7200)
        if interval <= 0:
            return
        if time.time() - self._last_keepalive < interval:
            return
        self._last_keepalive = time.time()
        try:
            summary = service.keepalive_all()
        except Exception:
            logger.exception("令牌保活异常")
            return
        if summary.get("total"):
            logger.info(
                "令牌保活：成功 %s/%s", summary.get("ok"), summary.get("total")
            )
        for item in summary.get("details") or []:
            logger.warning("账号 %s 保活失败：%s", item.get("uid"), item.get("message"))

    def _prune_pass(self) -> None:
        today = db.today_str()
        if db.get_setting(LAST_PRUNE_KEY, "") == today:
            return
        db.set_setting(LAST_PRUNE_KEY, today)
        db.prune_logs(keep_days=180)
        db.prune_checkin_marks(keep_days=60)

    # ------------------------------------------------------------------ #

    def _target_datetime(self, now: datetime) -> datetime:
        raw = db.get_setting("checkin_time", "09:00")
        try:
            hour, minute = (int(part) for part in raw.split(":"))
        except (ValueError, TypeError):
            hour, minute = 9, 0
        target = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
        return target

    def next_run_at(self) -> Optional[int]:
        """下一次计划签到的时间戳（用于界面展示）。"""
        now = datetime.now(config.TZ)
        target = self._target_datetime(now)
        if db.get_setting(LAST_DAILY_KEY, "") == db.today_str():
            target = target + timedelta(days=1)
        elif now >= target:
            target = now
        return int(target.timestamp())


scheduler = Scheduler()
