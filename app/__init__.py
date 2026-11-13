"""WorkBuddy 多账号自动签到服务。"""

import sys

__version__ = "1.5.3"


def _make_streams_safe() -> None:
    """让控制台输出永远不会因为编码问题崩掉。

    Windows 中文控制台默认是 GBK：一旦日志/横幅里出现 emoji 或特殊符号，
    print 会直接抛 UnicodeEncodeError，把整个启动流程打断（实测过）。
    账号昵称里出现 emoji 时，后台线程写日志同样会中招。
    这里把无法编码的字符降级成 '?'，而不是抛异常。
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")  # type: ignore[union-attr]
        except (AttributeError, ValueError):
            pass


_make_streams_safe()
