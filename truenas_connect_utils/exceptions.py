import errno
from typing import Any


def get_errname(code: int) -> str:
    return errno.errorcode.get(code, 'EUNKNOWN')


class CallError(Exception):
    def __init__(self, errmsg: str, errno: int = errno.EFAULT, extra: Any = None) -> None:
        self.errmsg = errmsg
        self.errno = errno
        self.extra = extra

    def __str__(self) -> str:
        errname = get_errname(self.errno)
        return f'[{errname}] {self.errmsg}'
