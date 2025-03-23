import errno


def get_errname(code):
    return errno.errorcode.get(code, 'EUNKNOWN')


class CallError(Exception):
    def __init__(self, errmsg, errno=errno.EFAULT, extra=None):
        self.errmsg = errmsg
        self.errno = errno
        self.extra = extra

    def __str__(self):
        errname = get_errname(self.errno)
        return f'[{errname}] {self.errmsg}'
