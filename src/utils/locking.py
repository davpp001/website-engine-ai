import os
import fcntl
import time
from functools import wraps

def with_lock(lockfile):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            with open(lockfile, 'w') as f:
                try:
                    fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    return func(*args, **kwargs)
                except BlockingIOError:
                    raise RuntimeError('Another operation is in progress (locked)')
                finally:
                    fcntl.flock(f, fcntl.LOCK_UN)
        return wrapper
    return decorator
