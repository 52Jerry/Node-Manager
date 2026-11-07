"""Serialize one profile's remote lifecycle within the single API worker."""
from contextlib import contextmanager
import threading
import weakref

_guard = threading.Lock()
_locks = weakref.WeakValueDictionary()


@contextmanager
def profile_lock(owner_id, profile_id):
    key = (owner_id, profile_id)
    with _guard:
        lock = _locks.get(key)
        if lock is None:
            lock = threading.RLock()
            _locks[key] = lock
    with lock:
        yield
