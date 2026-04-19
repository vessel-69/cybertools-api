import time
import threading
from collections import deque
from fastapi import HTTPException, Request


class _SlidingWindow:
    def __init__(self):
        self._store: dict[str, deque] = {}
        self._lock  = threading.Lock()

    def check(self, key: str, max_req: int, window: int) -> tuple[bool, int]:
        now    = time.monotonic()
        cutoff = now - window
        with self._lock:
            if key not in self._store:
                self._store[key] = deque()
            dq = self._store[key]
            while dq and dq[0] < cutoff:
                dq.popleft()
            if len(dq) >= max_req:
                retry = int(window - (now - dq[0])) + 1
                return False, retry
            dq.append(now)
            return True, 0

    def purge(self, older_than: int = 120):
        cutoff = time.monotonic() - older_than
        with self._lock:
            stale = [k for k, dq in self._store.items()
                     if not dq or dq[-1] < cutoff]
            for k in stale:
                del self._store[k]


_w = _SlidingWindow()


def _ip(request: Request) -> str:
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return (request.client.host if request.client else "unknown")


def _limiter(max_req: int, window: int = 60):
    def _dep(request: Request):
        key = f"{request.url.path}:{_ip(request)}"
        ok, retry = _w.check(key, max_req, window)
        if not ok:
            raise HTTPException(
                429,
                detail=f"Rate limit exceeded — retry in {retry}s.",
                headers={"Retry-After": str(retry)},
            )
    return _dep


limit_recon    = _limiter(30)
limit_workflow = _limiter(10)
limit_payloads = _limiter(60)
limit_chat     = _limiter(20)
limit_util     = _limiter(120)