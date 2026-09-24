"""Tiny in-memory sliding-window rate limiter (per process).

Adequate for a training app; production would use Redis.
"""
import time
from collections import defaultdict, deque

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.config import get_settings

settings = get_settings()


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        self.hits: dict[str, deque] = defaultdict(deque)

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        limit = None
        if path == "/api/auth/login":
            limit = settings.RATE_LIMIT_LOGIN_PER_MIN
        elif path == "/api/auth/register":
            limit = settings.RATE_LIMIT_REGISTER_PER_MIN
        if limit:
            key = f"{path}:{request.client.host if request.client else 'unknown'}"
            now = time.time()
            window = self.hits[key]
            while window and now - window[0] > 60:
                window.popleft()
            if len(window) >= limit:
                return JSONResponse({"detail": "Too many requests, slow down."}, status_code=429)
            window.append(now)
        return await call_next(request)
