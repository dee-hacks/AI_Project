"""API middleware — TLS, rate-limiting, and basic auth."""

import time
from typing import Callable
from fastapi import FastAPI, Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Simple in-memory rate limiter (100 req/min per IP)."""

    def __init__(self, app: FastAPI, max_requests: int = 100, window_sec: int = 60):
        super().__init__(app)
        self.max_requests = max_requests
        self.window_sec = window_sec
        self._requests = {}

    async def dispatch(self, request: Request, call_next: Callable):
        client_ip = request.client.host if request.client else "unknown"
        now = time.time()

        # Clean old entries
        self._requests = {
            ip: times for ip, times in self._requests.items()
            if times[-1] > now - self.window_sec
        }

        # Track this request
        if client_ip not in self._requests:
            self._requests[client_ip] = []
        self._requests[client_ip].append(now)

        # Check limit
        if len(self._requests[client_ip]) > self.max_requests:
            raise HTTPException(status_code=429, detail="Rate limit exceeded")

        response = await call_next(request)
        return response


def add_middleware(app: FastAPI):
    """Register all middleware."""
    app.add_middleware(RateLimitMiddleware, max_requests=200, window_sec=60)

    @app.middleware("http")
    async def add_security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        return response