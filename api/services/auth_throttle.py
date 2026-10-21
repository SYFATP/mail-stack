"""Bounded, transactional authentication budgets shared by all password routes."""
from __future__ import annotations
import hashlib
import math
import time
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool


class AuthenticationRateLimit:
    def __init__(self, app, database):
        self.app, self.database = app, database

    def reserve(self, client):
        now = time.time()
        source = hashlib.sha256(client.encode()).hexdigest()
        budgets = ((source, 10, 300), ("global", 120, 60))
        c = self.database()
        try:
            c.execute("BEGIN IMMEDIATE")
            c.execute("delete from auth_attempts where expires_at<=?", (now,))
            for bucket, limit, window in budgets:
                row = c.execute("select attempts,expires_at from auth_attempts where source=?", (bucket,)).fetchone()
                if row and row["attempts"] >= limit:
                    c.rollback()
                    return max(1, math.ceil(row["expires_at"] - now))
            for bucket, limit, window in budgets:
                c.execute("""insert into auth_attempts(source,attempts,expires_at) values(?,1,?)
                             on conflict(source) do update set attempts=attempts+1""", (bucket, now + window))
            c.commit()
            return 0
        finally:
            c.close()

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            headers = dict(scope.get("headers", []))
            protected = scope.get("path") in {"/api/v1/auth/login", "/api/v1/auth/password"}
            if protected or b"x-admin-password" in headers:
                # Uvicorn supplies the client after applying its trusted proxy
                # policy. Never trust a caller's X-Forwarded-For here.
                client = scope.get("client")
                try:
                    retry = await run_in_threadpool(self.reserve, str(client[0]) if client else "unknown")
                except Exception:
                    response = JSONResponse({"detail": "authentication temporarily unavailable"}, status_code=503)
                    return await response(scope, receive, send)
                if retry:
                    response = JSONResponse({"detail": "authentication rate limit exceeded"}, status_code=429,
                                            headers={"Retry-After": str(retry), "Cache-Control": "no-store"})
                    return await response(scope, receive, send)
        return await self.app(scope, receive, send)
