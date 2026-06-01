"""
CSRF middleware — global double-submit cookie validation.

Intercepts every state-changing request (POST, PUT, DELETE, PATCH) and
verifies that the X-CSRF-Token header matches the readable csrf_token cookie
set by POST /auth/login.  Returns 403 immediately if they don't match.

Exempt paths are endpoints that predate authentication — no csrf_token cookie
exists yet so validation would always fail for them:
  - POST /api/auth/login    (sets the cookie)
  - POST /api/auth/register (no session at all)

All other state-changing endpoints are covered automatically, so routers
do not need to add Depends(verify_csrf) individually.
"""

import hmac

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

_STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "DELETE", "PATCH"})

# Pre-auth endpoints — csrf_token cookie does not exist yet at call time
_CSRF_EXEMPT_PATHS = frozenset({
    "/api/auth/login",
    "/api/auth/register",
    "/api/auth/prekeys",
})


class CSRFMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if (
            request.method in _STATE_CHANGING_METHODS
            and request.url.path not in _CSRF_EXEMPT_PATHS
        ):
            cookie = request.cookies.get("csrf_token")
            header = request.headers.get("X-CSRF-Token")
            if not cookie or not header or not hmac.compare_digest(cookie, header):
                return JSONResponse(
                    {"detail": "CSRF validation failed"},
                    status_code=403,
                )
        return await call_next(request)
