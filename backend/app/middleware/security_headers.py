"""
Security headers middleware — applied to every response.

Headers set:
  X-Content-Type-Options   nosniff — prevents MIME-type sniffing
  X-Frame-Options          DENY    — legacy clickjacking protection (older browsers)
  Referrer-Policy          no-referrer — no URL info leaked to third parties
  Content-Security-Policy  default-src 'none'; frame-ancestors 'none'
                           — API returns JSON only; all resource loading forbidden.
                           Skipped for /docs, /redoc, /openapi.json because Swagger UI
                           requires inline scripts from cdn.jsdelivr.net.
  Strict-Transport-Security max-age=31536000; includeSubDomains
                           — production only (APP_ENV != development).
                           Sending HSTS over plain HTTP violates the spec and can
                           poison the browser preload list, so it is suppressed on
                           http://localhost during local development.
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from app.config import settings

# FastAPI-served UI paths — inline scripts break under a strict CSP
_DOCS_PATHS = frozenset({"/docs", "/redoc", "/openapi.json"})


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"

        # HSTS — only meaningful over HTTPS; suppressed in development
        if settings.app_env != "development":
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )

        # CSP — skipped for Swagger/ReDoc which need inline scripts from jsdelivr.net
        if request.url.path not in _DOCS_PATHS:
            response.headers["Content-Security-Policy"] = (
                "default-src 'none'; frame-ancestors 'none'"
            )

        return response
