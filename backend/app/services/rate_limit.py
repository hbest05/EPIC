"""
Rate limiting — slowapi Limiter singleton.

Import `limiter` here rather than creating it in main.py so routers can
decorate their endpoints without importing from main (which would be circular).

Usage in a router:
    from app.services.rate_limit import limiter

    @router.post("/login")
    @limiter.limit("5/minute")
    async def login(request: Request, ...):
        ...

main.py registers the exception handler:
    from slowapi import _rate_limit_exceeded_handler
    from slowapi.errors import RateLimitExceeded
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
"""

from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
