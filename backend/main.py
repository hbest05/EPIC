"""
Entry point for the SecureMsg FastAPI application.

Responsibilities:
- Create the FastAPI app instance
- Register routers (auth, messages, blockchain)
- Configure CORS middleware for the web frontend
- Wire up startup/shutdown lifecycle events (DB pool, Redis connection)
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.middleware.csrf import CSRFMiddleware
from app.middleware.security_headers import SecurityHeadersMiddleware
from app.routers import auth, messages, blockchain
from app.database import engine
from app.services.rate_limit import limiter
from app.services.redis_service import init_redis, close_redis

app = FastAPI(
    title="SecureMsg API",
    description="End-to-end encrypted messaging with blockchain audit trail",
    version="0.1.0",
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Middleware executes in reverse registration order (last added = outermost).
# Outermost runs first on request and last on response — so SecurityHeaders
# wraps everything and adds its headers to every response, including error
# responses from inner layers (CSRF 403, rate-limiter 429, etc.).
#
# Execution order on request:  SecurityHeaders → CSRF → CORS → route handler
# Execution order on response: route handler  → CORS → CSRF → SecurityHeaders
app.add_middleware(CSRFMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:8000",
        "http://localhost:5500",
        "http://127.0.0.1:5500",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Must be added last — becomes outermost layer, stamps headers onto every response
app.add_middleware(SecurityHeadersMiddleware)

app.include_router(auth.router,             prefix="/api/auth",       tags=["auth"])
app.include_router(messages.router,         prefix="/api/messages",   tags=["messages"])
app.include_router(blockchain.router,               prefix="/api/blockchain",    tags=["blockchain"])
# Also mount the verify endpoint at /api/verify/:conversationId (task spec)
app.include_router(blockchain.verify_router,        prefix="/api/verify",        tags=["verify"])
# Tier 3: conversation close endpoint
app.include_router(blockchain.conversations_router, prefix="/api/conversations", tags=["conversations"])
# Public verify — no auth required, used by the standalone verify.html page
app.include_router(blockchain.public_router,        prefix="/public/verify",     tags=["verify-public"])


app.mount("/static", StaticFiles(directory="frontend"), name="static")


@app.on_event("startup")
async def startup_event():
    await init_redis()
    # TODO: Verify DB connectivity


@app.on_event("shutdown")
async def shutdown_event():
    await close_redis()


@app.get("/health")
async def health_check():
    """Liveness probe used by Docker and load balancers."""
    return {"status": "ok"}
