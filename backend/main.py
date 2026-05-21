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
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.routers import auth
# from app.routers import messages, blockchain
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

# TODO: Restrict origins to the deployed frontend URL in production
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
# app.include_router(messages.router, prefix="/api/messages", tags=["messages"])
# app.include_router(blockchain.router, prefix="/api/blockchain", tags=["blockchain"])


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