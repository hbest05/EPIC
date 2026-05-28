"""
WebSocket router — real-time inbound message delivery.

A client opens wss://<host>/ws after login. The handshake is authenticated the
same way as the REST API: the httpOnly `access_token` JWT cookie (also accepted
as a `?token=` query param fallback for clients that can't attach the cookie to
the upgrade request). On success the socket is registered in the in-process
ConnectionManager; the /messages/send handler then pushes a `new_message`
notification to the recipient's socket if they're connected.

We never read inbound frames as commands — the client only sends keepalives.
The receive loop exists solely to observe the disconnect.
"""

import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status
from jose import JWTError, jwt
from sqlalchemy import select

from app.config import settings
from app.database import AsyncSessionLocal
from app.models.user import User
from app.services.ws_manager import manager

logger = logging.getLogger(__name__)

router = APIRouter()


async def _authenticate(websocket: WebSocket) -> User | None:
    """Resolve the access_token (cookie or ?token= query param) to a live User.

    Returns None on any failure — missing token, bad signature, unknown or
    inactive user — so the caller can reject the handshake.
    """
    token = websocket.cookies.get("access_token") or websocket.query_params.get("token")
    if not token:
        return None

    try:
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
        user_id = payload.get("sub")
        if not user_id:
            return None
    except JWTError:
        return None

    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()

    if user is None or not user.is_active:
        return None
    return user


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    await websocket.accept()

    user = await _authenticate(websocket)
    if user is None:
        # 1008 = policy violation. Accept-then-close lets us send a code rather
        # than a bare handshake rejection.
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    user_id = str(user.id)
    await manager.connect(user_id, websocket)
    try:
        # Block on inbound frames purely to keep the connection open and detect
        # the client going away. Any received text is ignored.
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    except Exception as exc:
        logger.debug("ws receive loop ended user=%s: %s", user_id, exc)
    finally:
        await manager.disconnect(user_id, websocket)
