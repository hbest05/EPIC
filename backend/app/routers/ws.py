"""
WebSocket router — real-time inbound message delivery + cover traffic heartbeats.

A client opens wss://<host>/ws after login. The handshake is authenticated via
the httpOnly `access_token` JWT cookie sent automatically by the browser on
same-origin WebSocket upgrades. On success the socket is registered in the
in-process ConnectionManager; the /messages/send handler then pushes a
`new_message` notification to the recipient's socket if they're connected.

Cover traffic: after connecting, a background task (_heartbeat_task) sends a
256-byte random payload to the client at uniformly random [3, 10] second
intervals. The frames are indistinguishable in size from padded real-message
frames, reducing timing correlation between message send and receive events.
Clients silently discard frames with type != "new_message".

We never read inbound frames as commands — the client only sends keepalives.
The receive loop exists solely to observe the disconnect.
"""

import asyncio
import base64
import logging
import os
import random
import uuid

import jwt  # PyJWT — replaces python-jose (PYSEC-2024-232, PYSEC-2024-233)
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status
from sqlalchemy import select

from app.config import settings
from app.database import AsyncSessionLocal
from app.models.user import User
from app.services.ws_manager import manager

logger = logging.getLogger(__name__)

router = APIRouter()


async def _authenticate(websocket: WebSocket) -> User | None:
    """Resolve the access_token cookie to a live User.

    Returns None on any failure — missing token, bad signature, unknown or
    inactive user — so the caller can reject the handshake.
    """
    token = websocket.cookies.get("access_token")
    if not token:
        return None

    try:
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
        user_id = payload.get("sub")
        if not user_id:
            return None
    except jwt.PyJWTError:
        return None

    # User.id is a UUID(as_uuid=True) column — asyncpg needs a uuid.UUID, not
    # the plain string from the JWT sub claim, or the query silently matches
    # nothing and auth fails (surfacing as a 1008/403).
    try:
        uid = uuid.UUID(user_id)
    except ValueError:
        return None

    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.id == uid))
        user = result.scalar_one_or_none()

    if user is None or not user.is_active:
        logger.warning("ws auth: no user found for id=%r", uid)
        return None
    return user


async def _heartbeat_task(websocket: WebSocket) -> None:
    """Send cover-traffic frames at uniformly random 3–10 second intervals.

    Each frame carries 256 bytes of CSPRNG output encoded as base64 (344 chars).
    This matches the padded size of real message payloads, making heartbeat
    frames indistinguishable from real messages at the TLS record layer.
    The frame type field is "heartbeat" so clients can silently discard it.
    """
    try:
        while True:
            await asyncio.sleep(random.uniform(3.0, 10.0))
            payload = base64.b64encode(os.urandom(256)).decode()
            await websocket.send_json({"type": "heartbeat", "payload": payload})
    except Exception:
        pass


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
    heartbeat = asyncio.create_task(_heartbeat_task(websocket))
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
        heartbeat.cancel()
        await asyncio.gather(heartbeat, return_exceptions=True)
        await manager.disconnect(user_id, websocket)
