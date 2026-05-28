"""
WebSocket connection registry for real-time message delivery.

Keeps an in-process map of user_id -> set of live WebSocket connections so the
/send handler can push a notification to a recipient the moment a message is
persisted, instead of the client polling.

Scope note: this registry lives in a single process. With multiple uvicorn
workers a recipient connected to worker A won't receive a push for a message
sent through worker B. The client keeps pollInbox as a fallback, so messages
are never lost — they just arrive on the next poll/reconnect instead of
instantly. A Redis pub/sub fan-out would be the multi-worker upgrade path.
"""

import asyncio
import logging
from typing import Any

from fastapi import WebSocket

logger = logging.getLogger(__name__)


class ConnectionManager:
    def __init__(self) -> None:
        # user_id (str) -> set of connected sockets (a user may have several
        # clients/tabs open at once).
        self._connections: dict[str, set[WebSocket]] = {}
        self._lock = asyncio.Lock()

    async def connect(self, user_id: str, websocket: WebSocket) -> None:
        async with self._lock:
            self._connections.setdefault(user_id, set()).add(websocket)
        logger.info("ws connect user=%s (now %d socket(s))",
                    user_id, len(self._connections.get(user_id, ())))

    async def disconnect(self, user_id: str, websocket: WebSocket) -> None:
        async with self._lock:
            sockets = self._connections.get(user_id)
            if sockets:
                sockets.discard(websocket)
                if not sockets:
                    self._connections.pop(user_id, None)
        logger.info("ws disconnect user=%s", user_id)

    async def send_to_user(self, user_id: str, payload: dict[str, Any]) -> None:
        """Push a JSON payload to every live socket for a user.

        Best-effort: dead sockets are pruned, failures are swallowed so a
        broken recipient connection never affects the sender's request.
        """
        async with self._lock:
            sockets = list(self._connections.get(user_id, ()))
        if not sockets:
            return

        dead: list[WebSocket] = []
        for ws in sockets:
            try:
                await ws.send_json(payload)
            except Exception as exc:  # connection closed mid-send, etc.
                logger.debug("ws send failed user=%s: %s", user_id, exc)
                dead.append(ws)

        for ws in dead:
            await self.disconnect(user_id, ws)


# Module-level singleton shared by the /ws endpoint and the /send handler.
manager = ConnectionManager()
