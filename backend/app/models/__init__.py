# Re-export all ORM models so Alembic autogenerate picks up the full schema
from app.models.user import User  # noqa: F401
from app.models.message import UserKey, Message, MessageAccess  # noqa: F401
from app.models.signal import SignedPrekey, OneTimePrekey, RatchetSession, SkippedMessageKey  # noqa: F401
