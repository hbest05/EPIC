import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID

from app.database import Base


class ConversationRevocation(Base):
    __tablename__ = "conversation_revocations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    conversation_id = Column(String, nullable=False, index=True)
    revoked_user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    revoked_by_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    revoked_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
