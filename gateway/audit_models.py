from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import JSON, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from gateway.database import Base


class AuditEvent(Base):
    """Persistent record of a zero-trust policy evaluation."""

    __tablename__ = "audit_events"

    event_id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid4()),
    )
    request_id: Mapped[str] = mapped_column(
        String(36),
        unique=True,
        nullable=False,
        index=True,
    )
    agent_id: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
    )
    session_id: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
    )
    tool_name: Mapped[str] = mapped_column(
        String(150),
        nullable=False,
        index=True,
    )
    action: Mapped[str] = mapped_column(
        String(150),
        nullable=False,
    )
    target: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
    )
    decision: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        index=True,
    )
    risk_level: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        index=True,
    )
    risk_score: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )
    reasons: Mapped[list[str]] = mapped_column(
        JSON,
        nullable=False,
        default=list,
    )
    required_controls: Mapped[list[str]] = mapped_column(
        JSON,
        nullable=False,
        default=list,
    )
    previous_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    event_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        unique=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
        index=True,
    )