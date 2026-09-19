from datetime import datetime
from uuid import uuid4

from sqlalchemy import JSON, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from gateway.database import Base


class ApprovalRecord(Base):
    """Persistent human-approval request."""

    __tablename__ = "approval_requests"

    approval_id: Mapped[str] = mapped_column(
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
    )
    action: Mapped[str] = mapped_column(
        String(150),
        nullable=False,
    )
    target: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
    )
    risk_level: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
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
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        index=True,
    )
    approver_id: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )
    comment: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )
    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )