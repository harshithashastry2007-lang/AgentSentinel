from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gateway.approval_db_models import ApprovalRecord
from gateway.approval_models import (
    ApprovalAction,
    ApprovalDecisionRequest,
    ApprovalStatus,
)
from gateway.config import Settings, get_settings
from gateway.models import PolicyDecision, ToolInvocationRequest


class ApprovalNotFoundError(Exception):
    """Raised when an approval request does not exist."""


class ApprovalStateError(Exception):
    """Raised when an approval cannot be resolved."""


class ApprovalService:
    """Manages human approval requests for risky agent actions."""

    def __init__(
        self,
        session: AsyncSession,
        settings: Settings | None = None,
    ) -> None:
        self.session = session
        self.settings = settings or get_settings()

    async def create(
        self,
        request: ToolInvocationRequest,
        decision: PolicyDecision,
    ) -> ApprovalRecord:
        now = datetime.now(UTC)

        approval = ApprovalRecord(
            request_id=str(request.request_id),
            agent_id=request.agent_id,
            session_id=request.session_id,
            tool_name=request.tool_name,
            action=request.action,
            target=request.target,
            risk_level=decision.risk_level.value,
            risk_score=decision.risk_score,
            reasons=decision.reasons,
            required_controls=decision.required_controls,
            status=ApprovalStatus.PENDING.value,
            created_at=now,
            expires_at=now
            + timedelta(
                minutes=self.settings.approval_timeout_minutes
            ),
        )

        self.session.add(approval)
        await self.session.commit()
        await self.session.refresh(approval)

        return approval

    async def list_pending(
        self,
        limit: int = 50,
    ) -> list[ApprovalRecord]:
        now = datetime.now(UTC)

        statement = (
            select(ApprovalRecord)
            .where(
                ApprovalRecord.status
                == ApprovalStatus.PENDING.value,
                ApprovalRecord.expires_at > now,
            )
            .order_by(ApprovalRecord.created_at.asc())
            .limit(limit)
        )
        result = await self.session.execute(statement)

        return list(result.scalars().all())

    async def resolve(
        self,
        approval_id: str,
        resolution: ApprovalDecisionRequest,
    ) -> ApprovalRecord:
        statement = select(ApprovalRecord).where(
            ApprovalRecord.approval_id == approval_id
        )
        result = await self.session.execute(statement)
        approval = result.scalar_one_or_none()

        if approval is None:
            raise ApprovalNotFoundError

        if approval.status != ApprovalStatus.PENDING.value:
            raise ApprovalStateError(
                "Approval request has already been resolved"
            )

        now = datetime.now(UTC)
        expires_at = approval.expires_at

        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)

        if expires_at <= now:
            approval.status = ApprovalStatus.EXPIRED.value
            await self.session.commit()

            raise ApprovalStateError(
                "Approval request has expired"
            )

        if resolution.action == ApprovalAction.APPROVE:
            approval.status = ApprovalStatus.APPROVED.value
        else:
            approval.status = ApprovalStatus.REJECTED.value

        approval.approver_id = resolution.approver_id
        approval.comment = resolution.comment
        approval.resolved_at = now

        await self.session.commit()
        await self.session.refresh(approval)

        return approval