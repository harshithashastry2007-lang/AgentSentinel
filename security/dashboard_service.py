from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from gateway.approval_db_models import ApprovalRecord
from gateway.approval_models import ApprovalStatus
from gateway.audit_models import AuditEvent
from gateway.dashboard_models import DashboardSummary
from gateway.models import Decision, RiskLevel
from security.audit_service import AuditService


class DashboardService:
    """Builds real-time security dashboard statistics."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get_summary(self) -> DashboardSummary:
        total_evaluations = await self._count_events()
        allowed = await self._count_events(
            AuditEvent.decision == Decision.ALLOW.value
        )
        denied = await self._count_events(
            AuditEvent.decision == Decision.DENY.value
        )
        required_approval = await self._count_events(
            AuditEvent.decision
            == Decision.REQUIRE_APPROVAL.value
        )
        critical_events = await self._count_events(
            AuditEvent.risk_level == RiskLevel.CRITICAL.value
        )
        pending_approvals = await self._count_pending_approvals()
        average_risk_score = await self._average_risk_score()

        audit_chain_valid, _, _ = await AuditService(
            self.session
        ).verify_chain()

        return DashboardSummary(
            total_evaluations=total_evaluations,
            allowed=allowed,
            denied=denied,
            required_approval=required_approval,
            pending_approvals=pending_approvals,
            critical_events=critical_events,
            average_risk_score=average_risk_score,
            audit_chain_valid=audit_chain_valid,
        )

    async def _count_events(
        self,
        condition: object | None = None,
    ) -> int:
        statement = select(func.count()).select_from(
            AuditEvent
        )

        if condition is not None:
            statement = statement.where(condition)

        result = await self.session.execute(statement)

        return int(result.scalar_one())

    async def _count_pending_approvals(self) -> int:
        statement = (
            select(func.count())
            .select_from(ApprovalRecord)
            .where(
                ApprovalRecord.status
                == ApprovalStatus.PENDING.value,
                ApprovalRecord.expires_at > datetime.now(UTC),
            )
        )
        result = await self.session.execute(statement)

        return int(result.scalar_one())

    async def _average_risk_score(self) -> float:
        statement = select(
            func.avg(AuditEvent.risk_score)
        )
        result = await self.session.execute(statement)
        average = result.scalar_one_or_none()

        if average is None:
            return 0.0

        return round(float(average), 2)