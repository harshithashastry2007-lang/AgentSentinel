from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gateway.approval_db_models import ApprovalRecord
from gateway.approval_models import ApprovalStatus
from gateway.execution_models import (
    ExecutionStatus,
    SecureExecutionRequest,
    SecureExecutionResponse,
)
from gateway.models import (
    Decision,
    PolicyDecision,
    RiskLevel,
)
from gateway.threat_models import ThreatAssessment
from security.approval_service import ApprovalService
from security.policy_engine import PolicyEngine
from security.threat_detector import ThreatDetector
from security.tool_executor import (
    SandboxToolExecutor,
    ToolExecutionError,
    UnsupportedToolError,
)


class SecureExecutionService:
    """Applies threat, policy, and approval controls."""

    def __init__(
        self,
        session: AsyncSession,
    ) -> None:
        self.session = session
        self.policy_engine = PolicyEngine()
        self.threat_detector = ThreatDetector()
        self.executor = SandboxToolExecutor()

    async def execute(
        self,
        execution_request: SecureExecutionRequest,
    ) -> tuple[SecureExecutionResponse, PolicyDecision]:
        invocation = execution_request.invocation
        decision = self.policy_engine.evaluate(invocation)
        threat_assessment = self.threat_detector.analyze(
            invocation
        )

        if threat_assessment.blocked:
            threat_reasons = [
                finding.reason
                for finding in threat_assessment.findings
            ]
            decision = decision.model_copy(
                update={
                    "decision": Decision.DENY,
                    "risk_level": RiskLevel.CRITICAL,
                    "risk_score": max(
                        decision.risk_score,
                        threat_assessment.threat_score,
                    ),
                    "reasons": (
                        decision.reasons + threat_reasons
                    ),
                    "required_controls": sorted(
                        {
                            *decision.required_controls,
                            "runtime_threat_block",
                        }
                    ),
                }
            )

            return (
                self._response(
                    execution_request=execution_request,
                    decision=decision,
                    threat_assessment=threat_assessment,
                    status=ExecutionStatus.BLOCKED,
                    message=(
                        "Execution blocked by runtime "
                        "threat detection"
                    ),
                ),
                decision,
            )

        if decision.decision == Decision.DENY:
            return (
                self._response(
                    execution_request=execution_request,
                    decision=decision,
                    threat_assessment=threat_assessment,
                    status=ExecutionStatus.BLOCKED,
                    message=(
                        "Execution blocked by zero-trust policy"
                    ),
                ),
                decision,
            )

        approval_id: str | None = None

        if decision.decision == Decision.REQUIRE_APPROVAL:
            approval = await self._find_approval(
                execution_request=execution_request
            )

            if approval is None:
                approval = await ApprovalService(
                    self.session
                ).create(
                    request=invocation,
                    decision=decision,
                )

            approval_id = approval.approval_id
            decision = decision.model_copy(
                update={"approval_id": approval_id}
            )

            if not self._is_valid_approval(
                approval=approval,
                execution_request=execution_request,
            ):
                return (
                    self._response(
                        execution_request=execution_request,
                        decision=decision,
                        threat_assessment=threat_assessment,
                        status=(
                            ExecutionStatus.APPROVAL_REQUIRED
                        ),
                        approval_id=approval_id,
                        message=(
                            "Valid human approval is required "
                            "before execution"
                        ),
                    ),
                    decision,
                )

        try:
            output = await self.executor.execute(
                invocation=invocation,
                dry_run=execution_request.dry_run,
            )
        except UnsupportedToolError as exc:
            return (
                self._response(
                    execution_request=execution_request,
                    decision=decision,
                    threat_assessment=threat_assessment,
                    status=ExecutionStatus.BLOCKED,
                    approval_id=approval_id,
                    message=str(exc),
                ),
                decision,
            )
        except ToolExecutionError as exc:
            return (
                self._response(
                    execution_request=execution_request,
                    decision=decision,
                    threat_assessment=threat_assessment,
                    status=ExecutionStatus.FAILED,
                    approval_id=approval_id,
                    message=str(exc),
                ),
                decision,
            )

        return (
            self._response(
                execution_request=execution_request,
                decision=decision,
                threat_assessment=threat_assessment,
                status=ExecutionStatus.EXECUTED,
                approval_id=approval_id,
                output=output,
                message="Tool action executed inside sandbox",
            ),
            decision,
        )

    async def _find_approval(
        self,
        execution_request: SecureExecutionRequest,
    ) -> ApprovalRecord | None:
        invocation = execution_request.invocation

        if execution_request.approval_id is not None:
            statement = select(ApprovalRecord).where(
                ApprovalRecord.approval_id
                == execution_request.approval_id
            )
        else:
            statement = select(ApprovalRecord).where(
                ApprovalRecord.request_id
                == str(invocation.request_id)
            )

        result = await self.session.execute(statement)

        return result.scalar_one_or_none()

    @staticmethod
    def _is_valid_approval(
        approval: ApprovalRecord,
        execution_request: SecureExecutionRequest,
    ) -> bool:
        invocation = execution_request.invocation

        if (
            approval.approval_id
            != execution_request.approval_id
            or approval.request_id
            != str(invocation.request_id)
            or approval.agent_id != invocation.agent_id
            or approval.session_id != invocation.session_id
            or approval.status
            != ApprovalStatus.APPROVED.value
        ):
            return False

        expires_at = approval.expires_at

        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)

        return expires_at > datetime.now(UTC)

    @staticmethod
    def _response(
        execution_request: SecureExecutionRequest,
        decision: PolicyDecision,
        threat_assessment: ThreatAssessment,
        status: ExecutionStatus,
        message: str,
        approval_id: str | None = None,
        output: dict[str, object] | None = None,
    ) -> SecureExecutionResponse:
        invocation = execution_request.invocation

        return SecureExecutionResponse(
            request_id=invocation.request_id,
            status=status,
            tool_name=invocation.tool_name,
            action=invocation.action,
            approval_id=approval_id,
            output=output or {},
            risk_score=decision.risk_score,
            threat_assessment=threat_assessment,
            message=message,
        )