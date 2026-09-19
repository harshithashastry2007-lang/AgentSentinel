import hashlib
import json
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gateway.audit_models import AuditEvent
from gateway.models import PolicyDecision, ToolInvocationRequest

GENESIS_HASH = "0" * 64


class AuditService:
    """Creates and verifies hash-chained security audit events."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def record(
        self,
        request: ToolInvocationRequest,
        decision: PolicyDecision,
    ) -> AuditEvent:
        previous_hash = await self._get_latest_hash()

        payload = {
            "request_id": str(request.request_id),
            "agent_id": request.agent_id,
            "session_id": request.session_id,
            "tool_name": request.tool_name,
            "action": request.action,
            "target": request.target,
            "decision": decision.decision.value,
            "risk_level": decision.risk_level.value,
            "risk_score": decision.risk_score,
            "reasons": decision.reasons,
            "required_controls": decision.required_controls,
            "created_at": self._normalize_timestamp(
                decision.evaluated_at
            ),
        }

        event_hash = self._calculate_hash(
            previous_hash=previous_hash,
            payload=payload,
        )

        event = AuditEvent(
            request_id=payload["request_id"],
            agent_id=request.agent_id,
            session_id=request.session_id,
            tool_name=request.tool_name,
            action=request.action,
            target=request.target,
            decision=decision.decision.value,
            risk_level=decision.risk_level.value,
            risk_score=decision.risk_score,
            reasons=decision.reasons,
            required_controls=decision.required_controls,
            previous_hash=previous_hash,
            event_hash=event_hash,
            created_at=decision.evaluated_at,
        )

        self.session.add(event)
        await self.session.commit()
        await self.session.refresh(event)

        return event

    async def list_recent(
        self,
        limit: int = 50,
    ) -> list[AuditEvent]:
        statement = (
            select(AuditEvent)
            .order_by(
                AuditEvent.created_at.desc(),
                AuditEvent.event_id.desc(),
            )
            .limit(limit)
        )
        result = await self.session.execute(statement)

        return list(result.scalars().all())

    async def verify_chain(
        self,
    ) -> tuple[bool, int, str | None]:
        statement = select(AuditEvent).order_by(
            AuditEvent.created_at.asc(),
            AuditEvent.event_id.asc(),
        )
        result = await self.session.execute(statement)
        events = list(result.scalars().all())

        expected_previous_hash = GENESIS_HASH

        for event in events:
            payload = self._payload_from_event(event)
            expected_event_hash = self._calculate_hash(
                previous_hash=expected_previous_hash,
                payload=payload,
            )

            if (
                event.previous_hash != expected_previous_hash
                or event.event_hash != expected_event_hash
            ):
                return False, len(events), event.event_id

            expected_previous_hash = event.event_hash

        return True, len(events), None

    async def _get_latest_hash(self) -> str:
        statement = (
            select(AuditEvent.event_hash)
            .order_by(
                AuditEvent.created_at.desc(),
                AuditEvent.event_id.desc(),
            )
            .limit(1)
        )
        result = await self.session.execute(statement)

        return result.scalar_one_or_none() or GENESIS_HASH

    @classmethod
    def _payload_from_event(
        cls,
        event: AuditEvent,
    ) -> dict[str, object]:
        return {
            "request_id": event.request_id,
            "agent_id": event.agent_id,
            "session_id": event.session_id,
            "tool_name": event.tool_name,
            "action": event.action,
            "target": event.target,
            "decision": event.decision,
            "risk_level": event.risk_level,
            "risk_score": event.risk_score,
            "reasons": event.reasons,
            "required_controls": event.required_controls,
            "created_at": cls._normalize_timestamp(
                event.created_at
            ),
        }

    @staticmethod
    def _normalize_timestamp(value: datetime) -> str:
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        else:
            value = value.astimezone(UTC)

        return value.isoformat()

    @staticmethod
    def _calculate_hash(
        previous_hash: str,
        payload: dict[str, object],
    ) -> str:
        canonical_payload = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        hash_input = f"{previous_hash}:{canonical_payload}"

        return hashlib.sha256(hash_input.encode("utf-8")).hexdigest()