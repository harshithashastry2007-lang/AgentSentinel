from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import StaticPool

from gateway.audit_models import AuditEvent
from gateway.database import Base
from gateway.models import ToolInvocationRequest
from security.audit_service import GENESIS_HASH, AuditService
from security.policy_engine import PolicyEngine


@pytest_asyncio.fixture
async def database_session() -> AsyncIterator[AsyncSession]:
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
    )

    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    async with session_factory() as session:
        yield session

    await engine.dispose()


@pytest.mark.asyncio
async def test_policy_decision_is_persisted(
    database_session: AsyncSession,
) -> None:
    request = ToolInvocationRequest(
        agent_id="demo-agent-01",
        session_id="session-301",
        tool_name="filesystem",
        action="read_file",
        requested_scopes=["files:read"],
        target="README.md",
    )
    decision = PolicyEngine().evaluate(request)

    event = await AuditService(database_session).record(
        request=request,
        decision=decision,
    )

    count_statement = select(func.count()).select_from(AuditEvent)
    result = await database_session.execute(count_statement)

    assert result.scalar_one() == 1
    assert event.request_id == str(request.request_id)
    assert event.decision == decision.decision.value
    assert event.risk_score == decision.risk_score
    assert event.previous_hash == GENESIS_HASH
    assert len(event.event_hash) == 64


@pytest.mark.asyncio
async def test_audit_events_form_a_hash_chain(
    database_session: AsyncSession,
) -> None:
    service = AuditService(database_session)

    first_request = ToolInvocationRequest(
        agent_id="demo-agent-01",
        session_id="session-302",
        tool_name="filesystem",
        action="read_file",
        target="README.md",
    )
    first_decision = PolicyEngine().evaluate(first_request)
    first_event = await service.record(
        request=first_request,
        decision=first_decision,
    )

    second_request = ToolInvocationRequest(
        agent_id="demo-agent-01",
        session_id="session-302",
        tool_name="powershell",
        action="execute_command",
        requested_scopes=["shell:execute"],
        target="C:/Windows/System32",
    )
    second_decision = PolicyEngine().evaluate(second_request)
    second_event = await service.record(
        request=second_request,
        decision=second_decision,
    )

    assert first_event.previous_hash == GENESIS_HASH
    assert second_event.previous_hash == first_event.event_hash
    assert second_event.event_hash != first_event.event_hash
    assert len(second_event.event_hash) == 64

@pytest.mark.asyncio
async def test_valid_audit_chain_passes_verification(
    database_session: AsyncSession,
) -> None:
    request = ToolInvocationRequest(
        agent_id="demo-agent-01",
        session_id="session-303",
        tool_name="filesystem",
        action="read_file",
        target="README.md",
    )
    decision = PolicyEngine().evaluate(request)

    service = AuditService(database_session)
    await service.record(
        request=request,
        decision=decision,
    )

    valid, event_count, broken_event_id = (
        await service.verify_chain()
    )

    assert valid is True
    assert event_count == 1
    assert broken_event_id is None


@pytest.mark.asyncio
async def test_modified_audit_event_is_detected(
    database_session: AsyncSession,
) -> None:
    request = ToolInvocationRequest(
        agent_id="demo-agent-01",
        session_id="session-304",
        tool_name="filesystem",
        action="read_file",
        target="README.md",
    )
    decision = PolicyEngine().evaluate(request)

    service = AuditService(database_session)
    event = await service.record(
        request=request,
        decision=decision,
    )

    event.risk_score = 99
    await database_session.commit()

    valid, event_count, broken_event_id = (
        await service.verify_chain()
    )

    assert valid is False
    assert event_count == 1
    assert broken_event_id == event.event_id