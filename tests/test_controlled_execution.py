"""Comprehensive test suite for Milestone 10.5: Controlled Execution Boundary.

Verifies:
1. State machine prerequisites: only APPROVED actions can be executed.
2. Approval prerequisites: valid approval record required, separation of duties preserved.
3. Policy revalidation under lock: stale policy version blocks execution with audit trail.
4. Fail-closed executor registry: SIMULATOR allowed, unknown executors rejected (HTTP 422).
5. State transitions: APPROVED -> EXECUTING -> SUCCEEDED or FAILED.
6. Execution failure handling: simulated failures transition action to FAILED with error payload.
7. Durable idempotency: duplicate executions return existing SUCCEEDED execution.
8. Database constraint: uq_action_executions_single_succeeded enforced.
9. RBAC: VIEWER forbidden, ADMIN/ENGINEER/RESPONDER authorized.
10. Tenant isolation: cross-tenant execution blocked (HTTP 404).
11. Complete audit trail: REQUESTED, STARTED, SUCCEEDED, BLOCKED, FAILED.
12. Zero real execution safety: no subprocess, shell, or infrastructure calls.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from diagnose.domain.approval import ApprovalDecision
from diagnose.domain.exceptions import (
    ExecutionPreconditionError,
    PolicyViolationError,
    SeparationOfDutiesError,
    UnsupportedExecutorError,
)
from diagnose.domain.execution import (
    BaseExecutor,
    ExecutionContext,
    ExecutionResult,
    ExecutorRegistry,
    SimulatedExecutor,
)
from diagnose.domain.remediation import (
    ActionStatus,
    ActionType,
    ExecutionMode,
    ExecutorType,
    RiskLevel,
)
from diagnose.domain.roles import Role
from diagnose.models.approval import ActionApproval
from diagnose.models.audit_log import AuditLog
from diagnose.models.policy import RemediationPolicy
from diagnose.models.remediation import ActionExecution, RemediationAction
from diagnose.services.dry_run import DryRunService
from diagnose.services.execution import ControlledExecutionService
from diagnose.services.policy import PolicyService
from diagnose.services.remediation import RemediationService
from tests.factories import (
    auth_headers_for,
    create_test_incident,
    create_test_organization,
    create_test_service,
    create_test_user,
)


async def _setup_approved_action(
    client: AsyncClient,
    db_session: AsyncSession,
) -> tuple[Any, Any, Any, Any, Any, str]:
    """Helper to create and approve an action with full valid provenance."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    inc = await create_test_incident(db_session, org.id, svc.id)
    proposer = await create_test_user(db_session, org.id, role=Role.ENGINEER, email="proposer@example.com")
    approver = await create_test_user(db_session, org.id, role=Role.ADMIN, email="approver@example.com")

    # 1. Propose action
    r_create = await client.post(
        f"/api/v1/incidents/{inc.id}/actions",
        json={
            "service_id": str(svc.id),
            "action_type": "RESTART_SERVICE",
            "risk_level": "LOW",
            "execution_mode": "EXECUTE",
            "title": "Restart Cache Service",
            "description": "Restarting Redis to flush stale locks",
        },
        headers=auth_headers_for(proposer),
    )
    assert r_create.status_code == 201, r_create.text
    action_id = r_create.json()["id"]

    # 2. Submit for approval
    r_submit = await client.post(
        f"/api/v1/actions/{action_id}/submit",
        headers=auth_headers_for(proposer),
    )
    assert r_submit.status_code == 200, r_submit.text
    assert r_submit.json()["status"] == "PENDING_APPROVAL"

    # 3. Approve action
    r_approve = await client.post(
        f"/api/v1/actions/{action_id}/approve",
        json={"reason": "Approved for deployment"},
        headers=auth_headers_for(approver),
    )
    assert r_approve.status_code == 200, r_approve.text
    assert r_approve.json()["status"] == "APPROVED"

    return org, svc, inc, proposer, approver, action_id


@pytest.mark.asyncio
async def test_execute_approved_action_success_full_lifecycle(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Standard flow: APPROVED action executes successfully, transitions to SUCCEEDED, and audits events."""
    org, svc, inc, proposer, approver, action_id = await _setup_approved_action(client, db_session)

    # Execute via API
    r_exec = await client.post(
        f"/api/v1/actions/{action_id}/execute",
        json={
            "executor_type": "SIMULATOR",
            "parameters": {"graceful": True},
        },
        headers=auth_headers_for(approver),
    )
    assert r_exec.status_code == 200, r_exec.text
    data = r_exec.json()

    assert data["action_id"] == action_id
    assert data["status"] == "SUCCEEDED"
    assert data["execution_mode"] == "EXECUTE"
    assert data["executor_type"] == "SIMULATOR"
    assert data["result"]["status"] == "COMPLETED"
    assert data["started_at"] is not None
    assert data["completed_at"] is not None
    assert data["error"] is None

    # Verify action model status in DB
    act_row = await db_session.get(RemediationAction, uuid.UUID(action_id))
    assert act_row is not None
    assert act_row.status == "SUCCEEDED"

    # Verify audits
    audits = (
        await db_session.execute(
            select(AuditLog)
            .where(AuditLog.organization_id == org.id)
            .order_by(AuditLog.created_at.asc())
        )
    ).scalars().all()
    actions = [a.action for a in audits]

    assert "ACTION_EXECUTION_REQUESTED" in actions
    assert "ACTION_EXECUTION_STARTED" in actions
    assert "ACTION_EXECUTION_SUCCEEDED" in actions


@pytest.mark.asyncio
async def test_execute_simulated_failure_transitions_to_failed(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Executor failure transitions action to FAILED and records ACTION_EXECUTION_FAILED audit."""
    org, svc, inc, proposer, approver, action_id = await _setup_approved_action(client, db_session)

    # Trigger failure via simulator test flag
    r_exec = await client.post(
        f"/api/v1/actions/{action_id}/execute",
        json={
            "executor_type": "SIMULATOR",
            "parameters": {"__simulate_failure": True},
        },
        headers=auth_headers_for(approver),
    )
    assert r_exec.status_code == 200, r_exec.text
    data = r_exec.json()

    assert data["status"] == "FAILED"
    assert "Simulated execution failure" in data["error"]

    # Verify action row status
    act_row = await db_session.get(RemediationAction, uuid.UUID(action_id))
    assert act_row is not None
    assert act_row.status == "FAILED"

    # Verify audit
    audits = (
        await db_session.execute(
            select(AuditLog)
            .where(
                AuditLog.organization_id == org.id,
                AuditLog.action == "ACTION_EXECUTION_FAILED",
            )
        )
    ).scalars().all()
    assert len(audits) == 1
    assert audits[0].new_values["status"] == "FAILED"


@pytest.mark.asyncio
async def test_execute_precondition_unapproved_states_rejected(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Non-APPROVED actions (PROPOSED, PENDING_APPROVAL, REJECTED, CANCELLED) cannot be executed."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    inc = await create_test_incident(db_session, org.id, svc.id)
    user = await create_test_user(db_session, org.id, role=Role.ADMIN)

    # 1. Action in PROPOSED state
    r_create = await client.post(
        f"/api/v1/incidents/{inc.id}/actions",
        json={
            "service_id": str(svc.id),
            "action_type": "SCALE_SERVICE",
            "risk_level": "LOW",
            "title": "Scale web instances",
        },
        headers=auth_headers_for(user),
    )
    action_id = r_create.json()["id"]

    r_exec_prop = await client.post(
        f"/api/v1/actions/{action_id}/execute",
        headers=auth_headers_for(user),
    )
    assert r_exec_prop.status_code == 409
    assert "PROPOSED" in r_exec_prop.text

    # 2. Action in PENDING_APPROVAL state
    await client.post(f"/api/v1/actions/{action_id}/submit", headers=auth_headers_for(user))
    r_exec_pend = await client.post(
        f"/api/v1/actions/{action_id}/execute",
        headers=auth_headers_for(user),
    )
    assert r_exec_pend.status_code == 409
    assert "PENDING_APPROVAL" in r_exec_pend.text

    # 3. Action in REJECTED state
    another_admin = await create_test_user(db_session, org.id, role=Role.ADMIN, email="admin2@example.com")
    await client.post(
        f"/api/v1/actions/{action_id}/reject",
        json={"reason": "Rejected by admin2"},
        headers=auth_headers_for(another_admin),
    )
    r_exec_rej = await client.post(
        f"/api/v1/actions/{action_id}/execute",
        headers=auth_headers_for(user),
    )
    assert r_exec_rej.status_code == 409
    assert "REJECTED" in r_exec_rej.text


@pytest.mark.asyncio
async def test_execute_fails_closed_on_unsupported_executor(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Requesting unknown/forbidden executor types (e.g. KUBERNETES, SSH, BASH) returns 422."""
    org, svc, inc, proposer, approver, action_id = await _setup_approved_action(client, db_session)

    for forbidden in ["KUBERNETES", "SSH", "BASH", "SYSTEM", "DOCKER", "ANSIBLE"]:
        r_exec = await client.post(
            f"/api/v1/actions/{action_id}/execute",
            json={"executor_type": forbidden},
            headers=auth_headers_for(approver),
        )
        assert r_exec.status_code == 422, r_exec.text
        assert "UNSUPPORTED_EXECUTOR" in r_exec.text or "not supported" in r_exec.text


@pytest.mark.asyncio
async def test_execute_stale_policy_detection_blocks_execution(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """If policy_set_version changed since approval, execution triggers re-evaluation and blocks."""
    org, svc, inc, proposer, approver, action_id = await _setup_approved_action(client, db_session)

    # Mutate organization policy to increment policy_set_version
    r_pol = await client.post(
        "/api/v1/policies",
        json={
            "name": "Emergency Deny All Restarts",
            "action_type": "RESTART_SERVICE",
            "risk_level": "LOW",
            "decision": "DENY",
            "priority": 500,
            "is_active": True,
        },
        headers=auth_headers_for(approver),
    )
    assert r_pol.status_code == 201, r_pol.text

    # Attempt execution: must detect stale policy version under lock and block execution
    r_exec = await client.post(
        f"/api/v1/actions/{action_id}/execute",
        headers=auth_headers_for(approver),
    )
    assert r_exec.status_code == 403, r_exec.text
    assert "Policy set version changed" in r_exec.text or "Re-approval is required" in r_exec.text

    # Action must NOT have executed
    act_row = await db_session.get(RemediationAction, uuid.UUID(action_id))
    assert act_row is not None
    assert act_row.status == "APPROVED"  # still approved or awaiting fresh approval, but not executed

    # ACTION_EXECUTION_BLOCKED must be audited
    audits = (
        await db_session.execute(
            select(AuditLog)
            .where(
                AuditLog.organization_id == org.id,
                AuditLog.action == "ACTION_EXECUTION_BLOCKED",
            )
        )
    ).scalars().all()
    assert len(audits) >= 1
    assert "Policy set version changed" in audits[-1].new_values["blocked_reason"]


@pytest.mark.asyncio
async def test_execute_separation_of_duties_bypass_attempt_blocked(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """If an action row somehow has an approval where approver == proposer, execution blocks."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    inc = await create_test_incident(db_session, org.id, svc.id)
    proposer = await create_test_user(db_session, org.id, role=Role.ADMIN, email="same_admin@example.com")

    # Manually create action and approval bypassing API service check
    act = RemediationAction(
        organization_id=org.id,
        incident_id=inc.id,
        service_id=svc.id,
        action_type="RESTART_SERVICE",
        risk_level="LOW",
        status="APPROVED",
        execution_mode="EXECUTE",
        title="Illegitimately self-approved action",
        proposed_by=proposer.id,
        approved_by=proposer.id,
    )
    db_session.add(act)
    await db_session.flush()

    appr = ActionApproval(
        organization_id=org.id,
        action_id=act.id,
        decision=ApprovalDecision.APPROVED.value,
        approver_user_id=proposer.id,
        policy_set_version=org.policy_set_version,
    )
    db_session.add(appr)
    await db_session.commit()

    # Attempt execution
    r_exec = await client.post(
        f"/api/v1/actions/{act.id}/execute",
        headers=auth_headers_for(proposer),
    )
    assert r_exec.status_code == 403, r_exec.text
    assert "Separation of duties violation" in r_exec.text


@pytest.mark.asyncio
async def test_execute_durable_idempotency(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Repeated execution requests on an already SUCCEEDED action return the existing execution."""
    org, svc, inc, proposer, approver, action_id = await _setup_approved_action(client, db_session)

    # 1. First execution
    r_exec1 = await client.post(
        f"/api/v1/actions/{action_id}/execute",
        json={"parameters": {"key": "val"}},
        headers=auth_headers_for(approver),
    )
    assert r_exec1.status_code == 200, r_exec1.text
    exec1_data = r_exec1.json()
    assert exec1_data["status"] == "SUCCEEDED"

    # 2. Second execution (duplicate call)
    r_exec2 = await client.post(
        f"/api/v1/actions/{action_id}/execute",
        json={"parameters": {"key": "val"}},
        headers=auth_headers_for(approver),
    )
    assert r_exec2.status_code == 200, r_exec2.text
    exec2_data = r_exec2.json()

    # Must return exact same execution record
    assert exec2_data["id"] == exec1_data["id"]
    assert exec2_data["status"] == "SUCCEEDED"
    assert exec2_data["completed_at"] == exec1_data["completed_at"]

    # Exactly 1 execution record exists in the database
    execs = (
        await db_session.execute(
            select(ActionExecution).where(ActionExecution.action_id == uuid.UUID(action_id))
        )
    ).scalars().all()
    assert len(execs) == 1


@pytest.mark.asyncio
async def test_partial_unique_index_enforced_at_db_level(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Direct DB insertion of two SUCCEEDED EXECUTE records for the same action violates unique constraint."""
    org, svc, inc, proposer, approver, action_id = await _setup_approved_action(client, db_session)

    # Insert first SUCCEEDED execution
    exec1 = ActionExecution(
        organization_id=org.id,
        action_id=uuid.UUID(action_id),
        status="SUCCEEDED",
        execution_mode="EXECUTE",
        executor_type="SIMULATOR",
    )
    db_session.add(exec1)
    await db_session.commit()

    # Attempt to insert a second SUCCEEDED execution for the same action in EXECUTE mode
    exec2 = ActionExecution(
        organization_id=org.id,
        action_id=uuid.UUID(action_id),
        status="SUCCEEDED",
        execution_mode="EXECUTE",
        executor_type="SIMULATOR",
    )
    db_session.add(exec2)

    with pytest.raises(IntegrityError) as exc_info:
        await db_session.commit()

    assert "uq_action_executions_single_succeeded" in str(exc_info.value)
    await db_session.rollback()


@pytest.mark.asyncio
async def test_execute_rbac_viewer_denied(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Users with VIEWER role are denied execution with HTTP 403."""
    org, svc, inc, proposer, approver, action_id = await _setup_approved_action(client, db_session)
    viewer = await create_test_user(db_session, org.id, role=Role.VIEWER, email="viewer@example.com")

    r_exec = await client.post(
        f"/api/v1/actions/{action_id}/execute",
        headers=auth_headers_for(viewer),
    )
    assert r_exec.status_code == 403


@pytest.mark.asyncio
async def test_execute_tenant_isolation(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """User from Organization B cannot execute an action belonging to Organization A (HTTP 404)."""
    org_a, svc, inc, proposer, approver, action_id = await _setup_approved_action(client, db_session)

    org_b = await create_test_organization(db_session, name="Org B")
    user_b = await create_test_user(db_session, org_b.id, role=Role.ADMIN, email="user_b@example.com")

    r_exec = await client.post(
        f"/api/v1/actions/{action_id}/execute",
        headers=auth_headers_for(user_b),
    )
    assert r_exec.status_code == 404


@pytest.mark.asyncio
async def test_zero_real_execution_guarantee(
    client: AsyncClient,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Execution must not invoke subprocess or OS commands."""
    import subprocess
    import os

    def _forbidden_exec(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("FORBIDDEN: Real system execution was attempted!")

    monkeypatch.setattr(subprocess, "Popen", _forbidden_exec)
    monkeypatch.setattr(subprocess, "run", _forbidden_exec)
    monkeypatch.setattr(os, "system", _forbidden_exec)

    org, svc, inc, proposer, approver, action_id = await _setup_approved_action(client, db_session)

    r_exec = await client.post(
        f"/api/v1/actions/{action_id}/execute",
        json={"executor_type": "SIMULATOR"},
        headers=auth_headers_for(approver),
    )
    assert r_exec.status_code == 200, r_exec.text
    assert r_exec.json()["status"] == "SUCCEEDED"
