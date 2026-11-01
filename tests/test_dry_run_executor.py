"""Comprehensive test suite for Milestone 10.3: Remediation Dry-Run Executor."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import uuid

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from diagnose.domain.dry_run import (
    DryRunPlan,
    DryRunPlanBuilder,
    DryRunResult,
    DryRunStatus,
    ExecutionValidator,
)
from diagnose.domain.exceptions import (
    ActionNotExecutableError,
    ExecutionValidationError,
    PolicyViolationError,
)
from diagnose.domain.policy import PolicyDecision
from diagnose.domain.remediation import (
    ActionStatus,
    ActionType,
    ExecutionMode,
    ExecutorType,
    RiskLevel,
)
from diagnose.domain.roles import Role
from diagnose.models.audit_log import AuditLog
from diagnose.models.organization import Organization
from diagnose.models.policy import RemediationPolicy
from diagnose.models.remediation import ActionExecution, RemediationAction
from diagnose.models.service import Service
from diagnose.models.user import User
from diagnose.schemas.dry_run import DryRunRequest
from diagnose.schemas.policy import PolicyCreateRequest
from diagnose.schemas.remediation import ActionCreateRequest
from diagnose.services.dry_run import DryRunService
from diagnose.services.policy import PolicyService
from diagnose.services.remediation import RemediationService
from tests.factories import (
    auth_headers_for,
    create_test_incident,
    create_test_organization,
    create_test_service,
    create_test_user,
)


async def approve_test_action(
    rem_service: RemediationService,
    session: AsyncSession,
    org_id: uuid.UUID,
    action_id: uuid.UUID,
    admin_id: uuid.UUID,
    actor_role: Role = Role.ADMIN,
) -> RemediationAction:
    """Helper to transition PROPOSED -> PENDING_APPROVAL -> APPROVED adhering to separation of duties."""
    await rem_service.submit_for_approval(session, org_id, action_id, admin_id)
    approver = await create_test_user(
        session, org_id, role=Role.ADMIN, email=f"approver-{uuid.uuid4().hex[:6]}@example.com"
    )
    return await rem_service.approve_action(session, org_id, action_id, approver.id, actor_role=actor_role)


@pytest.mark.asyncio
async def test_dry_run_valid_approved_action(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """An approved action executes a deterministic dry run with no real infrastructure changes."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id, name="payment-gateway")
    inc = await create_test_incident(db_session, org.id, svc.id)
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)

    rem_service = RemediationService()
    req = ActionCreateRequest(
        service_id=svc.id,
        action_type=ActionType.RESTART_SERVICE,
        risk_level=RiskLevel.LOW,
        title="Restart crashed payment gateway",
        preconditions={"grace_period_seconds": 15, "restart_type": "rolling", "environment": "production"},
    )
    action = await rem_service.propose_action(db_session, org.id, inc.id, req, admin.id, actor_role=Role.ADMIN)
    await approve_test_action(rem_service, db_session, org.id, action.id, admin.id, actor_role=Role.ADMIN)
    await db_session.commit()

    headers = auth_headers_for(admin)
    resp = await client.post(
        f"/api/v1/actions/{action.id}/dry-run",
        headers=headers,
        json={"parameters": {"grace_period_seconds": 20}},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()

    assert data["status"] == "DRY_RUN_SUCCESS"
    assert data["no_real_execution"] is True
    assert data["safety_checks_passed"] is True
    assert data["action_id"] == str(action.id)
    assert "plan" in data and data["plan"] is not None

    plan = data["plan"]
    assert plan["action_type"] == "RESTART_SERVICE"
    assert plan["service_name"] == "payment-gateway"
    assert plan["environment"] == "production"
    assert plan["executor_type"] == "SIMULATOR"
    assert plan["execution_mode"] == "DRY_RUN"
    assert len(plan["ordered_steps"]) == 6
    assert plan["plan_hash"] is not None

    # Verify ActionExecution persisted
    stmt = select(ActionExecution).where(ActionExecution.action_id == action.id)
    executions = (await db_session.execute(stmt)).scalars().all()
    assert len(executions) == 1
    exec_row = executions[0]
    assert exec_row.status == "SUCCEEDED"
    assert exec_row.execution_mode == "DRY_RUN"
    assert exec_row.executor_type == "SIMULATOR"
    assert exec_row.plan_hash == plan["plan_hash"]
    assert exec_row.result["no_real_execution"] is True

    # Crucial: RemediationAction status must still be APPROVED (not falsely transitioned)
    stmt_act = select(RemediationAction).where(RemediationAction.id == action.id)
    act_reloaded = (await db_session.execute(stmt_act)).scalars().first()
    assert act_reloaded.status == ActionStatus.APPROVED.value


@pytest.mark.asyncio
async def test_dry_run_unapproved_action_rejected(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """An action in PROPOSED status cannot be dry-run (must be APPROVED)."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    inc = await create_test_incident(db_session, org.id, svc.id)
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)

    rem_service = RemediationService()
    req = ActionCreateRequest(
        service_id=svc.id,
        action_type=ActionType.RESTART_SERVICE,
        risk_level=RiskLevel.HIGH,
        title="Restart service without approval",
    )
    action = await rem_service.propose_action(db_session, org.id, inc.id, req, admin.id, actor_role=Role.ADMIN)
    await db_session.commit()

    headers = auth_headers_for(admin)
    resp = await client.post(
        f"/api/v1/actions/{action.id}/dry-run",
        headers=headers,
    )
    assert resp.status_code == 400
    err = resp.json()["error"]
    assert err["code"] == "ACTION_NOT_EXECUTABLE"
    assert "must be APPROVED" in err["message"]


@pytest.mark.asyncio
async def test_dry_run_denied_by_policy(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """If the active policy denies the action, dry-run is stopped with 403."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    inc = await create_test_incident(db_session, org.id, svc.id)
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)

    # Add DENY policy
    pol_service = PolicyService()
    pol_req = PolicyCreateRequest(
        name="Deny Production Restarts",
        action_type=ActionType.RESTART_SERVICE,
        environment="production",
        decision=PolicyDecision.DENY,
        priority=1,
    )
    await pol_service.create_policy(db_session, org.id, pol_req, admin.id)
    await db_session.commit()

    # Manually create an action pretending to be approved
    action = RemediationAction(
        organization_id=org.id,
        incident_id=inc.id,
        service_id=svc.id,
        action_type=ActionType.RESTART_SERVICE,
        risk_level=RiskLevel.HIGH,
        status=ActionStatus.APPROVED.value,
        title="Bypass attempt",
        preconditions={"environment": "production"},
    )
    db_session.add(action)
    await db_session.commit()

    action_id = action.id
    headers = auth_headers_for(admin)
    resp = await client.post(
        f"/api/v1/actions/{action_id}/dry-run",
        headers=headers,
    )
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "POLICY_VIOLATION"

    # ActionExecution recorded as FAILED
    db_session.expire_all()
    stmt = select(ActionExecution).where(ActionExecution.action_id == action_id)
    exec_row = (await db_session.execute(stmt)).scalars().first()
    assert exec_row is not None
    assert exec_row.status == "FAILED"
    assert "Policy violation" in exec_row.error


@pytest.mark.asyncio
async def test_dry_run_stale_policy_recheck(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """If policy set version changed after approval, dry-run re-evaluates active policies."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    inc = await create_test_incident(db_session, org.id, svc.id)
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)

    rem_service = RemediationService()
    req = ActionCreateRequest(
        service_id=svc.id,
        action_type=ActionType.RESTART_SERVICE,
        risk_level=RiskLevel.LOW,
        title="Restart action",
        preconditions={"environment": "production"},
    )
    action = await rem_service.propose_action(db_session, org.id, inc.id, req, admin.id, actor_role=Role.ADMIN)
    await approve_test_action(rem_service, db_session, org.id, action.id, admin.id, actor_role=Role.ADMIN)
    await db_session.commit()

    # Now an admin introduces a new DENY policy, incrementing policy_set_version
    pol_service = PolicyService()
    pol_req = PolicyCreateRequest(
        name="Emergency Freeze",
        action_type=ActionType.RESTART_SERVICE,
        decision=PolicyDecision.DENY,
        priority=1,
    )
    await pol_service.create_policy(db_session, org.id, pol_req, admin.id)
    await db_session.commit()

    # Dry-run must re-evaluate against version 2 and block execution
    headers = auth_headers_for(admin)
    resp = await client.post(
        f"/api/v1/actions/{action.id}/dry-run",
        headers=headers,
    )
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "POLICY_VIOLATION"


@pytest.mark.asyncio
async def test_dry_run_cross_tenant_isolation(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Tenant B cannot dry-run an action belonging to Tenant A (returns 404)."""
    org_a = await create_test_organization(db_session, name="Org A")
    org_b = await create_test_organization(db_session, name="Org B")

    svc_a = await create_test_service(db_session, org_a.id)
    inc_a = await create_test_incident(db_session, org_a.id, svc_a.id)
    admin_a = await create_test_user(db_session, org_a.id, role=Role.ADMIN)
    admin_b = await create_test_user(db_session, org_b.id, role=Role.ADMIN)

    rem_service = RemediationService()
    req = ActionCreateRequest(
        service_id=svc_a.id,
        action_type=ActionType.RUN_DIAGNOSTIC,
        risk_level=RiskLevel.LOW,
        title="Diagnostic A",
    )
    action = await rem_service.propose_action(db_session, org_a.id, inc_a.id, req, admin_a.id)
    await approve_test_action(rem_service, db_session, org_a.id, action.id, admin_a.id)
    await db_session.commit()

    # Call dry-run as Org B user
    headers_b = auth_headers_for(admin_b)
    resp = await client.post(
        f"/api/v1/actions/{action.id}/dry-run",
        headers=headers_b,
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_dry_run_invalid_parameters_rejected(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Invalid parameter ranges (e.g. replicas = 100 or negative grace period) fail validation."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    inc = await create_test_incident(db_session, org.id, svc.id)
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)

    rem_service = RemediationService()
    req = ActionCreateRequest(
        service_id=svc.id,
        action_type=ActionType.SCALE_SERVICE,
        risk_level=RiskLevel.MEDIUM,
        title="Scale service",
        preconditions={"replicas": 3},
    )
    action = await rem_service.propose_action(db_session, org.id, inc.id, req, admin.id)
    await approve_test_action(rem_service, db_session, org.id, action.id, admin.id)
    await db_session.commit()

    headers = auth_headers_for(admin)
    # Pass invalid replicas (exceeds max 50)
    resp = await client.post(
        f"/api/v1/actions/{action.id}/dry-run",
        headers=headers,
        json={"parameters": {"replicas": 999}},
    )
    assert resp.status_code == 422
    assert "replicas must be an integer between 1 and 50" in resp.json()["error"]["message"]


@pytest.mark.asyncio
async def test_dry_run_forbidden_injection_tokens_rejected(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Attempts to pass shell execution or bash commands are rejected immediately."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    inc = await create_test_incident(db_session, org.id, svc.id)
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)

    rem_service = RemediationService()
    req = ActionCreateRequest(
        service_id=svc.id,
        action_type=ActionType.RESTART_SERVICE,
        risk_level=RiskLevel.LOW,
        title="Restart service",
    )
    action = await rem_service.propose_action(db_session, org.id, inc.id, req, admin.id)
    await approve_test_action(rem_service, db_session, org.id, action.id, admin.id)
    await db_session.commit()

    headers = auth_headers_for(admin)
    resp = await client.post(
        f"/api/v1/actions/{action.id}/dry-run",
        headers=headers,
        json={"parameters": {"inject": "sudo rm -rf /; bash"}},
    )
    assert resp.status_code == 422
    assert "Forbidden execution token" in resp.json()["error"]["message"]


@pytest.mark.asyncio
async def test_dry_run_unsupported_executor_rejected(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Requesting an unsupported executor type is rejected."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    inc = await create_test_incident(db_session, org.id, svc.id)
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)

    rem_service = RemediationService()
    req = ActionCreateRequest(
        service_id=svc.id,
        action_type=ActionType.RESTART_SERVICE,
        risk_level=RiskLevel.LOW,
        title="Restart service",
    )
    action = await rem_service.propose_action(db_session, org.id, inc.id, req, admin.id)
    await approve_test_action(rem_service, db_session, org.id, action.id, admin.id)
    await db_session.commit()

    headers = auth_headers_for(admin)
    resp = await client.post(
        f"/api/v1/actions/{action.id}/dry-run",
        headers=headers,
        json={"executor_type": "KUBERNETES_OPERATOR"},
    )
    assert resp.status_code == 422
    assert "Unsupported executor type" in resp.json()["error"]["message"]


@pytest.mark.asyncio
async def test_deterministic_plan_hash() -> None:
    """The same action parameters must produce identical plan hashes every time."""
    action_id = uuid.uuid4()
    org_id = uuid.uuid4()
    svc_id = uuid.uuid4()

    class MockAction:
        id = action_id
        organization_id = org_id
        service_id = svc_id
        action_type = ActionType.RESTART_SERVICE

    class MockService:
        id = svc_id
        name = "auth-service"

    plan1 = DryRunPlanBuilder.build_plan(
        MockAction(),
        MockService(),
        parameters={"grace_period_seconds": 30, "restart_type": "rolling", "environment": "production"},
    )
    plan2 = DryRunPlanBuilder.build_plan(
        MockAction(),
        MockService(),
        parameters={"grace_period_seconds": 30, "restart_type": "rolling", "environment": "production"},
    )
    assert plan1.plan_hash == plan2.plan_hash

    # Different parameter -> different hash
    plan3 = DryRunPlanBuilder.build_plan(
        MockAction(),
        MockService(),
        parameters={"grace_period_seconds": 60, "restart_type": "rolling", "environment": "production"},
    )
    assert plan1.plan_hash != plan3.plan_hash


@pytest.mark.asyncio
async def test_dry_run_idempotency(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Repeated dry-run calls with identical parameters return the cached result without duplicate records."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    inc = await create_test_incident(db_session, org.id, svc.id)
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)

    rem_service = RemediationService()
    req = ActionCreateRequest(
        service_id=svc.id,
        action_type=ActionType.RUN_DIAGNOSTIC,
        risk_level=RiskLevel.LOW,
        title="Diagnostic dry-run",
    )
    action = await rem_service.propose_action(db_session, org.id, inc.id, req, admin.id)
    await approve_test_action(rem_service, db_session, org.id, action.id, admin.id)
    await db_session.commit()

    headers = auth_headers_for(admin)
    # First call
    resp1 = await client.post(f"/api/v1/actions/{action.id}/dry-run", headers=headers)
    assert resp1.status_code == 200
    data1 = resp1.json()

    # Second call
    resp2 = await client.post(f"/api/v1/actions/{action.id}/dry-run", headers=headers)
    assert resp2.status_code == 200
    data2 = resp2.json()

    assert data1["execution_id"] == data2["execution_id"]
    assert data1["plan"]["plan_hash"] == data2["plan"]["plan_hash"]

    # Verify only 1 ActionExecution record created
    stmt = select(ActionExecution).where(ActionExecution.action_id == action.id)
    executions = (await db_session.execute(stmt)).scalars().all()
    assert len(executions) == 1


@pytest.mark.asyncio
async def test_dry_run_all_action_types(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Dry-run successfully generates deterministic simulation plans for all 5 action types."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    inc = await create_test_incident(db_session, org.id, svc.id)
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)
    headers = auth_headers_for(admin)
    rem_service = RemediationService()

    cases = [
        (ActionType.RESTART_SERVICE, {"grace_period_seconds": 25}),
        (ActionType.SCALE_SERVICE, {"replicas": 4}),
        (ActionType.ROLLBACK_DEPLOYMENT, {"target_version": "v2.1.0"}),
        (ActionType.UPDATE_CONFIGURATION, {"config_keys": {"TIMEOUT_MS": 5000}}),
        (ActionType.RUN_DIAGNOSTIC, {"diagnostic_type": "stack_trace"}),
    ]

    for action_type, params in cases:
        req = ActionCreateRequest(
            service_id=svc.id,
            action_type=action_type,
            risk_level=RiskLevel.LOW,
            title=f"Plan {action_type}",
            preconditions=params,
        )
        action = await rem_service.propose_action(db_session, org.id, inc.id, req, admin.id)
        await approve_test_action(rem_service, db_session, org.id, action.id, admin.id)
        await db_session.commit()

        resp = await client.post(f"/api/v1/actions/{action.id}/dry-run", headers=headers)
        assert resp.status_code == 200, f"Failed for {action_type}: {resp.text}"
        data = resp.json()
        assert data["status"] == "DRY_RUN_SUCCESS"
        assert data["no_real_execution"] is True
        assert len(data["plan"]["ordered_steps"]) > 0


@pytest.mark.asyncio
async def test_dry_run_rbac(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """ADMIN, ENGINEER, RESPONDER can execute dry run; VIEWER is forbidden."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    inc = await create_test_incident(db_session, org.id, svc.id)
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)
    engineer = await create_test_user(db_session, org.id, email="eng@test.com", role=Role.ENGINEER)
    responder = await create_test_user(db_session, org.id, email="resp@test.com", role=Role.RESPONDER)
    viewer = await create_test_user(db_session, org.id, email="view@test.com", role=Role.VIEWER)

    rem_service = RemediationService()
    req = ActionCreateRequest(
        service_id=svc.id,
        action_type=ActionType.RUN_DIAGNOSTIC,
        risk_level=RiskLevel.LOW,
        title="Test RBAC",
    )
    action = await rem_service.propose_action(db_session, org.id, inc.id, req, admin.id)
    await approve_test_action(rem_service, db_session, org.id, action.id, admin.id)
    await db_session.commit()

    # Engineer -> 200 OK
    resp_eng = await client.post(
        f"/api/v1/actions/{action.id}/dry-run",
        headers=auth_headers_for(engineer),
    )
    assert resp_eng.status_code == 200

    # Responder -> 200 OK
    resp_resp = await client.post(
        f"/api/v1/actions/{action.id}/dry-run",
        headers=auth_headers_for(responder),
    )
    assert resp_resp.status_code == 200

    # Viewer -> 403 Forbidden
    resp_view = await client.post(
        f"/api/v1/actions/{action.id}/dry-run",
        headers=auth_headers_for(viewer),
    )
    assert resp_view.status_code == 403


@pytest.mark.asyncio
async def test_dry_run_audit_logs(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Dry-run emits transactional ACTION_DRY_RUN_STARTED, VALIDATED, and COMPLETED audit events."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    inc = await create_test_incident(db_session, org.id, svc.id)
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)

    rem_service = RemediationService()
    req = ActionCreateRequest(
        service_id=svc.id,
        action_type=ActionType.RESTART_SERVICE,
        risk_level=RiskLevel.LOW,
        title="Audit test restart",
    )
    action = await rem_service.propose_action(db_session, org.id, inc.id, req, admin.id)
    await approve_test_action(rem_service, db_session, org.id, action.id, admin.id)
    await db_session.commit()

    headers = auth_headers_for(admin)
    resp = await client.post(f"/api/v1/actions/{action.id}/dry-run", headers=headers)
    assert resp.status_code == 200

    stmt = select(AuditLog).where(
        AuditLog.entity_id == action.id,
        AuditLog.organization_id == org.id,
    ).order_by(AuditLog.created_at.asc())
    logs = (await db_session.execute(stmt)).scalars().all()
    action_types = [l.action for l in logs]

    assert "ACTION_DRY_RUN_STARTED" in action_types
    assert "ACTION_DRY_RUN_VALIDATED" in action_types
    assert "ACTION_DRY_RUN_COMPLETED" in action_types


@pytest.mark.asyncio
async def test_dry_run_terminal_state_actions_rejected(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Actions in terminal states (CANCELLED, REJECTED, FAILED) cannot be dry-run."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    inc = await create_test_incident(db_session, org.id, svc.id)
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)

    rem_service = RemediationService()
    # 1. Cancelled action
    req1 = ActionCreateRequest(
        service_id=svc.id,
        action_type=ActionType.RUN_DIAGNOSTIC,
        risk_level=RiskLevel.LOW,
        title="To be cancelled",
    )
    action1 = await rem_service.propose_action(db_session, org.id, inc.id, req1, admin.id)
    await rem_service.cancel_action(db_session, org.id, action1.id, admin.id)
    await db_session.commit()

    headers = auth_headers_for(admin)
    resp1 = await client.post(f"/api/v1/actions/{action1.id}/dry-run", headers=headers)
    assert resp1.status_code == 400
    assert "cannot be executed in state 'CANCELLED'" in resp1.json()["error"]["message"]

    # 2. Rejected action
    req2 = ActionCreateRequest(
        service_id=svc.id,
        action_type=ActionType.RESTART_SERVICE,
        risk_level=RiskLevel.HIGH,
        title="To be rejected",
    )
    action2 = await rem_service.propose_action(db_session, org.id, inc.id, req2, admin.id)
    await rem_service.submit_for_approval(db_session, org.id, action2.id, admin.id)
    await rem_service.reject_action(db_session, org.id, action2.id, admin.id, reason="Denied by operations")
    await db_session.commit()

    resp2 = await client.post(f"/api/v1/actions/{action2.id}/dry-run", headers=headers)
    assert resp2.status_code == 400
    assert "cannot be executed in state 'REJECTED'" in resp2.json()["error"]["message"]


@pytest.mark.asyncio
async def test_dry_run_missing_service_rejected(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """If target service belongs to another tenant or is missing, dry-run returns 404."""
    org_a = await create_test_organization(db_session, name="Org A")
    org_b = await create_test_organization(db_session, name="Org B")
    svc_b = await create_test_service(db_session, org_b.id)
    inc_a = await create_test_incident(db_session, org_a.id, svc_b.id)
    admin_a = await create_test_user(db_session, org_a.id, role=Role.ADMIN)

    # Action in org A illegally referencing service in org B
    action = RemediationAction(
        organization_id=org_a.id,
        incident_id=inc_a.id,
        service_id=svc_b.id,
        action_type=ActionType.RUN_DIAGNOSTIC,
        risk_level=RiskLevel.LOW,
        status=ActionStatus.APPROVED.value,
        title="Cross tenant service action",
    )
    db_session.add(action)
    await db_session.commit()

    headers = auth_headers_for(admin_a)
    resp = await client.post(f"/api/v1/actions/{action.id}/dry-run", headers=headers)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_dry_run_concurrent_serialization(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Concurrent dry-run requests are serialized cleanly without conflicts."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    inc = await create_test_incident(db_session, org.id, svc.id)
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)

    rem_service = RemediationService()
    req = ActionCreateRequest(
        service_id=svc.id,
        action_type=ActionType.RESTART_SERVICE,
        risk_level=RiskLevel.LOW,
        title="Concurrent restart dry-run",
    )
    action = await rem_service.propose_action(db_session, org.id, inc.id, req, admin.id)
    await approve_test_action(rem_service, db_session, org.id, action.id, admin.id)
    await db_session.commit()

    headers = auth_headers_for(admin)

    # Launch 2 concurrent dry runs
    coro1 = client.post(f"/api/v1/actions/{action.id}/dry-run", headers=headers)
    coro2 = client.post(f"/api/v1/actions/{action.id}/dry-run", headers=headers)
    results = await asyncio.gather(coro1, coro2)

    assert results[0].status_code == 200
    assert results[1].status_code == 200
    assert results[0].json()["plan"]["plan_hash"] == results[1].json()["plan"]["plan_hash"]

