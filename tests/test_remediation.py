"""Comprehensive test suite for Milestone 10.1: Remediation Action Domain Model."""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from diagnose.domain.exceptions import InvalidStateTransition, ValidationError
from diagnose.domain.remediation import (
    ActionStatus,
    ActionType,
    ExecutionMode,
    ExecutorType,
    RiskLevel,
    validate_action_transition,
)
from diagnose.domain.roles import Role
from diagnose.models.audit_log import AuditLog
from diagnose.models.remediation import RemediationAction
from diagnose.schemas.remediation import ActionCreateRequest
from diagnose.services.remediation import RemediationService
from tests.factories import (
    auth_headers_for,
    create_test_incident,
    create_test_organization,
    create_test_service,
    create_test_user,
)


# ── 1. DOMAIN ENUMS & STATE MACHINE TRANSITIONS ──────────────────────────────


def test_state_machine_valid_transitions() -> None:
    """Verify all valid forward, failure, and cancellation paths."""
    # PROPOSED -> PENDING_APPROVAL
    validate_action_transition(ActionStatus.PROPOSED, ActionStatus.PENDING_APPROVAL)
    # PROPOSED -> CANCELLED
    validate_action_transition(ActionStatus.PROPOSED, ActionStatus.CANCELLED)

    # PENDING_APPROVAL -> APPROVED
    validate_action_transition(ActionStatus.PENDING_APPROVAL, ActionStatus.APPROVED)
    # PENDING_APPROVAL -> REJECTED
    validate_action_transition(ActionStatus.PENDING_APPROVAL, ActionStatus.REJECTED)
    # PENDING_APPROVAL -> CANCELLED
    validate_action_transition(ActionStatus.PENDING_APPROVAL, ActionStatus.CANCELLED)

    # APPROVED -> EXECUTING
    validate_action_transition(ActionStatus.APPROVED, ActionStatus.EXECUTING)
    # APPROVED -> CANCELLED
    validate_action_transition(ActionStatus.APPROVED, ActionStatus.CANCELLED)

    # EXECUTING -> SUCCEEDED
    validate_action_transition(ActionStatus.EXECUTING, ActionStatus.SUCCEEDED)
    # EXECUTING -> FAILED
    validate_action_transition(ActionStatus.EXECUTING, ActionStatus.FAILED)


def test_state_machine_invalid_transitions() -> None:
    """Verify invalid transitions are rejected deterministically."""
    # Cannot jump from PROPOSED directly to APPROVED
    with pytest.raises(InvalidStateTransition):
        validate_action_transition(ActionStatus.PROPOSED, ActionStatus.APPROVED)

    # Cannot jump from PROPOSED directly to EXECUTING
    with pytest.raises(InvalidStateTransition):
        validate_action_transition(ActionStatus.PROPOSED, ActionStatus.EXECUTING)

    # Terminal states cannot transition anywhere
    for terminal in [
        ActionStatus.REJECTED,
        ActionStatus.SUCCEEDED,
        ActionStatus.FAILED,
        ActionStatus.CANCELLED,
    ]:
        with pytest.raises(InvalidStateTransition):
            validate_action_transition(terminal, ActionStatus.APPROVED)
        with pytest.raises(InvalidStateTransition):
            validate_action_transition(terminal, ActionStatus.EXECUTING)
        with pytest.raises(InvalidStateTransition):
            validate_action_transition(terminal, ActionStatus.CANCELLED)


# ── 2. SERVICE LAYER & AUDIT EVENTS ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_service_action_lifecycle_and_audit_events(
    db_session: AsyncSession,
) -> None:
    """Full lifecycle with service calls verifying all 8 audit events."""
    org = await create_test_organization(db_session)
    service_entity = await create_test_service(db_session, org.id)
    incident = await create_test_incident(db_session, org.id, service_entity.id)
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)

    rem_service = RemediationService()

    # 1. Propose action -> ACTION_CREATED
    create_req = ActionCreateRequest(
        service_id=service_entity.id,
        action_type=ActionType.RESTART_SERVICE,
        risk_level=RiskLevel.LOW,
        execution_mode=ExecutionMode.DRY_RUN,
        title="Restart worker service",
        description="Restarting pod to clear heap",
        rationale="OOM memory leak suspected",
    )

    action = await rem_service.propose_action(
        session=db_session,
        organization_id=org.id,
        incident_id=incident.id,
        data=create_req,
        actor_user_id=admin.id,
        correlation_id="corr-create-1",
    )
    await db_session.commit()
    assert action.status == ActionStatus.PROPOSED.value
    assert action.version == 1

    # 2. Submit for approval -> ACTION_SUBMITTED_FOR_APPROVAL
    action = await rem_service.submit_for_approval(
        session=db_session,
        organization_id=org.id,
        action_id=action.id,
        actor_user_id=admin.id,
        correlation_id="corr-submit-1",
    )
    await db_session.commit()
    assert action.status == ActionStatus.PENDING_APPROVAL.value
    assert action.version == 2

    # 3. Approve action -> ACTION_APPROVED
    action = await rem_service.approve_action(
        session=db_session,
        organization_id=org.id,
        action_id=action.id,
        actor_user_id=admin.id,
        correlation_id="corr-approve-1",
    )
    await db_session.commit()
    assert action.status == ActionStatus.APPROVED.value
    assert action.approved_by == admin.id
    assert action.version == 3

    # 4. Record execution start -> ACTION_EXECUTION_STARTED
    exec_run = await rem_service.record_execution_started(
        session=db_session,
        organization_id=org.id,
        action_id=action.id,
        execution_mode=ExecutionMode.DRY_RUN,
        executor_type=ExecutorType.SIMULATOR,
        actor_user_id=admin.id,
        correlation_id="corr-exec-1",
    )
    await db_session.commit()
    assert action.status == ActionStatus.EXECUTING.value
    assert exec_run.status == "EXECUTING"
    assert exec_run.started_at is not None

    # 5. Record execution completed -> ACTION_EXECUTION_SUCCEEDED
    exec_run = await rem_service.record_execution_completed(
        session=db_session,
        organization_id=org.id,
        action_id=action.id,
        execution_id=exec_run.id,
        success=True,
        result={"exit_code": 0, "simulated": True},
        actor_user_id=admin.id,
        correlation_id="corr-exec-comp-1",
    )
    await db_session.commit()
    assert action.status == ActionStatus.SUCCEEDED.value
    assert exec_run.status == "SUCCEEDED"
    assert exec_run.completed_at is not None

    # Verify audit logs in DB
    audit_stmt = (
        select(AuditLog)
        .where(AuditLog.organization_id == org.id)
        .order_by(AuditLog.created_at.asc())
    )
    audit_res = await db_session.execute(audit_stmt)
    audit_actions = [log.action for log in audit_res.scalars().all()]

    assert "ACTION_CREATED" in audit_actions
    assert "ACTION_SUBMITTED_FOR_APPROVAL" in audit_actions
    assert "ACTION_APPROVED" in audit_actions
    assert "ACTION_EXECUTION_STARTED" in audit_actions
    assert "ACTION_EXECUTION_SUCCEEDED" in audit_actions


@pytest.mark.asyncio
async def test_service_rejection_cancellation_and_failure_audits(
    db_session: AsyncSession,
) -> None:
    """Verify rejection, cancellation, and execution failure audit paths."""
    org = await create_test_organization(db_session)
    service_entity = await create_test_service(db_session, org.id)
    incident = await create_test_incident(db_session, org.id, service_entity.id)
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)

    rem_service = RemediationService()

    # Rejection flow
    req = ActionCreateRequest(
        service_id=service_entity.id,
        action_type=ActionType.ROLLBACK_DEPLOYMENT,
        risk_level="HIGH",  # type: ignore
        title="Rollback deployment v12",
    )
    action1 = await rem_service.propose_action(
        db_session, org.id, incident.id, req, admin.id
    )
    await rem_service.submit_for_approval(db_session, org.id, action1.id, admin.id)
    rejected_action = await rem_service.reject_action(
        db_session, org.id, action1.id, admin.id, reason="Too risky at peak traffic"
    )
    await db_session.commit()
    assert rejected_action.status == ActionStatus.REJECTED.value

    # Cancellation flow
    req2 = ActionCreateRequest(
        service_id=service_entity.id,
        action_type=ActionType.RUN_DIAGNOSTIC,
        risk_level="LOW",  # type: ignore
        title="Collect diagnostics",
    )
    action2 = await rem_service.propose_action(
        db_session, org.id, incident.id, req2, admin.id
    )
    cancelled_action = await rem_service.cancel_action(
        db_session, org.id, action2.id, admin.id
    )
    await db_session.commit()
    assert cancelled_action.status == ActionStatus.CANCELLED.value

    # Execution failure flow
    req3 = ActionCreateRequest(
        service_id=service_entity.id,
        action_type=ActionType.UPDATE_CONFIGURATION,
        risk_level="MEDIUM",  # type: ignore
        title="Increase worker timeout",
    )
    action3 = await rem_service.propose_action(
        db_session, org.id, incident.id, req3, admin.id
    )
    await rem_service.submit_for_approval(db_session, org.id, action3.id, admin.id)
    await rem_service.approve_action(db_session, org.id, action3.id, admin.id)
    exec_run = await rem_service.record_execution_started(
        db_session, org.id, action3.id
    )
    failed_exec = await rem_service.record_execution_completed(
        db_session,
        org.id,
        action3.id,
        exec_run.id,
        success=False,
        error="Simulated network failure",
    )
    await db_session.commit()
    assert action3.status == ActionStatus.FAILED.value
    assert failed_exec.status == "FAILED"

    # Verify audit actions
    audit_stmt = (
        select(AuditLog)
        .where(AuditLog.organization_id == org.id)
        .order_by(AuditLog.created_at.asc())
    )
    audit_res = await db_session.execute(audit_stmt)
    audit_actions = [log.action for log in audit_res.scalars().all()]

    assert "ACTION_REJECTED" in audit_actions
    assert "ACTION_CANCELLED" in audit_actions
    assert "ACTION_EXECUTION_FAILED" in audit_actions


@pytest.mark.asyncio
async def test_failed_action_leaves_no_orphan_audit_events(
    db_session: AsyncSession,
) -> None:
    """Verify that a rejected or invalid state transition aborts without orphan audit logs."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    inc = await create_test_incident(db_session, org.id, svc.id)
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)

    rem_service = RemediationService()
    req = ActionCreateRequest(
        service_id=svc.id,
        action_type=ActionType.RUN_DIAGNOSTIC,
        risk_level=RiskLevel.LOW,
        title="Check status",
    )
    action = await rem_service.propose_action(db_session, org.id, inc.id, req, admin.id)

    # Count audit logs
    count_stmt = select(AuditLog).where(AuditLog.organization_id == org.id)
    initial_count = len((await db_session.execute(count_stmt)).scalars().all())

    # Try invalid transition directly: PROPOSED -> APPROVED
    with pytest.raises(InvalidStateTransition):
        await rem_service.approve_action(db_session, org.id, action.id, admin.id)

    # Verify audit log count did not increase
    post_count = len((await db_session.execute(count_stmt)).scalars().all())
    assert post_count == initial_count


@pytest.mark.asyncio
async def test_incompatible_service_validation(
    db_session: AsyncSession,
) -> None:
    """Proposing an action for a service different from incident's affected service must fail with 422."""
    org = await create_test_organization(db_session)
    svc1 = await create_test_service(db_session, org.id, name="Service 1")
    svc2 = await create_test_service(db_session, org.id, name="Service 2")
    incident = await create_test_incident(db_session, org.id, svc1.id)
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)

    rem_service = RemediationService()
    req = ActionCreateRequest(
        service_id=svc2.id,  # Incompatible with incident.service_id (svc1.id)
        action_type=ActionType.RESTART_SERVICE,
        risk_level="LOW",  # type: ignore
        title="Restart wrong service",
    )

    with pytest.raises(ValidationError):
        await rem_service.propose_action(
            db_session, org.id, incident.id, req, admin.id
        )


# ── 3. API ENDPOINTS & VALIDATION ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_api_action_creation_and_defaults(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Test POST /api/v1/incidents/{incident_id}/actions creates action with PROPOSED and DRY_RUN defaults."""
    org = await create_test_organization(db_session)
    service_entity = await create_test_service(db_session, org.id)
    incident = await create_test_incident(db_session, org.id, service_entity.id)
    engineer = await create_test_user(db_session, org.id, role=Role.ENGINEER)

    headers = auth_headers_for(engineer)
    payload = {
        "service_id": str(service_entity.id),
        "action_type": "SCALE_SERVICE",
        "risk_level": "MEDIUM",
        "title": "Scale web service replicas",
        "description": "Increase replicas from 3 to 6",
        "rationale": "High CPU queue length",
        "preconditions": {"min_free_cpu_cores": 4},
        "expected_outcome": "CPU utilization drops below 60%",
        "rollback_plan": "Scale back to 3 replicas",
    }

    res = await client.post(
        f"/api/v1/incidents/{incident.id}/actions",
        json=payload,
        headers=headers,
    )
    assert res.status_code == 201
    data = res.json()
    assert data["incident_id"] == str(incident.id)
    assert data["service_id"] == str(service_entity.id)
    assert data["action_type"] == "SCALE_SERVICE"
    assert data["risk_level"] == "MEDIUM"
    assert data["status"] == "PROPOSED"
    assert data["execution_mode"] == "DRY_RUN"
    assert data["version"] == 1
    assert data["proposed_by"] == str(engineer.id)
    assert data["approved_by"] is None


@pytest.mark.asyncio
async def test_api_action_input_validation(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Test validation errors for empty title, invalid enum values, and mismatched service."""
    org = await create_test_organization(db_session)
    service_entity = await create_test_service(db_session, org.id)
    incident = await create_test_incident(db_session, org.id, service_entity.id)
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)

    headers = auth_headers_for(admin)

    # Empty title
    res_empty_title = await client.post(
        f"/api/v1/incidents/{incident.id}/actions",
        json={
            "service_id": str(service_entity.id),
            "action_type": "RESTART_SERVICE",
            "risk_level": "LOW",
            "title": "   ",
        },
        headers=headers,
    )
    assert res_empty_title.status_code == 422

    # Invalid action_type enum
    res_invalid_type = await client.post(
        f"/api/v1/incidents/{incident.id}/actions",
        json={
            "service_id": str(service_entity.id),
            "action_type": "NUKE_ENTIRE_CLUSTER",
            "risk_level": "CRITICAL",
            "title": "Invalid action",
        },
        headers=headers,
    )
    assert res_invalid_type.status_code == 422

    # Invalid risk_level enum
    res_invalid_risk = await client.post(
        f"/api/v1/incidents/{incident.id}/actions",
        json={
            "service_id": str(service_entity.id),
            "action_type": "RESTART_SERVICE",
            "risk_level": "EXTREME",
            "title": "Invalid risk",
        },
        headers=headers,
    )
    assert res_invalid_risk.status_code == 422


# ── 4. RBAC ENFORCEMENT ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_rbac_action_propose_approve_and_view(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Verify role permissions:
    - VIEWER: read-only (cannot propose or approve)
    - RESPONDER: can propose, cannot approve
    - ENGINEER: can propose, cannot approve
    - ADMIN: full action management (propose, approve, reject, cancel)
    """
    org = await create_test_organization(db_session)
    service_entity = await create_test_service(db_session, org.id)
    incident = await create_test_incident(db_session, org.id, service_entity.id)

    viewer = await create_test_user(db_session, org.id, role=Role.VIEWER)
    responder = await create_test_user(db_session, org.id, role=Role.RESPONDER)
    engineer = await create_test_user(db_session, org.id, role=Role.ENGINEER)
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)

    payload = {
        "service_id": str(service_entity.id),
        "action_type": "RESTART_SERVICE",
        "risk_level": "LOW",
        "title": "Restart service",
    }

    # 1. VIEWER cannot propose, submit, approve, reject, or cancel action -> 403
    r_viewer_create = await client.post(
        f"/api/v1/incidents/{incident.id}/actions",
        json=payload,
        headers=auth_headers_for(viewer),
    )
    assert r_viewer_create.status_code == 403

    # 2. RESPONDER can propose action -> 201
    r_resp_create = await client.post(
        f"/api/v1/incidents/{incident.id}/actions",
        json=payload,
        headers=auth_headers_for(responder),
    )
    assert r_resp_create.status_code == 201
    action_id = r_resp_create.json()["id"]

    # VIEWER cannot submit, reject, or cancel
    assert (
        await client.post(
            f"/api/v1/actions/{action_id}/submit", headers=auth_headers_for(viewer)
        )
    ).status_code == 403
    assert (
        await client.post(
            f"/api/v1/actions/{action_id}/reject", headers=auth_headers_for(viewer)
        )
    ).status_code == 403
    assert (
        await client.post(
            f"/api/v1/actions/{action_id}/cancel", headers=auth_headers_for(viewer)
        )
    ).status_code == 403

    # 3. VIEWER can view action -> 200
    r_viewer_get = await client.get(
        f"/api/v1/actions/{action_id}",
        headers=auth_headers_for(viewer),
    )
    assert r_viewer_get.status_code == 200

    # 4. ENGINEER can submit action for approval -> 200
    r_eng_submit = await client.post(
        f"/api/v1/actions/{action_id}/submit",
        headers=auth_headers_for(engineer),
    )
    assert r_eng_submit.status_code == 200
    assert r_eng_submit.json()["status"] == "PENDING_APPROVAL"

    # 5. ENGINEER cannot approve or reject action -> 403
    r_eng_approve = await client.post(
        f"/api/v1/actions/{action_id}/approve",
        headers=auth_headers_for(engineer),
    )
    assert r_eng_approve.status_code == 403

    r_eng_reject = await client.post(
        f"/api/v1/actions/{action_id}/reject",
        headers=auth_headers_for(engineer),
    )
    assert r_eng_reject.status_code == 403

    # 6. RESPONDER cannot approve or reject action -> 403
    r_resp_approve = await client.post(
        f"/api/v1/actions/{action_id}/approve",
        headers=auth_headers_for(responder),
    )
    assert r_resp_approve.status_code == 403

    r_resp_reject = await client.post(
        f"/api/v1/actions/{action_id}/reject",
        headers=auth_headers_for(responder),
    )
    assert r_resp_reject.status_code == 403

    # 7. ADMIN can approve action -> 200
    r_admin_approve = await client.post(
        f"/api/v1/actions/{action_id}/approve",
        headers=auth_headers_for(admin),
    )
    assert r_admin_approve.status_code == 200
    assert r_admin_approve.json()["status"] == "APPROVED"
    assert r_admin_approve.json()["approved_by"] == str(admin.id)


# ── 5. TENANT ISOLATION & NON-ENUMERATION ────────────────────────────────────


@pytest.mark.asyncio
async def test_cross_tenant_isolation_and_non_enumeration(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Verify that Org B user cannot view, transition, or propose actions for Org A resources (must return 404)."""
    org_a = await create_test_organization(db_session, name="Org A")
    org_b = await create_test_organization(db_session, name="Org B")

    svc_a = await create_test_service(db_session, org_a.id, name="Svc A")
    svc_b = await create_test_service(db_session, org_b.id, name="Svc B")

    inc_a = await create_test_incident(db_session, org_a.id, svc_a.id)

    user_a = await create_test_user(db_session, org_a.id, role=Role.ADMIN)
    user_b = await create_test_user(db_session, org_b.id, role=Role.ADMIN)

    # Org A creates an action
    rem_service = RemediationService()
    req = ActionCreateRequest(
        service_id=svc_a.id,
        action_type=ActionType.RESTART_SERVICE,
        risk_level="LOW",  # type: ignore
        title="Action in Org A",
    )
    action_a = await rem_service.propose_action(
        db_session, org_a.id, inc_a.id, req, user_a.id
    )
    await db_session.commit()

    headers_b = auth_headers_for(user_b)

    # 1. Org B cannot GET action_a by ID -> 404 (not 403)
    r_get = await client.get(
        f"/api/v1/actions/{action_a.id}",
        headers=headers_b,
    )
    assert r_get.status_code == 404

    # 2. Org B cannot list actions for inc_a -> 404
    r_list = await client.get(
        f"/api/v1/incidents/{inc_a.id}/actions",
        headers=headers_b,
    )
    assert r_list.status_code == 404

    # 3. Org B cannot propose action for inc_a -> 404
    r_cross_create = await client.post(
        f"/api/v1/incidents/{inc_a.id}/actions",
        json={
            "service_id": str(svc_b.id),
            "action_type": "RESTART_SERVICE",
            "risk_level": "LOW",
            "title": "Cross-tenant proposal",
        },
        headers=headers_b,
    )
    assert r_cross_create.status_code == 404

    # 4. Org A cannot propose action with service belonging to Org B -> 404
    headers_a = auth_headers_for(user_a)
    r_cross_svc = await client.post(
        f"/api/v1/incidents/{inc_a.id}/actions",
        json={
            "service_id": str(svc_b.id),  # Belongs to Org B!
            "action_type": "RESTART_SERVICE",
            "risk_level": "LOW",
            "title": "Cross-service proposal",
        },
        headers=headers_a,
    )
    assert r_cross_svc.status_code == 404

    # 5. Org B cannot submit or approve action_a -> 404
    r_submit = await client.post(
        f"/api/v1/actions/{action_a.id}/submit",
        headers=headers_b,
    )
    assert r_submit.status_code == 404

    r_approve = await client.post(
        f"/api/v1/actions/{action_a.id}/approve",
        headers=headers_b,
    )
    assert r_approve.status_code == 404


# ── 6. STATE TRANSITIONS VIA API & CONCURRENCY / LOCKING ─────────────────────


@pytest.mark.asyncio
async def test_api_state_transition_flow_and_errors(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Test API state transitions: PROPOSED -> PENDING_APPROVAL -> APPROVED -> CANCELLED."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    inc = await create_test_incident(db_session, org.id, svc.id)
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)

    headers = auth_headers_for(admin)

    # 1. Propose action
    r_create = await client.post(
        f"/api/v1/incidents/{inc.id}/actions",
        json={
            "service_id": str(svc.id),
            "action_type": "RUN_DIAGNOSTIC",
            "risk_level": "LOW",
            "title": "Run network diagnostic",
        },
        headers=headers,
    )
    assert r_create.status_code == 201
    action_id = r_create.json()["id"]

    # Invalid: Cannot approve from PROPOSED -> 409
    r_invalid_app = await client.post(
        f"/api/v1/actions/{action_id}/approve",
        headers=headers,
    )
    assert r_invalid_app.status_code == 409

    # Submit for approval -> 200
    r_sub = await client.post(
        f"/api/v1/actions/{action_id}/submit",
        headers=headers,
    )
    assert r_sub.status_code == 200
    assert r_sub.json()["status"] == "PENDING_APPROVAL"

    # Reject flow test on second action
    r_create2 = await client.post(
        f"/api/v1/incidents/{inc.id}/actions",
        json={
            "service_id": str(svc.id),
            "action_type": "RESTART_SERVICE",
            "risk_level": "CRITICAL",
            "title": "Restart DB primary",
        },
        headers=headers,
    )
    action2_id = r_create2.json()["id"]
    await client.post(f"/api/v1/actions/{action2_id}/submit", headers=headers)

    r_reject = await client.post(
        f"/api/v1/actions/{action2_id}/reject",
        json={"reason": "Cannot restart primary during failover testing"},
        headers=headers,
    )
    assert r_reject.status_code == 200
    assert r_reject.json()["status"] == "REJECTED"

    # Cannot transition rejected action -> 409
    r_re_app = await client.post(
        f"/api/v1/actions/{action2_id}/approve",
        headers=headers,
    )
    assert r_re_app.status_code == 409

    # Cancel action 1 from APPROVED
    await client.post(f"/api/v1/actions/{action_id}/approve", headers=headers)
    r_cancel = await client.post(
        f"/api/v1/actions/{action_id}/cancel",
        headers=headers,
    )
    assert r_cancel.status_code == 200
    assert r_cancel.json()["status"] == "CANCELLED"


# ── 7. PAGINATION & FILTERING ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_api_list_actions_pagination_and_filter(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Verify pagination and filtering by status on incident actions endpoint."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    inc = await create_test_incident(db_session, org.id, svc.id)
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)

    rem_service = RemediationService()

    # Create 3 actions: 2 PROPOSED, 1 PENDING_APPROVAL
    for i in range(3):
        req = ActionCreateRequest(
            service_id=svc.id,
            action_type=ActionType.RESTART_SERVICE,
            risk_level="LOW",  # type: ignore
            title=f"Action {i + 1}",
        )
        act = await rem_service.propose_action(
            db_session, org.id, inc.id, req, admin.id
        )
        if i == 2:
            await rem_service.submit_for_approval(
                db_session, org.id, act.id, admin.id
            )
    await db_session.commit()

    headers = auth_headers_for(admin)

    # 1. Page size 2
    r_page1 = await client.get(
        f"/api/v1/incidents/{inc.id}/actions?page=1&page_size=2",
        headers=headers,
    )
    assert r_page1.status_code == 200
    data1 = r_page1.json()
    assert data1["total"] == 3
    assert len(data1["items"]) == 2
    assert data1["page"] == 1
    assert data1["pages"] == 2

    # 2. Filter by status=PENDING_APPROVAL
    r_filter = await client.get(
        f"/api/v1/incidents/{inc.id}/actions?status=PENDING_APPROVAL",
        headers=headers,
    )
    assert r_filter.status_code == 200
    data_filt = r_filter.json()
    assert data_filt["total"] == 1
    assert data_filt["items"][0]["status"] == "PENDING_APPROVAL"
