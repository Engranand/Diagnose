"""Comprehensive test suite for Milestone 10.4: Human Approval Workflow.

Verifies:
1. Strict Separation of Duties: Proposer cannot approve their own action (even as ADMIN).
2. Human-in-the-loop authorization with immutable ActionApproval provenance.
3. Cryptographic dry-run plan hash verification and binding.
4. Serialized organization policy re-check under pessimistic locking.
5. Action rejection workflow and audit trail.
6. Approval history retrieval and tenant isolation.
7. Zero real execution safety guarantees.
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
    DryRunHashMismatchError,
    InvalidStateTransition,
    PolicyViolationError,
    SeparationOfDutiesError,
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
from diagnose.models.approval import ActionApproval
from diagnose.models.audit_log import AuditLog
from diagnose.models.policy import RemediationPolicy
from diagnose.models.remediation import ActionExecution, RemediationAction
from diagnose.schemas.approval import ActionApproveRequest, ActionRejectRequest
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


@pytest.mark.asyncio
async def test_separation_of_duties_admin_cannot_approve_own_action(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Strict separation of duties: Admin who proposed the action CANNOT approve it (HTTP 403)."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    inc = await create_test_incident(db_session, org.id, svc.id)
    admin_proposer = await create_test_user(db_session, org.id, role=Role.ADMIN, email="proposer@example.com")

    headers_proposer = auth_headers_for(admin_proposer)

    # 1. Propose action
    r_create = await client.post(
        f"/api/v1/incidents/{inc.id}/actions",
        json={
            "service_id": str(svc.id),
            "action_type": "RESTART_SERVICE",
            "risk_level": "HIGH",
            "title": "Restart payment core",
        },
        headers=headers_proposer,
    )
    assert r_create.status_code == 201
    action_id = r_create.json()["id"]

    # 2. Submit for approval
    r_sub = await client.post(
        f"/api/v1/actions/{action_id}/submit",
        headers=headers_proposer,
    )
    assert r_sub.status_code == 200
    assert r_sub.json()["status"] == "PENDING_APPROVAL"

    # 3. Proposer attempts to approve their own action -> 403 Forbidden with SEPARATION_OF_DUTIES_VIOLATION
    r_app = await client.post(
        f"/api/v1/actions/{action_id}/approve",
        json={"reason": "Self-approving my own critical action"},
        headers=headers_proposer,
    )
    assert r_app.status_code == 403
    data = r_app.json()
    assert data["error"]["code"] == "SEPARATION_OF_DUTIES_VIOLATION"
    assert "proposer cannot approve their own action" in data["error"]["message"].lower()

    # 4. Verify action remains in PENDING_APPROVAL
    r_get = await client.get(f"/api/v1/actions/{action_id}", headers=headers_proposer)
    assert r_get.json()["status"] == "PENDING_APPROVAL"


@pytest.mark.asyncio
async def test_separation_of_duties_service_layer_raises_exception(
    db_session: AsyncSession,
) -> None:
    """Direct service call to approve_action by proposer raises SeparationOfDutiesError."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    inc = await create_test_incident(db_session, org.id, svc.id)
    admin_proposer = await create_test_user(db_session, org.id, role=Role.ADMIN)

    rem_service = RemediationService()
    req = ActionCreateRequest(
        service_id=svc.id,
        action_type=ActionType.SCALE_SERVICE,
        risk_level=RiskLevel.MEDIUM,
        title="Scale worker pods",
    )
    action = await rem_service.propose_action(db_session, org.id, inc.id, req, admin_proposer.id)
    await rem_service.submit_for_approval(db_session, org.id, action.id, admin_proposer.id)

    with pytest.raises(SeparationOfDutiesError) as exc_info:
        await rem_service.approve_action(
            db_session,
            org.id,
            action.id,
            actor_user_id=admin_proposer.id,
            actor_role=Role.ADMIN,
        )
    assert "proposer cannot approve their own action" in str(exc_info.value).lower()


@pytest.mark.asyncio
async def test_successful_approval_by_distinct_authorized_user(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Distinct Admin approves action: creates ActionApproval, updates status, and logs audit events."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    inc = await create_test_incident(db_session, org.id, svc.id)
    proposer = await create_test_user(db_session, org.id, role=Role.RESPONDER, email="proposer@example.com")
    approver = await create_test_user(db_session, org.id, role=Role.ADMIN, email="approver@example.com")

    # 1. Proposer creates and submits action
    r_create = await client.post(
        f"/api/v1/incidents/{inc.id}/actions",
        json={
            "service_id": str(svc.id),
            "action_type": "RESTART_SERVICE",
            "risk_level": "MEDIUM",
            "title": "Rolling restart of auth service",
        },
        headers=auth_headers_for(proposer),
    )
    assert r_create.status_code == 201
    action_id = uuid.UUID(r_create.json()["id"])

    r_sub = await client.post(
        f"/api/v1/actions/{action_id}/submit",
        headers=auth_headers_for(proposer),
    )
    assert r_sub.status_code == 200

    # 2. Distinct Admin approves the action
    approval_reason = "Reviewed incident graph and telemetry, change approved for execution window"
    r_app = await client.post(
        f"/api/v1/actions/{action_id}/approve",
        json={"reason": approval_reason},
        headers=auth_headers_for(approver),
    )
    assert r_app.status_code == 200
    action_data = r_app.json()
    assert action_data["status"] == "APPROVED"
    assert action_data["approved_by"] == str(approver.id)

    # 3. Verify ActionApproval table row persisted in DB
    stmt_appr = select(ActionApproval).where(ActionApproval.action_id == action_id)
    approval_records = (await db_session.execute(stmt_appr)).scalars().all()
    assert len(approval_records) == 1
    appr = approval_records[0]
    assert appr.organization_id == org.id
    assert appr.approver_user_id == approver.id
    assert appr.decision == "APPROVED"
    assert appr.reason == approval_reason
    assert appr.policy_set_version == org.policy_set_version
    assert appr.decided_at is not None

    # 4. Verify AuditLog entries
    stmt_audit = select(AuditLog).where(
        AuditLog.organization_id == org.id,
        AuditLog.action.in_(["ACTION_APPROVAL_RECORDED", "ACTION_APPROVED"]),
    )
    audit_logs = (await db_session.execute(stmt_audit)).scalars().all()
    audit_actions = [log.action for log in audit_logs]
    assert "ACTION_APPROVAL_RECORDED" in audit_actions
    assert "ACTION_APPROVED" in audit_actions


@pytest.mark.asyncio
async def test_rejection_workflow_and_audit_provenance(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Authorized user rejects pending action: transitions to REJECTED and records ActionApproval."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    inc = await create_test_incident(db_session, org.id, svc.id)
    proposer = await create_test_user(db_session, org.id, role=Role.ENGINEER, email="proposer-rej@example.com")
    approver = await create_test_user(db_session, org.id, role=Role.ADMIN, email="approver-rej@example.com")

    # Propose and submit
    rem_service = RemediationService()
    req = ActionCreateRequest(
        service_id=svc.id,
        action_type=ActionType.ROLLBACK_DEPLOYMENT,
        risk_level=RiskLevel.HIGH,
        title="Rollback cluster deployment",
    )
    action = await rem_service.propose_action(db_session, org.id, inc.id, req, proposer.id)
    await rem_service.submit_for_approval(db_session, org.id, action.id, proposer.id)
    await db_session.commit()

    # Reject via API
    rejection_reason = "Rollback plan lacks database migration backwards-compatibility."
    r_rej = await client.post(
        f"/api/v1/actions/{action.id}/reject",
        json={"reason": rejection_reason},
        headers=auth_headers_for(approver),
    )
    assert r_rej.status_code == 200
    assert r_rej.json()["status"] == "REJECTED"

    # Verify ActionApproval persisted with REJECTED decision
    stmt_appr = select(ActionApproval).where(ActionApproval.action_id == action.id)
    appr_rows = (await db_session.execute(stmt_appr)).scalars().all()
    assert len(appr_rows) == 1
    assert appr_rows[0].decision == "REJECTED"
    assert appr_rows[0].reason == rejection_reason
    assert appr_rows[0].approver_user_id == approver.id


@pytest.mark.asyncio
async def test_approval_state_prerequisites(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Only actions in PENDING_APPROVAL can be approved or rejected (HTTP 409 on invalid states)."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    inc = await create_test_incident(db_session, org.id, svc.id)
    proposer = await create_test_user(db_session, org.id, role=Role.RESPONDER, email="p1@example.com")
    approver = await create_test_user(db_session, org.id, role=Role.ADMIN, email="a1@example.com")

    headers_appr = auth_headers_for(approver)

    # 1. Action in PROPOSED state -> cannot approve or reject directly (409)
    rem_service = RemediationService()
    req = ActionCreateRequest(
        service_id=svc.id,
        action_type=ActionType.RUN_DIAGNOSTIC,
        risk_level=RiskLevel.LOW,
        title="Network probe",
    )
    action = await rem_service.propose_action(db_session, org.id, inc.id, req, proposer.id)
    await db_session.commit()

    r_app_proposed = await client.post(f"/api/v1/actions/{action.id}/approve", headers=headers_appr)
    assert r_app_proposed.status_code == 409
    assert r_app_proposed.json()["error"]["code"] == "INVALID_STATE_TRANSITION"

    r_rej_proposed = await client.post(f"/api/v1/actions/{action.id}/reject", headers=headers_appr)
    assert r_rej_proposed.status_code == 409
    assert r_rej_proposed.json()["error"]["code"] == "INVALID_STATE_TRANSITION"

    # 2. Transition to PENDING_APPROVAL -> then APPROVE
    await rem_service.submit_for_approval(db_session, org.id, action.id, proposer.id)
    await db_session.commit()

    r_app_ok = await client.post(f"/api/v1/actions/{action.id}/approve", headers=headers_appr)
    assert r_app_ok.status_code == 200
    assert r_app_ok.json()["status"] == "APPROVED"

    # 3. Action in APPROVED state -> cannot re-approve (409)
    r_app_again = await client.post(f"/api/v1/actions/{action.id}/approve", headers=headers_appr)
    assert r_app_again.status_code == 409


@pytest.mark.asyncio
async def test_dry_run_plan_hash_verification(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Approval validates and binds dry-run plan hash: matching succeeds, mismatch returns 422."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    inc = await create_test_incident(db_session, org.id, svc.id)
    proposer = await create_test_user(db_session, org.id, role=Role.RESPONDER, email="prop-hash@example.com")
    approver = await create_test_user(db_session, org.id, role=Role.ADMIN, email="appr-hash@example.com")

    rem_service = RemediationService()
    req = ActionCreateRequest(
        service_id=svc.id,
        action_type=ActionType.RESTART_SERVICE,
        risk_level=RiskLevel.LOW,
        title="Restart worker",
        preconditions={"environment": "production"},
    )
    action = await rem_service.propose_action(db_session, org.id, inc.id, req, proposer.id)
    await rem_service.submit_for_approval(db_session, org.id, action.id, proposer.id)
    await db_session.commit()

    # Pre-record an existing dry-run execution with a known plan hash
    expected_hash = "a" * 64
    fake_exec = ActionExecution(
        organization_id=org.id,
        action_id=action.id,
        execution_mode="DRY_RUN",
        executor_type="SIMULATOR",
        status="SUCCEEDED",
        plan_hash=expected_hash,
    )
    await rem_service.remediation_repo.create_execution(db_session, fake_exec)
    await db_session.commit()

    # 1. Approver supplies mismatched plan hash -> 422 DRY_RUN_HASH_MISMATCH
    r_mismatch = await client.post(
        f"/api/v1/actions/{action.id}/approve",
        json={"dry_run_plan_hash": "b" * 64},
        headers=auth_headers_for(approver),
    )
    assert r_mismatch.status_code == 422
    assert r_mismatch.json()["error"]["code"] == "DRY_RUN_HASH_MISMATCH"

    # 2. Approver supplies correct matching plan hash -> 200 OK
    r_match = await client.post(
        f"/api/v1/actions/{action.id}/approve",
        json={"dry_run_plan_hash": expected_hash, "reason": "Hash matches verified plan"},
        headers=auth_headers_for(approver),
    )
    assert r_match.status_code == 200
    assert r_match.json()["status"] == "APPROVED"

    # Verify ActionApproval records the bound plan hash
    stmt = select(ActionApproval).where(ActionApproval.action_id == action.id)
    appr = (await db_session.execute(stmt)).scalars().first()
    assert appr is not None
    assert appr.dry_run_plan_hash == expected_hash


@pytest.mark.asyncio
async def test_stale_policy_invalidation_during_approval(
    app: Any,
    db_session: AsyncSession,
) -> None:
    """If policy_set_version incremented to a DENY rule after submission, approval detects change, re-evaluates, and aborts with PolicyViolationError."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    inc = await create_test_incident(db_session, org.id, svc.id)
    proposer = await create_test_user(db_session, org.id, role=Role.RESPONDER, email="proposer-stale@example.com")
    approver = await create_test_user(db_session, org.id, role=Role.ADMIN, email="approver-stale@example.com")

    rem_service = RemediationService()
    policy_service = PolicyService()

    req = ActionCreateRequest(
        service_id=svc.id,
        action_type=ActionType.RESTART_SERVICE,
        risk_level=RiskLevel.MEDIUM,
        title="Restart service",
    )
    action = await rem_service.propose_action(db_session, org.id, inc.id, req, proposer.id)
    await rem_service.submit_for_approval(db_session, org.id, action.id, proposer.id)
    await db_session.commit()

    # Admin updates policy set to introduce a DENY rule
    session_factory = app.state.db_session_factory
    async with session_factory() as s2:
        await policy_service.create_policy(
            s2,
            org.id,
            PolicyCreateRequest(
                name="Global blackout for restart service",
                action_type=ActionType.RESTART_SERVICE,
                decision=PolicyDecision.DENY,
                priority=1,
            ),
            approver.id,
        )

    # Approver tries to approve action -> stale policy detected, re-evaluation triggers DENY -> PolicyViolationError
    async with session_factory() as s1:
        with pytest.raises(PolicyViolationError) as exc_info:
            await rem_service.approve_action(s1, org.id, action.id, approver.id)
        assert "governance policy (DENY)" in str(exc_info.value)

    # Verify action remains in PENDING_APPROVAL
    async with session_factory() as s3:
        act = await rem_service.get_action(s3, org.id, action.id)
        assert act.status == ActionStatus.PENDING_APPROVAL.value


@pytest.mark.asyncio
async def test_listing_action_approvals_history(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """GET /actions/{id}/approvals returns chronological audit trail of approval/rejection decisions."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    inc = await create_test_incident(db_session, org.id, svc.id)
    proposer = await create_test_user(db_session, org.id, role=Role.RESPONDER, email="p-hist@example.com")
    approver = await create_test_user(db_session, org.id, role=Role.ADMIN, email="a-hist@example.com")

    rem_service = RemediationService()
    req = ActionCreateRequest(
        service_id=svc.id,
        action_type=ActionType.RUN_DIAGNOSTIC,
        risk_level=RiskLevel.LOW,
        title="Diagnostic audit",
    )
    action = await rem_service.propose_action(db_session, org.id, inc.id, req, proposer.id)
    await rem_service.submit_for_approval(db_session, org.id, action.id, proposer.id)
    await db_session.commit()

    # 1. Distinct Admin approves
    r_app = await client.post(
        f"/api/v1/actions/{action.id}/approve",
        json={"reason": "Approved for diagnostic analysis"},
        headers=auth_headers_for(approver),
    )
    assert r_app.status_code == 200

    # 2. Query approvals endpoint
    r_list = await client.get(
        f"/api/v1/actions/{action.id}/approvals",
        headers=auth_headers_for(approver),
    )
    assert r_list.status_code == 200
    approvals = r_list.json()
    assert len(approvals) == 1
    record = approvals[0]
    assert record["action_id"] == str(action.id)
    assert record["approver_user_id"] == str(approver.id)
    assert record["decision"] == "APPROVED"
    assert record["reason"] == "Approved for diagnostic analysis"
    assert record["policy_set_version"] == org.policy_set_version
    assert "decided_at" in record


@pytest.mark.asyncio
async def test_rbac_and_cross_tenant_isolation(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Users without APPROVE_ACTION role cannot approve; other tenants receive 404."""
    org_a = await create_test_organization(db_session, name="Org A")
    org_b = await create_test_organization(db_session, name="Org B")

    svc_a = await create_test_service(db_session, org_a.id)
    inc_a = await create_test_incident(db_session, org_a.id, svc_a.id)

    eng_a = await create_test_user(db_session, org_a.id, role=Role.ENGINEER, email="eng-a@example.com")
    resp_a = await create_test_user(db_session, org_a.id, role=Role.RESPONDER, email="resp-a@example.com")
    view_a = await create_test_user(db_session, org_a.id, role=Role.VIEWER, email="view-a@example.com")
    admin_b = await create_test_user(db_session, org_b.id, role=Role.ADMIN, email="admin-b@example.com")

    rem_service = RemediationService()
    req = ActionCreateRequest(
        service_id=svc_a.id,
        action_type=ActionType.RESTART_SERVICE,
        risk_level=RiskLevel.LOW,
        title="Restart service",
    )
    action = await rem_service.propose_action(db_session, org_a.id, inc_a.id, req, eng_a.id)
    await rem_service.submit_for_approval(db_session, org_a.id, action.id, eng_a.id)
    await db_session.commit()

    # 1. ENGINEER without APPROVE_ACTION -> 403 Forbidden
    r1 = await client.post(f"/api/v1/actions/{action.id}/approve", headers=auth_headers_for(eng_a))
    assert r1.status_code == 403

    # 2. RESPONDER without APPROVE_ACTION -> 403 Forbidden
    r2 = await client.post(f"/api/v1/actions/{action.id}/approve", headers=auth_headers_for(resp_a))
    assert r2.status_code == 403

    # 3. VIEWER without APPROVE_ACTION -> 403 Forbidden
    r3 = await client.post(f"/api/v1/actions/{action.id}/approve", headers=auth_headers_for(view_a))
    assert r3.status_code == 403

    # 4. Cross-tenant isolation: Admin B in Org B gets 404 Not Found
    r4 = await client.post(f"/api/v1/actions/{action.id}/approve", headers=auth_headers_for(admin_b))
    assert r4.status_code == 404

    r5 = await client.get(f"/api/v1/actions/{action.id}/approvals", headers=auth_headers_for(admin_b))
    assert r5.status_code == 404


@pytest.mark.asyncio
async def test_zero_real_execution_safety_boundary(
    client: AsyncClient,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify that approval workflow invokes no subprocess, shell, or execution systems."""
    import subprocess

    def forbidden_call(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("CRITICAL SAFETY VIOLATION: Execution attempted during approval!")

    monkeypatch.setattr(subprocess, "Popen", forbidden_call)
    monkeypatch.setattr(subprocess, "run", forbidden_call)

    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    inc = await create_test_incident(db_session, org.id, svc.id)
    proposer = await create_test_user(db_session, org.id, role=Role.RESPONDER)
    approver = await create_test_user(db_session, org.id, role=Role.ADMIN, email="approver-safe@example.com")

    rem_service = RemediationService()
    req = ActionCreateRequest(
        service_id=svc.id,
        action_type=ActionType.RESTART_SERVICE,
        risk_level=RiskLevel.MEDIUM,
        title="Safe restart",
    )
    action = await rem_service.propose_action(db_session, org.id, inc.id, req, proposer.id)
    await rem_service.submit_for_approval(db_session, org.id, action.id, proposer.id)
    await db_session.commit()

    # Approve action -> must never trigger subprocess
    r_app = await client.post(
        f"/api/v1/actions/{action.id}/approve",
        headers=auth_headers_for(approver),
    )
    assert r_app.status_code == 200
    assert r_app.json()["status"] == "APPROVED"


@pytest.mark.asyncio
async def test_action_deletion_restricted_when_approval_history_exists(
    db_session: AsyncSession,
) -> None:
    """RemediationAction with an ActionApproval cannot be deleted (ON DELETE RESTRICT preserves provenance)."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    inc = await create_test_incident(db_session, org.id, svc.id)
    proposer = await create_test_user(db_session, org.id, role=Role.RESPONDER, email="p-del@example.com")
    approver = await create_test_user(db_session, org.id, role=Role.ADMIN, email="a-del@example.com")

    rem_service = RemediationService()
    req = ActionCreateRequest(
        service_id=svc.id,
        action_type=ActionType.RESTART_SERVICE,
        risk_level=RiskLevel.LOW,
        title="Protected restart action",
    )
    action = await rem_service.propose_action(db_session, org.id, inc.id, req, proposer.id)
    await rem_service.submit_for_approval(db_session, org.id, action.id, proposer.id)
    await rem_service.approve_action(db_session, org.id, action.id, approver.id)
    await db_session.commit()

    # Verify ActionApproval exists
    stmt_appr = select(ActionApproval).where(ActionApproval.action_id == action.id)
    appr = (await db_session.execute(stmt_appr)).scalars().first()
    assert appr is not None

    # Attempting to delete RemediationAction must be blocked by ON DELETE RESTRICT
    await db_session.delete(action)
    with pytest.raises(IntegrityError):
        await db_session.commit()
    await db_session.rollback()

    # Verify approval record is still intact
    survived_appr = (await db_session.execute(stmt_appr)).scalars().first()
    assert survived_appr is not None
    assert survived_appr.id == appr.id


@pytest.mark.asyncio
async def test_organization_deletion_restricted_when_approval_history_exists(
    db_session: AsyncSession,
) -> None:
    """Organization with ActionApproval records cannot be deleted (ON DELETE RESTRICT preserves history)."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    inc = await create_test_incident(db_session, org.id, svc.id)
    proposer = await create_test_user(db_session, org.id, role=Role.RESPONDER, email="p-orgdel@example.com")
    approver = await create_test_user(db_session, org.id, role=Role.ADMIN, email="a-orgdel@example.com")

    rem_service = RemediationService()
    req = ActionCreateRequest(
        service_id=svc.id,
        action_type=ActionType.RUN_DIAGNOSTIC,
        risk_level=RiskLevel.LOW,
        title="Protected diagnostic",
    )
    action = await rem_service.propose_action(db_session, org.id, inc.id, req, proposer.id)
    await rem_service.submit_for_approval(db_session, org.id, action.id, proposer.id)
    await rem_service.approve_action(db_session, org.id, action.id, approver.id)
    await db_session.commit()

    # Attempting to delete Organization must fail due to ON DELETE RESTRICT on action_approvals
    await db_session.delete(org)
    with pytest.raises(IntegrityError):
        await db_session.commit()
    await db_session.rollback()


@pytest.mark.asyncio
async def test_approver_deletion_restricted_when_approval_history_exists(
    db_session: AsyncSession,
) -> None:
    """Approver User with ActionApproval records cannot be deleted (ON DELETE RESTRICT preserves provenance)."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    inc = await create_test_incident(db_session, org.id, svc.id)
    proposer = await create_test_user(db_session, org.id, role=Role.RESPONDER, email="p-userdel@example.com")
    approver = await create_test_user(db_session, org.id, role=Role.ADMIN, email="a-userdel@example.com")

    rem_service = RemediationService()
    req = ActionCreateRequest(
        service_id=svc.id,
        action_type=ActionType.SCALE_SERVICE,
        risk_level=RiskLevel.MEDIUM,
        title="Protected scaling action",
    )
    action = await rem_service.propose_action(db_session, org.id, inc.id, req, proposer.id)
    await rem_service.submit_for_approval(db_session, org.id, action.id, proposer.id)
    await rem_service.approve_action(db_session, org.id, action.id, approver.id)
    await db_session.commit()

    # Attempting to delete the approver User must fail due to ON DELETE RESTRICT
    await db_session.delete(approver)
    with pytest.raises(IntegrityError):
        await db_session.commit()
    await db_session.rollback()

