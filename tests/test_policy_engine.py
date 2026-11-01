"""Comprehensive test suite for Milestone 10.2: Policy Engine & Policy Management."""

from __future__ import annotations

import asyncio
import uuid
from typing import Any

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from diagnose.domain.exceptions import (
    EntityNotFound,
    InvalidStateTransition,
    PolicyViolationError,
)
from diagnose.domain.policy import (
    PolicyDecision,
    PolicyEvaluationContext,
    calculate_specificity_score,
    evaluate_policies_deterministically,
)
from diagnose.domain.remediation import (
    ActionStatus,
    ActionType,
    ExecutionMode,
    RiskLevel,
    validate_action_transition,
)
from diagnose.domain.roles import Role
from diagnose.models.audit_log import AuditLog
from diagnose.models.organization import Organization
from diagnose.models.policy import PolicyEvaluation, RemediationPolicy
from diagnose.models.remediation import RemediationAction
from diagnose.models.service import Service
from diagnose.schemas.policy import PolicyCreateRequest, PolicyUpdateRequest
from diagnose.schemas.remediation import ActionCreateRequest
from diagnose.services.policy import PolicyService
from diagnose.services.remediation import RemediationService
from tests.factories import (
    auth_headers_for,
    create_test_incident,
    create_test_organization,
    create_test_service,
    create_test_user,
)


# ── 1. DOMAIN MATCHING, PRECEDENCE & SPECIFICITY TESTS ───────────────────────


def test_specificity_score_calculation() -> None:
    """Verify discrete specificity scoring [0..7] with +1 per explicit non-null constraint."""
    # Wildcard only
    assert calculate_specificity_score(None, None, None, None, None, None, None) == 0

    # Specific service and action type (+2)
    assert calculate_specificity_score(uuid.uuid4(), "RESTART_SERVICE", None, None, None, None, None) == 2

    # Fully constrained (+7)
    assert calculate_specificity_score(
        uuid.uuid4(),
        "RESTART_SERVICE",
        "HIGH",
        "CRITICAL",
        "production",
        "ENGINEER",
        "EXECUTE",
    ) == 7


def test_deny_overrides_allow_and_require_approval() -> None:
    """Requirement: Step 2 — If ANY matching policy has decision == DENY, decision is DENY."""
    org_id = uuid.uuid4()
    svc_id = uuid.uuid4()
    inc_id = uuid.uuid4()

    context = PolicyEvaluationContext(
        organization_id=org_id,
        incident_id=inc_id,
        service_id=svc_id,
        service_tier="CRITICAL",
        action_type=ActionType.RESTART_SERVICE,
        risk_level=RiskLevel.HIGH,
        execution_mode=ExecutionMode.EXECUTE,
        environment="production",
        actor_role=Role.ENGINEER,
    )

    # 3 active policies: 1 ALLOW, 1 REQUIRE_APPROVAL, 1 DENY
    p_allow = RemediationPolicy(
        id=uuid.uuid4(),
        organization_id=org_id,
        name="Allow restarts",
        action_type="RESTART_SERVICE",
        decision="ALLOW",
        priority=100,
        version=1,
    )
    p_req = RemediationPolicy(
        id=uuid.uuid4(),
        organization_id=org_id,
        name="Require approval for high risk",
        risk_level="HIGH",
        decision="REQUIRE_APPROVAL",
        priority=50,
        version=1,
    )
    p_deny = RemediationPolicy(
        id=uuid.uuid4(),
        organization_id=org_id,
        name="Deny restarts in production",
        environment="production",
        decision="DENY",
        priority=200,  # Lower priority number, but DENY overrides decision class!
        version=1,
    )

    res = evaluate_policies_deterministically(context, [p_allow, p_req, p_deny])
    assert res.decision == PolicyDecision.DENY
    assert res.winning_policy_id == p_deny.id
    assert len(res.all_matched_policies) == 3


def test_require_approval_overrides_allow() -> None:
    """Requirement: Step 3 — REQUIRE_APPROVAL overrides ALLOW."""
    org_id = uuid.uuid4()
    svc_id = uuid.uuid4()
    inc_id = uuid.uuid4()

    context = PolicyEvaluationContext(
        organization_id=org_id,
        incident_id=inc_id,
        service_id=svc_id,
        service_tier="HIGH",
        action_type=ActionType.SCALE_SERVICE,
        risk_level=RiskLevel.MEDIUM,
        execution_mode=ExecutionMode.DRY_RUN,
        environment="staging",
        actor_role=Role.ENGINEER,
    )

    p_allow = RemediationPolicy(
        id=uuid.uuid4(),
        organization_id=org_id,
        name="Allow scaling",
        action_type="SCALE_SERVICE",
        decision="ALLOW",
        priority=10,  # Higher precedence, but decision class REQUIRE_APPROVAL wins!
        version=1,
    )
    p_req = RemediationPolicy(
        id=uuid.uuid4(),
        organization_id=org_id,
        name="Require approval for tier HIGH",
        service_tier="HIGH",
        decision="REQUIRE_APPROVAL",
        priority=100,
        version=1,
    )

    res = evaluate_policies_deterministically(context, [p_allow, p_req])
    assert res.decision == PolicyDecision.REQUIRE_APPROVAL
    assert res.winning_policy_id == p_req.id


def test_priority_and_specificity_resolution_within_decision_class() -> None:
    """Requirement: Steps 5 & 6 — Within winning decision class, lowest priority wins; ties resolved by specificity."""
    org_id = uuid.uuid4()
    svc_id = uuid.uuid4()
    inc_id = uuid.uuid4()

    context = PolicyEvaluationContext(
        organization_id=org_id,
        incident_id=inc_id,
        service_id=svc_id,
        service_tier="CRITICAL",
        action_type=ActionType.RUN_DIAGNOSTIC,
        risk_level=RiskLevel.LOW,
        execution_mode=ExecutionMode.DRY_RUN,
        environment="production",
        actor_role=Role.ENGINEER,
    )

    # Both ALLOW, but p1 has lower priority integer (20 < 50)
    p1 = RemediationPolicy(
        id=uuid.uuid4(),
        organization_id=org_id,
        name="Priority 20 Allow",
        action_type="RUN_DIAGNOSTIC",
        decision="ALLOW",
        priority=20,
        version=1,
    )
    p2 = RemediationPolicy(
        id=uuid.uuid4(),
        organization_id=org_id,
        name="Priority 50 Allow",
        action_type="RUN_DIAGNOSTIC",
        risk_level="LOW",  # Higher specificity (2 vs 1), but p1 has better priority!
        decision="ALLOW",
        priority=50,
        version=1,
    )

    res = evaluate_policies_deterministically(context, [p1, p2])
    assert res.decision == PolicyDecision.ALLOW
    assert res.winning_policy_id == p1.id

    # Now test equal priority (both 30), p2 has higher specificity
    p1.priority = 30
    p2.priority = 30
    res2 = evaluate_policies_deterministically(context, [p1, p2])
    assert res2.winning_policy_id == p2.id  # Higher specificity wins!


def test_environment_safety_unknown_never_production() -> None:
    """Requirement: Unknown/missing environment must NEVER match explicit 'production' rule."""
    org_id = uuid.uuid4()
    svc_id = uuid.uuid4()
    inc_id = uuid.uuid4()

    context = PolicyEvaluationContext(
        organization_id=org_id,
        incident_id=inc_id,
        service_id=svc_id,
        service_tier="MEDIUM",
        action_type=ActionType.ROLLBACK_DEPLOYMENT,
        risk_level=RiskLevel.HIGH,
        execution_mode=ExecutionMode.DRY_RUN,
        environment="UNKNOWN",  # Explicitly unknown environment
        actor_role=Role.ENGINEER,
    )

    # Policy explicitly restricted to production
    p_prod = RemediationPolicy(
        id=uuid.uuid4(),
        organization_id=org_id,
        name="Deny rollbacks in production",
        action_type="ROLLBACK_DEPLOYMENT",
        environment="production",
        decision="DENY",
        priority=10,
        version=1,
    )

    # Should NOT match p_prod because context environment is UNKNOWN!
    res = evaluate_policies_deterministically(context, [p_prod])
    # Falls back safely to REQUIRE_APPROVAL (for DRY_RUN), not DENY from p_prod
    assert res.decision == PolicyDecision.REQUIRE_APPROVAL
    assert res.winning_policy_id is None
    assert len(res.all_matched_policies) == 0


# ── 2. POLICY MANAGEMENT, REVISION & RBAC TESTS ──────────────────────────────


@pytest.mark.asyncio
async def test_policy_creation_and_organization_revision_increment(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Creating a policy atomically increments organization.policy_set_version and sets version=1."""
    org = await create_test_organization(db_session)
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)

    initial_set_ver = org.policy_set_version

    headers = auth_headers_for(admin)
    payload = {
        "name": "Block Production Restarts",
        "action_type": "RESTART_SERVICE",
        "risk_level": "CRITICAL",
        "environment": "production",
        "decision": "DENY",
        "priority": 10,
    }

    res = await client.post("/api/v1/policies", json=payload, headers=headers)
    assert res.status_code == 201
    data = res.json()
    assert data["name"] == "Block Production Restarts"
    assert data["decision"] == "DENY"
    assert data["priority"] == 10
    assert data["version"] == 1
    assert data["is_active"] is True

    # Verify organization policy_set_version was incremented
    await db_session.refresh(org)
    assert org.policy_set_version == initial_set_ver + 1


@pytest.mark.asyncio
async def test_policy_update_and_deactivation_no_hard_delete(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Updating fields or deactivating policy increments policy.version and org.policy_set_version."""
    org = await create_test_organization(db_session)
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)

    headers = auth_headers_for(admin)

    # Create policy
    res = await client.post(
        "/api/v1/policies",
        json={"name": "Rule 1", "decision": "ALLOW", "priority": 100},
        headers=headers,
    )
    policy_id = res.json()["id"]

    # PATCH to deactivate
    patch_res = await client.patch(
        f"/api/v1/policies/{policy_id}",
        json={"is_active": False, "priority": 90},
        headers=headers,
    )
    assert patch_res.status_code == 200
    pdata = patch_res.json()
    assert pdata["is_active"] is False
    assert pdata["priority"] == 90
    assert pdata["version"] == 2

    # Verify DELETE method is NOT supported
    del_res = await client.delete(f"/api/v1/policies/{policy_id}", headers=headers)
    assert del_res.status_code == 405  # Method Not Allowed


@pytest.mark.asyncio
async def test_policy_rbac_enforcement(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Non-admin roles cannot create or update policies (403), but can view policies (200)."""
    org = await create_test_organization(db_session)
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)
    engineer = await create_test_user(db_session, org.id, role=Role.ENGINEER)
    viewer = await create_test_user(db_session, org.id, role=Role.VIEWER)

    # Create policy by admin
    p_res = await client.post(
        "/api/v1/policies",
        json={"name": "Org Policy", "decision": "REQUIRE_APPROVAL"},
        headers=auth_headers_for(admin),
    )
    policy_id = p_res.json()["id"]

    # Engineer cannot create -> 403
    r_eng = await client.post(
        "/api/v1/policies",
        json={"name": "Eng Policy", "decision": "ALLOW"},
        headers=auth_headers_for(engineer),
    )
    assert r_eng.status_code == 403

    # Viewer cannot patch -> 403
    r_view_patch = await client.patch(
        f"/api/v1/policies/{policy_id}",
        json={"is_active": False},
        headers=auth_headers_for(viewer),
    )
    assert r_view_patch.status_code == 403

    # Viewer can view -> 200
    r_view_get = await client.get(
        f"/api/v1/policies/{policy_id}",
        headers=auth_headers_for(viewer),
    )
    assert r_view_get.status_code == 200


# ── 3. PROPOSAL INTEGRATION & AUTO-APPROVAL PROVENANCE ───────────────────────


@pytest.mark.asyncio
async def test_proposal_denied_persists_evaluation_with_null_action_id(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """When an action proposal violates a DENY policy, evaluation is persisted with action_id=NULL and HTTP 403 is returned."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    inc = await create_test_incident(db_session, org.id, svc.id)
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)
    eng = await create_test_user(db_session, org.id, role=Role.ENGINEER)

    # Admin creates DENY policy for RESTART_SERVICE
    await client.post(
        "/api/v1/policies",
        json={
            "name": "Forbid All Restarts",
            "action_type": "RESTART_SERVICE",
            "decision": "DENY",
            "priority": 1,
        },
        headers=auth_headers_for(admin),
    )

    # Engineer tries to propose RESTART_SERVICE -> 403 Policy Violation
    prop_res = await client.post(
        f"/api/v1/incidents/{inc.id}/actions",
        json={
            "service_id": str(svc.id),
            "action_type": "RESTART_SERVICE",
            "risk_level": "LOW",
            "title": "Restart web server",
        },
        headers=auth_headers_for(eng),
    )
    assert prop_res.status_code == 403
    assert "prohibited by policy" in prop_res.json()["error"]["message"]

    # Verify PolicyEvaluation was persisted in DB with action_id = NULL
    stmt = (
        select(PolicyEvaluation)
        .where(PolicyEvaluation.organization_id == org.id)
        .order_by(PolicyEvaluation.created_at.desc())
    )
    eval_row = (await db_session.execute(stmt)).scalars().first()
    assert eval_row is not None
    assert eval_row.action_id is None
    assert eval_row.decision == "DENY"
    assert eval_row.winning_policy_snapshot["name"] == "Forbid All Restarts"


@pytest.mark.asyncio
async def test_proposal_allow_triggers_auto_approval_with_persisted_provenance(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """An ALLOW policy automatically advances action from PROPOSED to APPROVED with authoritative DB provenance."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    inc = await create_test_incident(db_session, org.id, svc.id)
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)

    # Create ALLOW policy for RUN_DIAGNOSTIC in DRY_RUN
    await client.post(
        "/api/v1/policies",
        json={
            "name": "Auto-Allow Safe Diagnostics",
            "action_type": "RUN_DIAGNOSTIC",
            "risk_level": "LOW",
            "execution_mode": "DRY_RUN",
            "decision": "ALLOW",
            "priority": 10,
        },
        headers=auth_headers_for(admin),
    )

    # Propose matching diagnostic action
    prop_res = await client.post(
        f"/api/v1/incidents/{inc.id}/actions",
        json={
            "service_id": str(svc.id),
            "action_type": "RUN_DIAGNOSTIC",
            "risk_level": "LOW",
            "execution_mode": "DRY_RUN",
            "title": "Run health diagnostic",
        },
        headers=auth_headers_for(admin),
    )
    assert prop_res.status_code == 201
    data = prop_res.json()
    assert data["status"] == "APPROVED"  # Auto-approved!
    assert data["approved_by"] is None   # Indicating automated policy clearance

    # Verify audit event captures auto_approved metadata
    audit_stmt = (
        select(AuditLog)
        .where(AuditLog.organization_id == org.id, AuditLog.action == "ACTION_APPROVED")
    )
    audit_row = (await db_session.execute(audit_stmt)).scalars().first()
    assert audit_row is not None
    assert audit_row.new_values["auto_approved"] is True


def test_forged_in_memory_auto_approval_rejected() -> None:
    """Attempting direct PROPOSED -> APPROVED transition without valid persisted ALLOW provenance raises InvalidStateTransition."""
    with pytest.raises(InvalidStateTransition):
        validate_action_transition(ActionStatus.PROPOSED, ActionStatus.APPROVED, auto_approval_provenance=None)

    class FakeProvenance:
        decision = "REQUIRE_APPROVAL"

    with pytest.raises(InvalidStateTransition):
        validate_action_transition(ActionStatus.PROPOSED, ActionStatus.APPROVED, auto_approval_provenance=FakeProvenance())


# ── 4. CONCURRENT APPROVAL & SERIALIZATION TESTS ─────────────────────────────


@pytest.mark.asyncio
async def test_concurrent_policy_update_serializes_before_approval(
    app: Any,
    db_session: AsyncSession,
) -> None:
    """Verify that when a policy mutation commits before approval, approval observes new version, re-evaluates, and aborts if DENY."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    inc = await create_test_incident(db_session, org.id, svc.id)
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)
    approver = await create_test_user(db_session, org.id, role=Role.ADMIN, email="approver1@example.com")

    rem_service = RemediationService()
    policy_service = PolicyService()

    # Create action in PROPOSED status (safe fallback to REQUIRE_APPROVAL)
    req = ActionCreateRequest(
        service_id=svc.id,
        action_type=ActionType.RESTART_SERVICE,
        risk_level=RiskLevel.MEDIUM,
        title="Restart worker",
    )
    action = await rem_service.propose_action(db_session, org.id, inc.id, req, admin.id)
    await rem_service.submit_for_approval(db_session, org.id, action.id, admin.id)

    # Session 2: Concurrent admin creates a DENY policy that increments policy_set_version
    session_factory = app.state.db_session_factory
    async with session_factory() as s2:
        await policy_service.create_policy(
            s2,
            org.id,
            PolicyCreateRequest(
                name="Emergency blackout DENY",
                action_type=ActionType.RESTART_SERVICE,
                decision=PolicyDecision.DENY,
                priority=1,
            ),
            admin.id,
        )

    # Session 1: Approval attempt observes policy_set_version mismatch, re-evaluates, and aborts with PolicyViolationError
    async with session_factory() as s1:
        with pytest.raises(PolicyViolationError):
            await rem_service.approve_action(s1, org.id, action.id, approver.id)


@pytest.mark.asyncio
async def test_approval_serializes_before_subsequent_policy_update(
    app: Any,
    db_session: AsyncSession,
) -> None:
    """When approval acquires organization lock first, it completes cleanly; subsequent policy mutation increments version for future."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    inc = await create_test_incident(db_session, org.id, svc.id)
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)
    approver = await create_test_user(db_session, org.id, role=Role.ADMIN, email="approver2@example.com")

    rem_service = RemediationService()
    policy_service = PolicyService()

    req = ActionCreateRequest(
        service_id=svc.id,
        action_type=ActionType.RUN_DIAGNOSTIC,
        risk_level=RiskLevel.LOW,
        title="Diagnostic",
    )
    action = await rem_service.propose_action(db_session, org.id, inc.id, req, admin.id)
    await rem_service.submit_for_approval(db_session, org.id, action.id, admin.id)

    session_factory = app.state.db_session_factory

    # Session 1 approves first
    async with session_factory() as s1:
        approved_act = await rem_service.approve_action(s1, org.id, action.id, approver.id)
        assert approved_act.status == ActionStatus.APPROVED.value

    # Session 2 subsequently adds a DENY policy
    async with session_factory() as s2:
        p = await policy_service.create_policy(
            s2,
            org.id,
            PolicyCreateRequest(
                name="Post-approval Deny",
                action_type=ActionType.RUN_DIAGNOSTIC,
                decision=PolicyDecision.DENY,
                priority=1,
            ),
            admin.id,
        )
        assert p.version == 1

    # Previously committed approval remains APPROVED in DB
    async with session_factory() as s3:
        refreshed = await rem_service.get_action(s3, org.id, action.id)
        assert refreshed.status == ActionStatus.APPROVED.value


# ── 5. REFERENTIAL INTEGRITY & DELETION BEHAVIOR TESTS ───────────────────────


@pytest.mark.asyncio
async def test_policy_evaluation_survives_action_deletion(
    db_session: AsyncSession,
) -> None:
    """When a RemediationAction row is deleted, PolicyEvaluation survives with action_id = NULL."""
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

    # Fetch created evaluation
    stmt = select(PolicyEvaluation).where(PolicyEvaluation.action_id == action.id)
    eval_row = (await db_session.execute(stmt)).scalars().first()
    assert eval_row is not None
    eval_id = eval_row.id

    # Delete the action directly in database session
    await db_session.delete(action)
    await db_session.commit()
    db_session.expire_all()

    # Verify PolicyEvaluation still exists with action_id = NULL
    stmt_eval = select(PolicyEvaluation).where(PolicyEvaluation.id == eval_id)
    eval_survived = (await db_session.execute(stmt_eval)).scalars().first()
    assert eval_survived is not None
    assert eval_survived.action_id is None
    assert eval_survived.context_hash is not None


@pytest.mark.asyncio
async def test_service_deletion_restricted_when_policies_exist(
    db_session: AsyncSession,
) -> None:
    """Attempting to delete a Service targeted by a RemediationPolicy raises IntegrityError (ON DELETE RESTRICT)."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id)
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)

    policy_service = PolicyService()
    await policy_service.create_policy(
        db_session,
        org.id,
        PolicyCreateRequest(
            name="Protect Critical Service",
            service_id=svc.id,
            decision=PolicyDecision.REQUIRE_APPROVAL,
            priority=10,
        ),
        admin.id,
    )

    # Attempting to delete service must raise IntegrityError
    await db_session.delete(svc)
    with pytest.raises(IntegrityError):
        await db_session.commit()
    await db_session.rollback()


@pytest.mark.asyncio
async def test_deactivated_service_policy_behavior(
    db_session: AsyncSession,
) -> None:
    """Policies targeting soft-deactivated services continue to match and enforce rules deterministically."""
    org = await create_test_organization(db_session)
    svc = await create_test_service(db_session, org.id, is_active=False)  # Soft-deactivated service
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)

    policy_service = PolicyService()
    await policy_service.create_policy(
        db_session,
        org.id,
        PolicyCreateRequest(
            name="Block Actions on Decommissioned Service",
            service_id=svc.id,
            decision=PolicyDecision.DENY,
            priority=1,
        ),
        admin.id,
    )

    context = PolicyEvaluationContext(
        organization_id=org.id,
        incident_id=uuid.uuid4(),
        service_id=svc.id,
        service_tier="MEDIUM",
        action_type=ActionType.RESTART_SERVICE,
        risk_level=RiskLevel.LOW,
        execution_mode=ExecutionMode.DRY_RUN,
        environment="production",
        actor_role=Role.ENGINEER,
    )

    active_policies = await policy_service.policy_repo.list_active_policies_for_evaluation(
        db_session, org.id
    )
    res = evaluate_policies_deterministically(context, active_policies)
    assert res.decision == PolicyDecision.DENY
    assert res.winning_policy_snapshot["name"] == "Block Actions on Decommissioned Service"


# ── 6. TENANT ISOLATION TESTS ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_policy_tenant_isolation(
    client: AsyncClient,
    db_session: AsyncSession,
) -> None:
    """Tenant B cannot read, update, or evaluate Tenant A's policies (returns 404)."""
    org_a = await create_test_organization(db_session, name="Org A")
    org_b = await create_test_organization(db_session, name="Org B")

    admin_a = await create_test_user(db_session, org_a.id, role=Role.ADMIN)
    admin_b = await create_test_user(db_session, org_b.id, role=Role.ADMIN)

    # Org A creates policy
    p_res = await client.post(
        "/api/v1/policies",
        json={"name": "Org A Policy", "decision": "ALLOW"},
        headers=auth_headers_for(admin_a),
    )
    policy_a_id = p_res.json()["id"]

    # Org B cannot GET policy A -> 404
    get_res = await client.get(
        f"/api/v1/policies/{policy_a_id}",
        headers=auth_headers_for(admin_b),
    )
    assert get_res.status_code == 404

    # Org B cannot PATCH policy A -> 404
    patch_res = await client.patch(
        f"/api/v1/policies/{policy_a_id}",
        json={"name": "Hacked Policy"},
        headers=auth_headers_for(admin_b),
    )
    assert patch_res.status_code == 404
