"""API endpoints for Remediation Actions and Executions (Milestone 10.1)."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from diagnose.api.deps import (
    get_correlation_id,
    get_current_org_id,
    get_current_user,
    get_db,
    require_permission,
)
from diagnose.domain.roles import Permission
from diagnose.models.user import User
from diagnose.schemas.approval import ActionApprovalResponse, ActionApproveRequest
from diagnose.schemas.dry_run import DryRunRequest, DryRunResponse
from diagnose.schemas.execution import ActionExecuteRequest
from diagnose.schemas.pagination import PaginatedResponse, PaginationParams
from diagnose.schemas.policy import PolicyEvaluationResponse
from diagnose.schemas.remediation import (
    ActionCreateRequest,
    ActionExecutionResponse,
    ActionRejectRequest,
    RemediationActionDetailResponse,
    RemediationActionResponse,
)
from diagnose.services.dry_run import DryRunService
from diagnose.services.execution import ControlledExecutionService
from diagnose.services.policy import PolicyService
from diagnose.services.remediation import RemediationService

incident_actions_router = APIRouter(prefix="/incidents", tags=["remediation"])
actions_router = APIRouter(prefix="/actions", tags=["remediation"])


# ── INCIDENT SCOPED REMEDIATION ACTION ENDPOINTS ─────────────────────────────


@incident_actions_router.post(
    "/{incident_id}/actions",
    response_model=RemediationActionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Propose a new remediation action for an incident",
)
async def propose_action(
    incident_id: UUID,
    payload: ActionCreateRequest,
    current_user: User = Depends(require_permission(Permission.PROPOSE_ACTION)),
    org_id: UUID = Depends(get_current_org_id),
    session: AsyncSession = Depends(get_db),
    correlation_id: str | None = Depends(get_correlation_id),
) -> RemediationActionResponse:
    """Propose a new remediation intervention in PROPOSED status with DRY_RUN default."""
    service = RemediationService()
    action = await service.propose_action(
        session=session,
        organization_id=org_id,
        incident_id=incident_id,
        data=payload,
        actor_user_id=current_user.id,
        actor_role=current_user.role,
        correlation_id=correlation_id,
    )
    return RemediationActionResponse.model_validate(action)


@incident_actions_router.get(
    "/{incident_id}/actions",
    response_model=PaginatedResponse[RemediationActionResponse],
    summary="List remediation actions for an incident",
)
async def list_actions(
    incident_id: UUID,
    status_filter: str | None = Query(default=None, alias="status", description="Filter by status"),
    pagination: PaginationParams = Depends(),
    current_user: User = Depends(require_permission(Permission.VIEW_ACTIONS)),
    org_id: UUID = Depends(get_current_org_id),
    session: AsyncSession = Depends(get_db),
) -> PaginatedResponse[RemediationActionResponse]:
    """List remediation actions associated with an incident with pagination."""
    service = RemediationService()
    items, total = await service.list_actions(
        session=session,
        organization_id=org_id,
        incident_id=incident_id,
        status=status_filter,
        offset=pagination.offset,
        limit=pagination.limit,
    )
    return PaginatedResponse(
        items=[RemediationActionResponse.model_validate(item) for item in items],
        total=total,
        page=pagination.page,
        page_size=pagination.page_size,
        pages=pagination.calculate_pages(total),
    )


# ── ACTION SPECIFIC ENDPOINTS ────────────────────────────────────────────────


@actions_router.get(
    "/{action_id}",
    response_model=RemediationActionDetailResponse,
    summary="Get remediation action details and execution history",
)
async def get_action(
    action_id: UUID,
    current_user: User = Depends(require_permission(Permission.VIEW_ACTIONS)),
    org_id: UUID = Depends(get_current_org_id),
    session: AsyncSession = Depends(get_db),
) -> RemediationActionDetailResponse:
    """Retrieve full details for a remediation action including its execution attempts."""
    service = RemediationService()
    action = await service.get_action(
        session=session,
        organization_id=org_id,
        action_id=action_id,
    )
    return RemediationActionDetailResponse.model_validate(action)


@actions_router.post(
    "/{action_id}/submit",
    response_model=RemediationActionResponse,
    summary="Submit proposed remediation action for approval",
)
async def submit_action(
    action_id: UUID,
    current_user: User = Depends(require_permission(Permission.PROPOSE_ACTION)),
    org_id: UUID = Depends(get_current_org_id),
    session: AsyncSession = Depends(get_db),
    correlation_id: str | None = Depends(get_correlation_id),
) -> RemediationActionResponse:
    """Advance action from PROPOSED to PENDING_APPROVAL."""
    service = RemediationService()
    action = await service.submit_for_approval(
        session=session,
        organization_id=org_id,
        action_id=action_id,
        actor_user_id=current_user.id,
        correlation_id=correlation_id,
    )
    return RemediationActionResponse.model_validate(action)


@actions_router.post(
    "/{action_id}/approve",
    response_model=RemediationActionResponse,
    summary="Approve a pending remediation action",
)
async def approve_action(
    action_id: UUID,
    payload: ActionApproveRequest | None = None,
    current_user: User = Depends(require_permission(Permission.APPROVE_ACTION)),
    org_id: UUID = Depends(get_current_org_id),
    session: AsyncSession = Depends(get_db),
    correlation_id: str | None = Depends(get_correlation_id),
) -> RemediationActionResponse:
    """Advance action from PENDING_APPROVAL to APPROVED under strict separation of duties and plan verification."""
    service = RemediationService()
    reason = payload.reason if payload else None
    dry_run_plan_hash = payload.dry_run_plan_hash if payload else None
    action = await service.approve_action(
        session=session,
        organization_id=org_id,
        action_id=action_id,
        actor_user_id=current_user.id,
        reason=reason,
        dry_run_plan_hash=dry_run_plan_hash,
        actor_role=current_user.role,
        correlation_id=correlation_id,
    )
    return RemediationActionResponse.model_validate(action)


@actions_router.get(
    "/{action_id}/approvals",
    response_model=list[ActionApprovalResponse],
    summary="List human approval records and audit trail for an action",
)
async def list_action_approvals(
    action_id: UUID,
    current_user: User = Depends(require_permission(Permission.VIEW_ACTIONS)),
    org_id: UUID = Depends(get_current_org_id),
    session: AsyncSession = Depends(get_db),
) -> list[ActionApprovalResponse]:
    """List immutable approval and rejection records for a remediation action."""
    service = RemediationService()
    approvals = await service.list_approvals_for_action(
        session=session,
        organization_id=org_id,
        action_id=action_id,
    )
    return [ActionApprovalResponse.model_validate(appr) for appr in approvals]


@actions_router.post(
    "/{action_id}/evaluate-policy",
    response_model=PolicyEvaluationResponse,
    summary="Evaluate active policies on an existing action without state changes",
)
async def evaluate_action_policy(
    action_id: UUID,
    current_user: User = Depends(require_permission(Permission.VIEW_ACTIONS)),
    org_id: UUID = Depends(get_current_org_id),
    session: AsyncSession = Depends(get_db),
) -> PolicyEvaluationResponse:
    """Run deterministic dry-run policy evaluation on an existing remediation action."""
    rem_service = RemediationService()
    action = await rem_service.get_action(session, org_id, action_id)

    from diagnose.domain.policy import PolicyEvaluationContext
    from diagnose.domain.remediation import ActionType, ExecutionMode, RiskLevel
    from diagnose.domain.roles import Role
    from diagnose.repositories.service import ServiceRepository

    service_repo = ServiceRepository()
    svc = await service_repo.get_by_id(session, org_id, action.service_id)

    context = PolicyEvaluationContext(
        organization_id=org_id,
        incident_id=action.incident_id,
        service_id=action.service_id,
        service_tier=svc.tier if svc else "MEDIUM",
        action_type=ActionType(action.action_type),
        risk_level=RiskLevel(action.risk_level),
        execution_mode=ExecutionMode(action.execution_mode),
        environment="UNKNOWN",
        actor_id=current_user.id,
        actor_role=Role(current_user.role),
        action_id=action.id,
    )

    policy_service = PolicyService()
    evaluation = await policy_service.evaluate_context_and_persist(
        session=session,
        context=context,
        action_id=action.id,
        actor_user_id=current_user.id,
    )
    await session.commit()
    return PolicyEvaluationResponse.model_validate(evaluation)


@actions_router.post(
    "/{action_id}/reject",
    response_model=RemediationActionResponse,
    summary="Reject a pending remediation action",
)
async def reject_action(
    action_id: UUID,
    payload: ActionRejectRequest | None = None,
    current_user: User = Depends(require_permission(Permission.APPROVE_ACTION)),
    org_id: UUID = Depends(get_current_org_id),
    session: AsyncSession = Depends(get_db),
    correlation_id: str | None = Depends(get_correlation_id),
) -> RemediationActionResponse:
    """Transition action from PENDING_APPROVAL to REJECTED."""
    service = RemediationService()
    reason = payload.reason if payload else None
    action = await service.reject_action(
        session=session,
        organization_id=org_id,
        action_id=action_id,
        actor_user_id=current_user.id,
        reason=reason,
        correlation_id=correlation_id,
    )
    return RemediationActionResponse.model_validate(action)


@actions_router.post(
    "/{action_id}/cancel",
    response_model=RemediationActionResponse,
    summary="Cancel a proposed, pending, or approved remediation action",
)
async def cancel_action(
    action_id: UUID,
    current_user: User = Depends(require_permission(Permission.PROPOSE_ACTION)),
    org_id: UUID = Depends(get_current_org_id),
    session: AsyncSession = Depends(get_db),
    correlation_id: str | None = Depends(get_correlation_id),
) -> RemediationActionResponse:
    """Transition action to CANCELLED."""
    service = RemediationService()
    action = await service.cancel_action(
        session=session,
        organization_id=org_id,
        action_id=action_id,
        actor_user_id=current_user.id,
        correlation_id=correlation_id,
    )
    return RemediationActionResponse.model_validate(action)


@actions_router.post(
    "/{action_id}/dry-run",
    response_model=DryRunResponse,
    status_code=status.HTTP_200_OK,
    summary="Execute deterministic dry-run on an approved remediation action",
)
async def dry_run_action(
    action_id: UUID,
    payload: DryRunRequest | None = None,
    current_user: User = Depends(require_permission(Permission.DRY_RUN_ACTION)),
    org_id: UUID = Depends(get_current_org_id),
    session: AsyncSession = Depends(get_db),
    correlation_id: str | None = Depends(get_correlation_id),
) -> DryRunResponse:
    """Execute dry-run simulation, producing deterministic execution plan and simulated outcome."""
    service = DryRunService()
    params = payload.parameters if payload else None
    idempotency_key = payload.idempotency_key if payload else None
    executor_type = payload.executor_type if payload else "SIMULATOR"
    res = await service.execute_dry_run(
        session=session,
        organization_id=org_id,
        action_id=action_id,
        actor_user_id=current_user.id,
        actor_role=current_user.role,
        idempotency_key=idempotency_key,
        parameters_override=params,
        requested_executor_type=executor_type,
        correlation_id=correlation_id,
    )
    await session.commit()
    return res


@actions_router.post(
    "/{action_id}/execute",
    response_model=ActionExecutionResponse,
    status_code=status.HTTP_200_OK,
    summary="Execute an approved remediation action through the controlled execution boundary",
)
async def execute_action(
    action_id: UUID,
    payload: ActionExecuteRequest | None = None,
    current_user: User = Depends(require_permission(Permission.EXECUTE_ACTION)),
    org_id: UUID = Depends(get_current_org_id),
    session: AsyncSession = Depends(get_db),
    correlation_id: str | None = Depends(get_correlation_id),
) -> ActionExecutionResponse:
    """Execute an approved remediation action deterministically and safely."""
    service = ControlledExecutionService()
    params = payload.parameters if payload else None
    idempotency_key = payload.idempotency_key if payload else None
    executor_type = payload.executor_type if payload else "SIMULATOR"
    execution = await service.execute_action(
        session=session,
        organization_id=org_id,
        action_id=action_id,
        actor_user_id=current_user.id,
        actor_role=current_user.role,
        requested_executor_type=executor_type,
        parameters_override=params,
        idempotency_key=idempotency_key,
        correlation_id=correlation_id,
    )
    return ActionExecutionResponse.model_validate(execution)
