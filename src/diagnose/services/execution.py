"""Service layer for Controlled Remediation Action Execution (Milestone 10.5)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from diagnose.domain.approval import ApprovalDecision
from diagnose.domain.exceptions import (
    ConflictError,
    EntityNotFound,
    ExecutionPreconditionError,
    InvalidStateTransition,
    PolicyViolationError,
    SeparationOfDutiesError,
    UnsupportedExecutorError,
)
from diagnose.domain.execution import (
    ExecutionContext,
    ExecutionResult,
    ExecutorRegistry,
)
from diagnose.domain.policy import (
    PolicyDecision,
    PolicyEvaluationContext,
    evaluate_policies_deterministically,
)
from diagnose.domain.remediation import (
    ActionStatus,
    ActionType,
    ExecutionMode,
    ExecutorType,
    RiskLevel,
    validate_action_transition,
)
from diagnose.domain.roles import Role
from diagnose.models.policy import PolicyEvaluation
from diagnose.models.remediation import ActionExecution, RemediationAction
from diagnose.repositories.approval import ApprovalRepository
from diagnose.repositories.policy import PolicyRepository
from diagnose.repositories.remediation import RemediationRepository
from diagnose.repositories.service import ServiceRepository
from diagnose.repositories.user import UserRepository
from diagnose.services.audit import AuditService, sanitize_audit_payload


class ControlledExecutionService:
    """Orchestrates controlled execution of approved remediation actions."""

    def __init__(
        self,
        remediation_repo: RemediationRepository | None = None,
        policy_repo: PolicyRepository | None = None,
        approval_repo: ApprovalRepository | None = None,
        service_repo: ServiceRepository | None = None,
        user_repo: UserRepository | None = None,
        audit_service: AuditService | None = None,
        registry: ExecutorRegistry | None = None,
    ) -> None:
        self.remediation_repo = remediation_repo or RemediationRepository()
        self.policy_repo = policy_repo or PolicyRepository()
        self.approval_repo = approval_repo or ApprovalRepository()
        self.service_repo = service_repo or ServiceRepository()
        self.user_repo = user_repo or UserRepository()
        self.audit_service = audit_service or AuditService()
        self.registry = registry or ExecutorRegistry()

    async def execute_action(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        action_id: uuid.UUID,
        actor_user_id: uuid.UUID | None,
        actor_role: Role | str | None = None,
        requested_executor_type: str = "SIMULATOR",
        parameters_override: dict[str, Any] | None = None,
        idempotency_key: str | None = None,
        correlation_id: str | None = None,
    ) -> ActionExecution:
        """Execute an approved remediation action through the controlled execution boundary."""
        # 1. Pessimistically lock Organization row first to serialize against policy mutations
        org = await self.policy_repo.lock_organization(session, organization_id)
        if org is None:
            raise EntityNotFound("Organization", str(organization_id))

        # 2. Pessimistically lock RemediationAction row second
        action = await self.remediation_repo.get_action_by_id(
            session, organization_id, action_id, for_update=True
        )
        if action is None:
            raise EntityNotFound("RemediationAction", str(action_id))

        # 3. Audit execution requested
        await self.audit_service.record(
            session=session,
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            action="ACTION_EXECUTION_REQUESTED",
            entity_type="RemediationAction",
            entity_id=action.id,
            new_values={
                "action_id": str(action.id),
                "status": action.status,
                "requested_executor": requested_executor_type,
            },
            correlation_id=correlation_id,
        )

        # 4. Idempotency Check: if action has already SUCCEEDED in EXECUTE mode, return existing record
        existing_succeeded = await self.remediation_repo.get_successful_execution_for_action(
            session, organization_id, action.id
        )
        if existing_succeeded is not None:
            return existing_succeeded

        # 5. Concurrency / In-Flight Check
        if action.status == ActionStatus.EXECUTING.value:
            raise ConflictError("Remediation action is currently executing in another process.")

        # 6. Action Lifecycle State Check (Only APPROVED actions may enter execution)
        if action.status != ActionStatus.APPROVED.value:
            # Let the domain state machine validate transition, raising InvalidStateTransition (409)
            validate_action_transition(action.status, ActionStatus.EXECUTING)

        # 7. Approval History & Separation-of-Duties Verification
        approvals = await self.approval_repo.list_approvals_for_action(
            session, organization_id, action.id
        )
        if not approvals:
            await self._record_blocked(
                session, organization_id, actor_user_id, action.id, "Action has no recorded approval history.", correlation_id
            )
            await session.commit()
            raise ExecutionPreconditionError("Remediation action has no recorded approval history.")

        latest_approval = approvals[-1]
        if latest_approval.decision != ApprovalDecision.APPROVED.value:
            await self._record_blocked(
                session, organization_id, actor_user_id, action.id, "Latest approval decision is not APPROVED.", correlation_id
            )
            await session.commit()
            raise ExecutionPreconditionError(
                f"Action latest approval decision is '{latest_approval.decision}', not APPROVED."
            )

        if action.proposed_by is not None and latest_approval.approver_user_id == action.proposed_by:
            await self._record_blocked(
                session, organization_id, actor_user_id, action.id, "Separation of duties violation: approved by proposer.", correlation_id
            )
            await session.commit()
            raise SeparationOfDutiesError(
                "Separation of duties violation: action proposer cannot approve their own action."
            )

        # 8. Service Entity & Policy Revalidation Under Lock
        service = await self.service_repo.get_by_id(session, organization_id, action.service_id)
        if service is None:
            raise EntityNotFound("Service", str(action.service_id))

        if actor_role is not None:
            role_enum = Role(actor_role) if isinstance(actor_role, str) else actor_role
        elif actor_user_id is not None:
            user = await self.user_repo.get_by_id(session, actor_user_id, organization_id)
            role_enum = Role(user.role) if user else Role.ADMIN
        else:
            role_enum = Role.ADMIN

        # Check if policy set changed since approval
        if org.policy_set_version != latest_approval.policy_set_version:
            env_str = getattr(service, "environment", "UNKNOWN") or "UNKNOWN"
            context = PolicyEvaluationContext(
                organization_id=organization_id,
                incident_id=action.incident_id,
                service_id=action.service_id,
                service_tier=service.tier,
                action_type=ActionType(action.action_type),
                risk_level=RiskLevel(action.risk_level),
                execution_mode=ExecutionMode.EXECUTE,
                environment=env_str,
                actor_id=actor_user_id,
                actor_role=role_enum,
                action_id=action.id,
            )
            active_policies = await self.policy_repo.list_active_policies_for_evaluation(
                session, organization_id
            )
            eval_res = evaluate_policies_deterministically(context, active_policies)

            # Persist new PolicyEvaluation
            new_eval = PolicyEvaluation(
                organization_id=organization_id,
                action_id=action.id,
                policy_id=eval_res.winning_policy_id,
                policy_version=eval_res.winning_policy_version,
                policy_set_version=org.policy_set_version,
                decision=eval_res.decision.value,
                context_hash=eval_res.context_hash,
                context_snapshot=eval_res.context_snapshot,
                winning_policy_snapshot=eval_res.winning_policy_snapshot,
                all_matched_policies=eval_res.all_matched_policies,
                reasons=eval_res.reasons,
                evaluated_by=actor_user_id,
            )
            await self.policy_repo.create_evaluation(session, new_eval)

            # Stale policy approval => block execution and require new approval
            msg = (
                f"Policy set version changed from {latest_approval.policy_set_version} to "
                f"{org.policy_set_version} since approval. New evaluation yielded '{eval_res.decision.value}'. "
                f"Re-approval is required."
            )
            await self._record_blocked(session, organization_id, actor_user_id, action.id, msg, correlation_id)
            await session.commit()
            raise PolicyViolationError(msg)

        # Check latest policy evaluation for action is not DENY
        latest_eval = await self.policy_repo.get_latest_evaluation_for_action(
            session, organization_id, action.id
        )
        if latest_eval and latest_eval.decision == PolicyDecision.DENY.value:
            msg = "Action execution prohibited by current active governance policy (DENY)."
            await self._record_blocked(session, organization_id, actor_user_id, action.id, msg, correlation_id)
            await session.commit()
            raise PolicyViolationError(msg)

        # 9. Validate Executor Registry (Fails closed on unknown executor)
        try:
            executor = self.registry.get(requested_executor_type)
        except UnsupportedExecutorError as exc:
            await self._record_blocked(session, organization_id, actor_user_id, action.id, str(exc), correlation_id)
            await session.commit()
            raise

        # 10. Advance state machine to EXECUTING
        validate_action_transition(action.status, ActionStatus.EXECUTING)
        old_status = action.status
        action.status = ActionStatus.EXECUTING.value
        action.execution_mode = ExecutionMode.EXECUTE.value
        action.version += 1

        bound_plan_hash = latest_approval.dry_run_plan_hash
        execution = ActionExecution(
            organization_id=organization_id,
            action_id=action.id,
            status="EXECUTING",
            execution_mode=ExecutionMode.EXECUTE.value,
            executor_type=requested_executor_type.upper(),
            plan_hash=bound_plan_hash,
            started_at=datetime.now(timezone.utc),
            correlation_id=correlation_id,
        )
        await self.remediation_repo.create_execution(session, execution)

        await self.audit_service.record(
            session=session,
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            action="ACTION_EXECUTION_STARTED",
            entity_type="ActionExecution",
            entity_id=execution.id,
            new_values={
                "action_id": str(action.id),
                "execution_mode": execution.execution_mode,
                "executor_type": execution.executor_type,
                "status": execution.status,
            },
            correlation_id=correlation_id,
        )
        await session.flush()

        # 11. Run Executor
        combined_params = dict(action.preconditions or {})
        if parameters_override:
            combined_params.update(parameters_override)

        exec_context = ExecutionContext(
            organization_id=organization_id,
            action_id=action.id,
            incident_id=action.incident_id,
            service_id=action.service_id,
            action_type=ActionType(action.action_type),
            risk_level=RiskLevel(action.risk_level),
            execution_mode=ExecutionMode.EXECUTE,
            environment=getattr(service, "environment", "production") or "production",
            plan_hash=bound_plan_hash,
            parameters=combined_params,
            actor_user_id=actor_user_id,
            actor_role=str(role_enum),
            correlation_id=correlation_id,
        )

        try:
            exec_result: ExecutionResult = await executor.execute(exec_context)
        except Exception as exc:
            exec_result = ExecutionResult(
                success=False,
                output={"error": str(exc)},
                error=str(exc),
                simulated=True,
                executor_type=requested_executor_type.upper(),
            )

        # 12. Finalize execution status
        execution.completed_at = datetime.now(timezone.utc)
        clean_output = sanitize_audit_payload(exec_result.output)
        execution.result = clean_output

        if exec_result.success:
            validate_action_transition(action.status, ActionStatus.SUCCEEDED)
            action.status = ActionStatus.SUCCEEDED.value
            action.version += 1
            execution.status = "SUCCEEDED"

            await self.audit_service.record(
                session=session,
                organization_id=organization_id,
                actor_user_id=actor_user_id,
                action="ACTION_EXECUTION_SUCCEEDED",
                entity_type="ActionExecution",
                entity_id=execution.id,
                new_values={
                    "action_id": str(action.id),
                    "status": "SUCCEEDED",
                    "plan_hash": bound_plan_hash,
                },
                correlation_id=correlation_id,
            )
        else:
            validate_action_transition(action.status, ActionStatus.FAILED)
            action.status = ActionStatus.FAILED.value
            action.version += 1
            execution.status = "FAILED"
            execution.error = exec_result.error

            await self.audit_service.record(
                session=session,
                organization_id=organization_id,
                actor_user_id=actor_user_id,
                action="ACTION_EXECUTION_FAILED",
                entity_type="ActionExecution",
                entity_id=execution.id,
                new_values={
                    "action_id": str(action.id),
                    "status": "FAILED",
                    "error": exec_result.error,
                },
                correlation_id=correlation_id,
            )

        await session.commit()
        await session.refresh(execution)
        return execution

    async def _record_blocked(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        actor_user_id: uuid.UUID | None,
        action_id: uuid.UUID,
        reason: str,
        correlation_id: str | None,
    ) -> None:
        """Record an ACTION_EXECUTION_BLOCKED audit event."""
        await self.audit_service.record(
            session=session,
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            action="ACTION_EXECUTION_BLOCKED",
            entity_type="RemediationAction",
            entity_id=action_id,
            new_values={
                "action_id": str(action_id),
                "blocked_reason": reason,
            },
            correlation_id=correlation_id,
        )
