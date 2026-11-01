"""Service implementing deterministic dry-run execution for approved remediation actions (Milestone 10.3).

ABSOLUTE SAFETY GUARANTEE:
- Pure simulation and plan synthesis.
- Zero calls to subprocess, shell, SSH, Docker, Kubernetes, or cloud SDKs.
- Zero infrastructure mutation.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from diagnose.domain.dry_run import (
    DryRunPlanBuilder,
    DryRunResult,
    DryRunStatus,
    ExecutionValidator,
)
from diagnose.domain.exceptions import (
    ActionNotExecutableError,
    EntityNotFound,
    ExecutionValidationError,
    PolicyViolationError,
)
from diagnose.domain.policy import PolicyDecision, PolicyEvaluationContext
from diagnose.domain.remediation import (
    ActionStatus,
    ActionType,
    ExecutionMode,
    ExecutorType,
    RiskLevel,
)
from diagnose.domain.roles import Role
from diagnose.models.organization import Organization
from diagnose.models.policy import PolicyEvaluation
from diagnose.models.remediation import ActionExecution, RemediationAction
from diagnose.models.service import Service
from diagnose.schemas.dry_run import DryRunPlanResponse, DryRunResponse
from diagnose.services.audit import AuditService
from diagnose.services.policy import PolicyService


class DryRunService:
    """Orchestrates deterministic validation, policy re-checks, plan building, and execution recording."""

    def __init__(
        self,
        audit_service: AuditService | None = None,
        policy_service: PolicyService | None = None,
    ) -> None:
        self.audit_service = audit_service or AuditService()
        self.policy_service = policy_service or PolicyService(audit_service=self.audit_service)

    async def execute_dry_run(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        action_id: uuid.UUID,
        actor_user_id: uuid.UUID,
        actor_role: str,
        idempotency_key: str | None = None,
        parameters_override: dict[str, Any] | None = None,
        requested_executor_type: str = "SIMULATOR",
        correlation_id: str | None = None,
    ) -> DryRunResponse:
        """Execute a deterministic dry-run on an approved remediation action."""
        started_at = datetime.now(timezone.utc)

        # 1. Acquire organization serialization lock
        stmt_org = (
            select(Organization)
            .where(Organization.id == organization_id)
            .with_for_update()
        )
        org_row = (await session.execute(stmt_org)).scalars().first()
        if org_row is None:
            raise EntityNotFound("Organization", str(organization_id))

        # 2. Acquire action row lock
        stmt_action = (
            select(RemediationAction)
            .where(
                RemediationAction.id == action_id,
                RemediationAction.organization_id == organization_id,
            )
            .with_for_update()
        )
        action_row = (await session.execute(stmt_action)).scalars().first()
        if action_row is None:
            raise EntityNotFound("RemediationAction", str(action_id))

        # 3. Emit started audit event
        await self.audit_service.record(
            session=session,
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            action="ACTION_DRY_RUN_STARTED",
            entity_type="RemediationAction",
            entity_id=action_row.id,
            new_values={
                "action_type": action_row.action_type,
                "status": action_row.status,
                "correlation_id": correlation_id,
            },
        )

        # 4. Check action executable lifecycle state
        if action_row.status != ActionStatus.APPROVED:
            await self.audit_service.record(
                session=session,
                organization_id=organization_id,
                actor_user_id=actor_user_id,
                action="ACTION_DRY_RUN_FAILED",
                entity_type="RemediationAction",
                entity_id=action_row.id,
                new_values={
                    "reason": f"Action is in '{action_row.status}' state; must be APPROVED",
                    "status": action_row.status,
                },
            )
            await session.commit()
            raise ActionNotExecutableError(
                f"Action {action_id} cannot be executed in state '{action_row.status}'. "
                "Action must be APPROVED before execution."
            )

        # 5. Retrieve target service within same tenant
        stmt_svc = select(Service).where(
            Service.id == action_row.service_id,
            Service.organization_id == organization_id,
        )
        service_row = (await session.execute(stmt_svc)).scalars().first()
        if service_row is None:
            failed_exec = ActionExecution(
                organization_id=organization_id,
                action_id=action_row.id,
                status="FAILED",
                execution_mode="DRY_RUN",
                executor_type=requested_executor_type,
                error="Target service not found or does not belong to organization",
                started_at=started_at,
                completed_at=datetime.now(timezone.utc),
                correlation_id=correlation_id,
            )
            session.add(failed_exec)
            await session.flush()

            await self.audit_service.record(
                session=session,
                organization_id=organization_id,
                actor_user_id=actor_user_id,
                action="ACTION_DRY_RUN_FAILED",
                entity_type="RemediationAction",
                entity_id=action_row.id,
                new_values={"reason": "Target service not found or cross-tenant"},
            )
            await session.commit()
            raise EntityNotFound("Service", str(action_row.service_id))

        # 6. Combined parameters & environment resolution
        combined_params = dict(action_row.preconditions or {})
        if parameters_override:
            combined_params.update(parameters_override)
        env = str(combined_params.get("environment") or "UNKNOWN")

        safe_executor_type = (
            requested_executor_type
            if requested_executor_type in (ExecutorType.SIMULATOR.value, ExecutorType.SYSTEM.value, ExecutorType.MANUAL.value)
            else ExecutorType.SIMULATOR.value
        )

        # Authoritative Policy Re-check (Requirement 4)
        stmt_eval = (
            select(PolicyEvaluation)
            .where(
                PolicyEvaluation.action_id == action_row.id,
                PolicyEvaluation.organization_id == organization_id,
            )
            .order_by(PolicyEvaluation.created_at.desc())
        )
        latest_eval = (await session.execute(stmt_eval)).scalars().first()

        # Check if policy evaluation is stale or missing
        if latest_eval is None or latest_eval.policy_set_version != org_row.policy_set_version:
            context = PolicyEvaluationContext(
                organization_id=organization_id,
                incident_id=action_row.incident_id,
                service_id=service_row.id,
                service_tier=service_row.tier,
                action_type=ActionType(action_row.action_type),
                risk_level=RiskLevel(action_row.risk_level),
                execution_mode=ExecutionMode.DRY_RUN,
                environment=env,
                actor_id=actor_user_id,
                actor_role=Role(actor_role) if isinstance(actor_role, str) else actor_role,
                action_id=action_row.id,
            )
            fresh_eval = await self.policy_service.evaluate_context_and_persist(
                session=session,
                context=context,
                action_id=action_row.id,
                actor_user_id=actor_user_id,
            )
            if fresh_eval.decision == PolicyDecision.DENY:
                reason_str = "; ".join(fresh_eval.reasons) if fresh_eval.reasons else "Denied by updated policy set"
                failed_exec = ActionExecution(
                    organization_id=organization_id,
                    action_id=action_row.id,
                    status="FAILED",
                    execution_mode="DRY_RUN",
                    executor_type=safe_executor_type,
                    error=f"Policy violation: {reason_str}",
                    started_at=started_at,
                    completed_at=datetime.now(timezone.utc),
                    correlation_id=correlation_id,
                )
                session.add(failed_exec)
                await session.flush()

                await self.audit_service.record(
                    session=session,
                    organization_id=organization_id,
                    actor_user_id=actor_user_id,
                    action="ACTION_DRY_RUN_FAILED",
                    entity_type="RemediationAction",
                    entity_id=action_row.id,
                    new_values={"reason": "Action denied by updated policy set"},
                )
                await session.commit()
                raise PolicyViolationError(
                    f"Remediation action denied by policy: {reason_str}"
                )

            if fresh_eval.decision == PolicyDecision.REQUIRE_APPROVAL:
                if action_row.approved_by is None:
                    # Action was auto-approved under previous ALLOW, but current policy mandates human approval
                    failed_exec = ActionExecution(
                        organization_id=organization_id,
                        action_id=action_row.id,
                        status="FAILED",
                        execution_mode="DRY_RUN",
                        executor_type=safe_executor_type,
                        error="Policy changed to REQUIRE_APPROVAL; action requires explicit human approval",
                        started_at=started_at,
                        completed_at=datetime.now(timezone.utc),
                        correlation_id=correlation_id,
                    )
                    session.add(failed_exec)
                    await session.flush()

                    await self.audit_service.record(
                        session=session,
                        organization_id=organization_id,
                        actor_user_id=actor_user_id,
                        action="ACTION_DRY_RUN_FAILED",
                        entity_type="RemediationAction",
                        entity_id=action_row.id,
                        new_values={"reason": "Policy changed to REQUIRE_APPROVAL"},
                    )
                    await session.commit()
                    raise PolicyViolationError(
                        "Policy changed to REQUIRE_APPROVAL; action requires explicit human approval before execution"
                    )

        elif latest_eval.decision == PolicyDecision.DENY:
            failed_exec = ActionExecution(
                organization_id=organization_id,
                action_id=action_row.id,
                status="FAILED",
                execution_mode="DRY_RUN",
                executor_type=safe_executor_type,
                error="Remediation action was previously denied by policy",
                started_at=started_at,
                completed_at=datetime.now(timezone.utc),
                correlation_id=correlation_id,
            )
            session.add(failed_exec)
            await session.flush()

            await self.audit_service.record(
                session=session,
                organization_id=organization_id,
                actor_user_id=actor_user_id,
                action="ACTION_DRY_RUN_FAILED",
                entity_type="RemediationAction",
                entity_id=action_row.id,
                new_values={"reason": "Action previously denied by policy"},
            )
            await session.commit()
            raise PolicyViolationError("Remediation action previously denied by policy")

        # 7. Validation of parameters and safety constraints (Requirement 3)
        validation_result = ExecutionValidator.validate(
            action=action_row,
            service=service_row,
            parameters=combined_params,
            requested_executor_type=requested_executor_type,
            requested_execution_mode="DRY_RUN",
        )

        if not validation_result.is_valid:
            error_summary = "; ".join(validation_result.errors)
            failed_exec = ActionExecution(
                organization_id=organization_id,
                action_id=action_row.id,
                status="FAILED",
                execution_mode="DRY_RUN",
                executor_type=safe_executor_type,
                error=error_summary,
                result={
                    "errors": validation_result.errors,
                    "warnings": validation_result.warnings,
                    "no_real_execution": True,
                },
                started_at=started_at,
                completed_at=datetime.now(timezone.utc),
                correlation_id=correlation_id,
            )
            session.add(failed_exec)
            await session.flush()

            await self.audit_service.record(
                session=session,
                organization_id=organization_id,
                actor_user_id=actor_user_id,
                action="ACTION_DRY_RUN_FAILED",
                entity_type="RemediationAction",
                entity_id=action_row.id,
                new_values={"errors": validation_result.errors},
            )
            await session.commit()
            raise ExecutionValidationError(error_summary)

        # 8. Record validated audit event
        await self.audit_service.record(
            session=session,
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            action="ACTION_DRY_RUN_VALIDATED",
            entity_type="RemediationAction",
            entity_id=action_row.id,
            new_values={"warnings": validation_result.warnings},
        )

        # 9. Build deterministic plan
        plan = DryRunPlanBuilder.build_plan(
            action=action_row,
            service=service_row,
            parameters=combined_params,
            warnings=validation_result.warnings,
            executor_type=requested_executor_type,
            execution_mode="DRY_RUN",
        )

        # 10. Idempotency Check (Requirement 6)
        stmt_existing = (
            select(ActionExecution)
            .where(
                ActionExecution.action_id == action_row.id,
                ActionExecution.execution_mode == "DRY_RUN",
                ActionExecution.status == "SUCCEEDED",
                ActionExecution.plan_hash == plan.plan_hash,
            )
            .order_by(ActionExecution.created_at.desc())
        )
        existing_exec = (await session.execute(stmt_existing)).scalars().first()
        if existing_exec and existing_exec.result:
            # Deterministic reuse of identical execution attempt
            return DryRunResponse.model_validate(existing_exec.result)

        # 11. Construct DryRunResult
        exec_id = uuid.uuid4()
        completed_at = datetime.now(timezone.utc)
        simulated_outcome = (
            f"Simulated dry-run for '{action_row.action_type}' on service '{service_row.name}' "
            "passed all safety checks with 0 mutations."
        )

        dry_run_result = DryRunResult(
            status=DryRunStatus.DRY_RUN_SUCCESS,
            action_id=action_row.id,
            execution_id=exec_id,
            plan=plan,
            simulated_outcome=simulated_outcome,
            safety_checks_passed=True,
            expected_effects=plan.expected_effects,
            warnings=plan.warnings,
            errors=[],
            no_real_execution=True,
            started_at=started_at,
            completed_at=completed_at,
        )
        result_dict = dry_run_result.to_dict()

        # 12. Persist durable ActionExecution record
        execution = ActionExecution(
            id=exec_id,
            organization_id=organization_id,
            action_id=action_row.id,
            status="SUCCEEDED",
            execution_mode="DRY_RUN",
            executor_type=safe_executor_type,
            plan_hash=plan.plan_hash,
            started_at=started_at,
            completed_at=completed_at,
            result=result_dict,
            error=None,
            correlation_id=correlation_id,
        )
        session.add(execution)
        await session.flush()

        # 13. Audit completed event
        await self.audit_service.record(
            session=session,
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            action="ACTION_DRY_RUN_COMPLETED",
            entity_type="RemediationAction",
            entity_id=action_row.id,
            new_values={
                "execution_id": str(exec_id),
                "plan_hash": plan.plan_hash,
                "status": DryRunStatus.DRY_RUN_SUCCESS.value,
                "no_real_execution": True,
            },
        )

        return DryRunResponse.model_validate(result_dict)
