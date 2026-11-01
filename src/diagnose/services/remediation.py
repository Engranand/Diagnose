"""Service layer for Remediation Actions and Executions (Milestone 10.1 & 10.2)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Sequence

from sqlalchemy.ext.asyncio import AsyncSession

from diagnose.domain.approval import (
    ApprovalDecision,
    validate_approval_state,
    validate_dry_run_hash,
    validate_rejection_state,
    validate_separation_of_duties,
)
from diagnose.domain.exceptions import (
    DryRunHashMismatchError,
    EntityNotFound,
    InvalidStateTransition,
    PolicyViolationError,
    SeparationOfDutiesError,
    ValidationError,
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
from diagnose.models.approval import ActionApproval
from diagnose.models.policy import PolicyEvaluation
from diagnose.models.remediation import ActionExecution, RemediationAction
from diagnose.repositories.approval import ApprovalRepository
from diagnose.repositories.incident import IncidentRepository
from diagnose.repositories.policy import PolicyRepository
from diagnose.repositories.remediation import RemediationRepository
from diagnose.repositories.service import ServiceRepository
from diagnose.repositories.user import UserRepository
from diagnose.schemas.remediation import ActionCreateRequest
from diagnose.services.audit import AuditService


class RemediationService:
    """Operations for Remediation Action lifecycle management with deterministic state machine enforcement."""

    def __init__(
        self,
        remediation_repo: RemediationRepository | None = None,
        incident_repo: IncidentRepository | None = None,
        service_repo: ServiceRepository | None = None,
        policy_repo: PolicyRepository | None = None,
        user_repo: UserRepository | None = None,
        approval_repo: ApprovalRepository | None = None,
        audit_service: AuditService | None = None,
    ) -> None:
        self.remediation_repo = remediation_repo or RemediationRepository()
        self.incident_repo = incident_repo or IncidentRepository()
        self.service_repo = service_repo or ServiceRepository()
        self.policy_repo = policy_repo or PolicyRepository()
        self.user_repo = user_repo or UserRepository()
        self.approval_repo = approval_repo or ApprovalRepository()
        self.audit_service = audit_service or AuditService()

    async def propose_action(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        incident_id: uuid.UUID,
        data: ActionCreateRequest,
        actor_user_id: uuid.UUID | None,
        actor_role: Role | str | None = None,
        environment: str | None = None,
        correlation_id: str | None = None,
    ) -> RemediationAction:
        """Validate context, evaluate policy under organization lock, propose action, and record audit events."""
        # 1. Pessimistically lock organization row to serialize policy evaluation and revision check
        org = await self.policy_repo.lock_organization(session, organization_id)
        if org is None:
            raise EntityNotFound("Organization", str(organization_id))

        current_set_version = org.policy_set_version

        # 2. Validate incident and service belonging to tenant
        incident = await self.incident_repo.get_by_id(session, organization_id, incident_id)
        if incident is None:
            raise EntityNotFound("Incident", str(incident_id))

        service = await self.service_repo.get_by_id(session, organization_id, data.service_id)
        if service is None:
            raise EntityNotFound("Service", str(data.service_id))

        if incident.service_id != data.service_id:
            raise ValidationError(
                f"Target service {data.service_id} does not match incident affected service {incident.service_id}."
            )

        # 3. Resolve actor role
        if actor_role is not None:
            role_enum = Role(actor_role) if isinstance(actor_role, str) else actor_role
        elif actor_user_id is not None:
            user = await self.user_repo.get_by_id(session, actor_user_id, organization_id)
            role_enum = Role(user.role) if user else Role.ENGINEER
        else:
            role_enum = Role.ENGINEER

        # 4. Construct canonical PolicyEvaluationContext
        env_str = environment or getattr(service, "environment", "UNKNOWN") or "UNKNOWN"
        context = PolicyEvaluationContext(
            organization_id=organization_id,
            incident_id=incident_id,
            service_id=data.service_id,
            service_tier=service.tier,
            action_type=data.action_type,
            risk_level=data.risk_level,
            execution_mode=data.execution_mode,
            environment=env_str,
            actor_id=actor_user_id,
            actor_role=role_enum,
            action_id=None,
        )

        # 5. Evaluate active policies
        active_policies = await self.policy_repo.list_active_policies_for_evaluation(
            session, organization_id
        )
        eval_res = evaluate_policies_deterministically(context, active_policies)

        # 6. If policy DENY: persist evaluation with action_id=None, audit, commit, and abort
        if eval_res.decision == PolicyDecision.DENY:
            denied_eval = PolicyEvaluation(
                organization_id=organization_id,
                action_id=None,
                policy_id=eval_res.winning_policy_id,
                policy_version=eval_res.winning_policy_version,
                policy_set_version=current_set_version,
                decision=eval_res.decision.value,
                context_hash=eval_res.context_hash,
                context_snapshot=eval_res.context_snapshot,
                winning_policy_snapshot=eval_res.winning_policy_snapshot,
                all_matched_policies=eval_res.all_matched_policies,
                reasons=eval_res.reasons,
                evaluated_by=actor_user_id,
            )
            await self.policy_repo.create_evaluation(session, denied_eval)

            await self.audit_service.record(
                session=session,
                organization_id=organization_id,
                actor_user_id=actor_user_id,
                action="POLICY_EVALUATION_DENIED",
                entity_type="PolicyEvaluation",
                entity_id=denied_eval.id,
                new_values={
                    "decision": "DENY",
                    "policy_id": str(eval_res.winning_policy_id) if eval_res.winning_policy_id else None,
                    "policy_set_version": current_set_version,
                },
                correlation_id=correlation_id,
            )
            await session.commit()
            winning_name = (
                eval_res.winning_policy_snapshot.get("name", "Remediation Governance Policy")
                if eval_res.winning_policy_snapshot
                else "Remediation Governance Policy"
            )
            raise PolicyViolationError(
                f"Action proposal prohibited by policy '{winning_name}': {eval_res.reasons[0] if eval_res.reasons else 'DENY'}"
            )

        # 7. Create RemediationAction in PROPOSED status
        action = RemediationAction(
            organization_id=organization_id,
            incident_id=incident_id,
            service_id=data.service_id,
            action_type=data.action_type.value,
            risk_level=data.risk_level.value,
            status=ActionStatus.PROPOSED.value,
            execution_mode=data.execution_mode.value,
            title=data.title,
            description=data.description,
            rationale=data.rationale,
            preconditions=data.preconditions,
            expected_outcome=data.expected_outcome,
            rollback_plan=data.rollback_plan,
            proposed_by=actor_user_id,
            version=1,
        )
        await self.remediation_repo.create_action(session, action)

        # 8. Persist PolicyEvaluation with action_id
        action_eval = PolicyEvaluation(
            organization_id=organization_id,
            action_id=action.id,
            policy_id=eval_res.winning_policy_id,
            policy_version=eval_res.winning_policy_version,
            policy_set_version=current_set_version,
            decision=eval_res.decision.value,
            context_hash=eval_res.context_hash,
            context_snapshot=eval_res.context_snapshot,
            winning_policy_snapshot=eval_res.winning_policy_snapshot,
            all_matched_policies=eval_res.all_matched_policies,
            reasons=eval_res.reasons,
            evaluated_by=actor_user_id,
        )
        await self.policy_repo.create_evaluation(session, action_eval)

        # 9. Handle Auto-Approval if ALLOW
        is_auto_approved = False
        if eval_res.decision == PolicyDecision.ALLOW:
            # Strict persisted DB provenance check
            if (
                action_eval.action_id == action.id
                and action_eval.organization_id == action.organization_id
                and action_eval.decision == PolicyDecision.ALLOW.value
                and action_eval.context_hash == context.compute_hash()
                and action_eval.policy_set_version == org.policy_set_version
            ):
                validate_action_transition(
                    action.status, ActionStatus.APPROVED, auto_approval_provenance=action_eval
                )
                action.status = ActionStatus.APPROVED.value
                action.approved_by = None
                action.version += 1
                is_auto_approved = True

        # 10. Audit events
        await self.audit_service.record(
            session=session,
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            action="ACTION_CREATED",
            entity_type="RemediationAction",
            entity_id=action.id,
            new_values={
                "incident_id": str(incident_id),
                "service_id": str(data.service_id),
                "action_type": action.action_type,
                "risk_level": action.risk_level,
                "status": action.status,
                "execution_mode": action.execution_mode,
                "title": action.title,
            },
            correlation_id=correlation_id,
        )

        await self.audit_service.record(
            session=session,
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            action="POLICY_EVALUATION_RECORDED",
            entity_type="PolicyEvaluation",
            entity_id=action_eval.id,
            new_values={
                "action_id": str(action.id),
                "decision": action_eval.decision,
                "policy_set_version": action_eval.policy_set_version,
            },
            correlation_id=correlation_id,
        )

        if is_auto_approved:
            await self.audit_service.record(
                session=session,
                organization_id=organization_id,
                actor_user_id=actor_user_id,
                action="ACTION_APPROVED",
                entity_type="RemediationAction",
                entity_id=action.id,
                new_values={
                    "status": action.status,
                    "auto_approved": True,
                    "evaluation_id": str(action_eval.id),
                    "policy_id": str(eval_res.winning_policy_id) if eval_res.winning_policy_id else None,
                    "policy_version": eval_res.winning_policy_version,
                    "policy_set_version": current_set_version,
                },
                correlation_id=correlation_id,
            )

        await session.commit()
        await session.refresh(action)
        return action

    async def submit_for_approval(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        action_id: uuid.UUID,
        actor_user_id: uuid.UUID | None,
        correlation_id: str | None = None,
    ) -> RemediationAction:
        """Transition action from PROPOSED to PENDING_APPROVAL."""
        action = await self.remediation_repo.get_action_by_id(
            session, organization_id, action_id, for_update=True
        )
        if action is None:
            raise EntityNotFound("RemediationAction", str(action_id))

        validate_action_transition(action.status, ActionStatus.PENDING_APPROVAL)
        old_status = action.status
        action.status = ActionStatus.PENDING_APPROVAL.value
        action.version += 1

        await self.audit_service.record(
            session=session,
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            action="ACTION_SUBMITTED_FOR_APPROVAL",
            entity_type="RemediationAction",
            entity_id=action.id,
            old_values={"status": old_status},
            new_values={"status": action.status, "version": action.version},
            correlation_id=correlation_id,
        )
        await session.commit()
        await session.refresh(action)
        return action

    async def approve_action(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        action_id: uuid.UUID,
        actor_user_id: uuid.UUID | None,
        reason: str | None = None,
        dry_run_plan_hash: str | None = None,
        actor_role: Role | str | None = None,
        correlation_id: str | None = None,
    ) -> RemediationAction:
        """Approve action under organization lock, strict policy re-evaluation, separation-of-duties, and plan hash verification."""
        # 1. Pessimistically lock Organization row FIRST to serialize against policy mutations
        org = await self.policy_repo.lock_organization(session, organization_id)
        if org is None:
            raise EntityNotFound("Organization", str(organization_id))

        current_set_version = org.policy_set_version

        # 2. Pessimistically lock action row SECOND
        action = await self.remediation_repo.get_action_by_id(
            session, organization_id, action_id, for_update=True
        )
        if action is None:
            raise EntityNotFound("RemediationAction", str(action_id))

        # 3. Separation of duties validation (CRITICAL SECURITY RULE)
        validate_separation_of_duties(action.proposed_by, actor_user_id)

        # 4. State validation (action must be in PENDING_APPROVAL)
        validate_approval_state(action.status)

        # 5. Fetch latest evaluation
        latest_eval = await self.policy_repo.get_latest_evaluation_for_action(
            session, organization_id, action.id
        )

        # 6. If latest evaluation is missing or stale (policy_set_version changed), re-evaluate!
        if latest_eval is None or latest_eval.policy_set_version != current_set_version:
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

            env_str = getattr(service, "environment", "UNKNOWN") or "UNKNOWN"
            context = PolicyEvaluationContext(
                organization_id=organization_id,
                incident_id=action.incident_id,
                service_id=action.service_id,
                service_tier=service.tier,
                action_type=ActionType(action.action_type),
                risk_level=RiskLevel(action.risk_level),
                execution_mode=ExecutionMode(action.execution_mode),
                environment=env_str,
                actor_id=actor_user_id,
                actor_role=role_enum,
                action_id=action.id,
            )

            active_policies = await self.policy_repo.list_active_policies_for_evaluation(
                session, organization_id
            )
            eval_res = evaluate_policies_deterministically(context, active_policies)

            latest_eval = PolicyEvaluation(
                organization_id=organization_id,
                action_id=action.id,
                policy_id=eval_res.winning_policy_id,
                policy_version=eval_res.winning_policy_version,
                policy_set_version=current_set_version,
                decision=eval_res.decision.value,
                context_hash=eval_res.context_hash,
                context_snapshot=eval_res.context_snapshot,
                winning_policy_snapshot=eval_res.winning_policy_snapshot,
                all_matched_policies=eval_res.all_matched_policies,
                reasons=eval_res.reasons,
                evaluated_by=actor_user_id,
            )
            await self.policy_repo.create_evaluation(session, latest_eval)

        # 7. If policy decision is DENY: abort approval
        if latest_eval.decision == PolicyDecision.DENY.value:
            await self.audit_service.record(
                session=session,
                organization_id=organization_id,
                actor_user_id=actor_user_id,
                action="POLICY_EVALUATION_DENIED",
                entity_type="PolicyEvaluation",
                entity_id=latest_eval.id,
                new_values={
                    "action_id": str(action.id),
                    "attempted": "APPROVED",
                    "decision": "DENY",
                    "policy_set_version": current_set_version,
                },
                correlation_id=correlation_id,
            )
            await session.commit()
            raise PolicyViolationError("Action approval prohibited by current active governance policy (DENY).")

        # 8. Dry-run plan hash verification & provenance binding
        latest_execution = await self.remediation_repo.get_latest_execution_for_action(
            session, organization_id, action.id
        )
        actual_plan_hash = latest_execution.plan_hash if latest_execution else None
        validate_dry_run_hash(actual_plan_hash=actual_plan_hash, expected_plan_hash=dry_run_plan_hash)
        bound_plan_hash = dry_run_plan_hash if dry_run_plan_hash is not None else actual_plan_hash

        # 9. Create immutable ActionApproval record
        if actor_user_id is None:
            raise ValidationError("Approver user ID is required to record action approval.")

        approval = ActionApproval(
            organization_id=organization_id,
            action_id=action.id,
            approver_user_id=actor_user_id,
            decision=ApprovalDecision.APPROVED.value,
            reason=reason,
            policy_set_version=current_set_version,
            policy_evaluation_id=latest_eval.id if latest_eval else None,
            dry_run_plan_hash=bound_plan_hash,
            decided_at=datetime.now(timezone.utc),
        )
        await self.approval_repo.create_approval(session, approval)

        # 10. Advance action state machine
        validate_action_transition(action.status, ActionStatus.APPROVED)
        old_status = action.status
        action.status = ActionStatus.APPROVED.value
        action.approved_by = actor_user_id
        action.version += 1

        # 11. Record audit logs
        await self.audit_service.record(
            session=session,
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            action="ACTION_APPROVAL_RECORDED",
            entity_type="ActionApproval",
            entity_id=approval.id,
            new_values={
                "action_id": str(action.id),
                "decision": approval.decision,
                "reason": approval.reason,
                "policy_set_version": approval.policy_set_version,
                "policy_evaluation_id": str(approval.policy_evaluation_id) if approval.policy_evaluation_id else None,
                "dry_run_plan_hash": approval.dry_run_plan_hash,
            },
            correlation_id=correlation_id,
        )

        await self.audit_service.record(
            session=session,
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            action="ACTION_APPROVED",
            entity_type="RemediationAction",
            entity_id=action.id,
            old_values={"status": old_status},
            new_values={
                "status": action.status,
                "approved_by": str(actor_user_id),
                "version": action.version,
                "evaluation_id": str(latest_eval.id) if latest_eval else None,
                "policy_set_version": current_set_version,
                "dry_run_plan_hash": bound_plan_hash,
            },
            correlation_id=correlation_id,
        )
        await session.commit()
        await session.refresh(action)
        return action

    async def reject_action(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        action_id: uuid.UUID,
        actor_user_id: uuid.UUID | None,
        reason: str | None = None,
        correlation_id: str | None = None,
    ) -> RemediationAction:
        """Transition action from PENDING_APPROVAL to REJECTED with immutable approval record."""
        # 1. Pessimistically lock Organization row
        org = await self.policy_repo.lock_organization(session, organization_id)
        if org is None:
            raise EntityNotFound("Organization", str(organization_id))

        current_set_version = org.policy_set_version

        # 2. Pessimistically lock action row
        action = await self.remediation_repo.get_action_by_id(
            session, organization_id, action_id, for_update=True
        )
        if action is None:
            raise EntityNotFound("RemediationAction", str(action_id))

        # 3. State validation (action must be in PENDING_APPROVAL)
        validate_rejection_state(action.status)

        # 4. Fetch latest evaluation and execution
        latest_eval = await self.policy_repo.get_latest_evaluation_for_action(
            session, organization_id, action.id
        )
        latest_execution = await self.remediation_repo.get_latest_execution_for_action(
            session, organization_id, action.id
        )
        actual_plan_hash = latest_execution.plan_hash if latest_execution else None

        # 5. Create immutable ActionApproval record with REJECTED decision
        if actor_user_id is None:
            raise ValidationError("Approver user ID is required to record action rejection.")

        approval = ActionApproval(
            organization_id=organization_id,
            action_id=action.id,
            approver_user_id=actor_user_id,
            decision=ApprovalDecision.REJECTED.value,
            reason=reason,
            policy_set_version=current_set_version,
            policy_evaluation_id=latest_eval.id if latest_eval else None,
            dry_run_plan_hash=actual_plan_hash,
            decided_at=datetime.now(timezone.utc),
        )
        await self.approval_repo.create_approval(session, approval)

        # 6. Advance action state machine
        validate_action_transition(action.status, ActionStatus.REJECTED)
        old_status = action.status
        action.status = ActionStatus.REJECTED.value
        action.version += 1

        # 7. Audit records
        await self.audit_service.record(
            session=session,
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            action="ACTION_APPROVAL_RECORDED",
            entity_type="ActionApproval",
            entity_id=approval.id,
            new_values={
                "action_id": str(action.id),
                "decision": approval.decision,
                "reason": approval.reason,
                "policy_set_version": approval.policy_set_version,
                "policy_evaluation_id": str(approval.policy_evaluation_id) if approval.policy_evaluation_id else None,
                "dry_run_plan_hash": approval.dry_run_plan_hash,
            },
            correlation_id=correlation_id,
        )

        await self.audit_service.record(
            session=session,
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            action="ACTION_REJECTED",
            entity_type="RemediationAction",
            entity_id=action.id,
            old_values={"status": old_status},
            new_values={
                "status": action.status,
                "rejection_reason": reason,
                "version": action.version,
            },
            correlation_id=correlation_id,
        )
        await session.commit()
        await session.refresh(action)
        return action

    async def list_approvals_for_action(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        action_id: uuid.UUID,
    ) -> Sequence[ActionApproval]:
        """Retrieve audit trail of all approval and rejection decisions for an action."""
        action = await self.remediation_repo.get_action_by_id(session, organization_id, action_id)
        if action is None:
            raise EntityNotFound("RemediationAction", str(action_id))
        return await self.approval_repo.list_approvals_for_action(session, organization_id, action_id)

    async def cancel_action(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        action_id: uuid.UUID,
        actor_user_id: uuid.UUID | None,
        correlation_id: str | None = None,
    ) -> RemediationAction:
        """Transition action to CANCELLED."""
        action = await self.remediation_repo.get_action_by_id(
            session, organization_id, action_id, for_update=True
        )
        if action is None:
            raise EntityNotFound("RemediationAction", str(action_id))

        validate_action_transition(action.status, ActionStatus.CANCELLED)
        old_status = action.status
        action.status = ActionStatus.CANCELLED.value
        action.version += 1

        await self.audit_service.record(
            session=session,
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            action="ACTION_CANCELLED",
            entity_type="RemediationAction",
            entity_id=action.id,
            old_values={"status": old_status},
            new_values={"status": action.status, "version": action.version},
            correlation_id=correlation_id,
        )
        await session.commit()
        await session.refresh(action)
        return action

    async def record_execution_started(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        action_id: uuid.UUID,
        execution_mode: ExecutionMode | None = None,
        executor_type: ExecutorType = ExecutorType.SIMULATOR,
        actor_user_id: uuid.UUID | None = None,
        correlation_id: str | None = None,
    ) -> ActionExecution:
        """Create an execution attempt and transition action to EXECUTING."""
        action = await self.remediation_repo.get_action_by_id(
            session, organization_id, action_id, for_update=True
        )
        if action is None:
            raise EntityNotFound("RemediationAction", str(action_id))

        if action.status not in (ActionStatus.APPROVED.value, ActionStatus.EXECUTING.value):
            raise InvalidStateTransition(
                "RemediationAction", action.status, ActionStatus.EXECUTING.value
            )

        if action.status == ActionStatus.APPROVED.value:
            validate_action_transition(action.status, ActionStatus.EXECUTING)
            action.status = ActionStatus.EXECUTING.value
            action.version += 1

        mode = execution_mode.value if execution_mode else action.execution_mode
        execution = ActionExecution(
            organization_id=organization_id,
            action_id=action_id,
            status="EXECUTING",
            execution_mode=mode,
            started_at=datetime.now(timezone.utc),
            executor_type=executor_type.value if isinstance(executor_type, ExecutorType) else str(executor_type),
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
                "action_id": str(action_id),
                "execution_mode": mode,
                "status": execution.status,
            },
            correlation_id=correlation_id,
        )
        await session.commit()
        await session.refresh(execution)
        return execution

    async def record_execution_completed(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        action_id: uuid.UUID,
        execution_id: uuid.UUID,
        success: bool,
        result: dict[str, Any] | None = None,
        error: str | None = None,
        actor_user_id: uuid.UUID | None = None,
        correlation_id: str | None = None,
    ) -> ActionExecution:
        """Record completion of an execution attempt and transition action status."""
        action = await self.remediation_repo.get_action_by_id(
            session, organization_id, action_id, for_update=True
        )
        if action is None:
            raise EntityNotFound("RemediationAction", str(action_id))

        execution = await self.remediation_repo.get_execution_by_id(
            session, organization_id, execution_id
        )
        if execution is None:
            raise EntityNotFound("ActionExecution", str(execution_id))

        target_status = ActionStatus.SUCCEEDED if success else ActionStatus.FAILED
        validate_action_transition(action.status, target_status)

        action.status = target_status.value
        action.version += 1

        execution.status = "SUCCEEDED" if success else "FAILED"
        execution.completed_at = datetime.now(timezone.utc)
        execution.result = result
        execution.error = error

        audit_action = "ACTION_EXECUTION_SUCCEEDED" if success else "ACTION_EXECUTION_FAILED"
        await self.audit_service.record(
            session=session,
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            action=audit_action,
            entity_type="ActionExecution",
            entity_id=execution.id,
            new_values={
                "action_id": str(action_id),
                "execution_status": execution.status,
                "action_status": action.status,
            },
            correlation_id=correlation_id,
        )
        await session.commit()
        await session.refresh(execution)
        return execution

    async def get_action(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        action_id: uuid.UUID,
    ) -> RemediationAction:
        """Retrieve a single remediation action with its execution attempts."""
        action = await self.remediation_repo.get_action_by_id(
            session, organization_id, action_id
        )
        if action is None:
            raise EntityNotFound("RemediationAction", str(action_id))
        return action

    async def list_actions(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        incident_id: uuid.UUID,
        status: str | None = None,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[Sequence[RemediationAction], int]:
        """List remediation actions for an incident."""
        incident = await self.incident_repo.get_by_id(session, organization_id, incident_id)
        if incident is None:
            raise EntityNotFound("Incident", str(incident_id))

        return await self.remediation_repo.list_actions_for_incident(
            session=session,
            organization_id=organization_id,
            incident_id=incident_id,
            status=status,
            offset=offset,
            limit=limit,
        )
