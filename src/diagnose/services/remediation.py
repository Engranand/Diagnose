"""Service layer for Remediation Actions and Executions (Milestone 10.1)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Sequence

from sqlalchemy.ext.asyncio import AsyncSession

from diagnose.domain.exceptions import EntityNotFound, InvalidStateTransition, ValidationError
from diagnose.domain.remediation import (
    ActionStatus,
    ExecutionMode,
    ExecutorType,
    validate_action_transition,
)
from diagnose.models.remediation import ActionExecution, RemediationAction
from diagnose.repositories.incident import IncidentRepository
from diagnose.repositories.remediation import RemediationRepository
from diagnose.repositories.service import ServiceRepository
from diagnose.schemas.remediation import ActionCreateRequest
from diagnose.services.audit import AuditService


class RemediationService:
    """Operations for Remediation Action lifecycle management with deterministic state machine enforcement."""

    def __init__(
        self,
        remediation_repo: RemediationRepository | None = None,
        incident_repo: IncidentRepository | None = None,
        service_repo: ServiceRepository | None = None,
        audit_service: AuditService | None = None,
    ) -> None:
        self.remediation_repo = remediation_repo or RemediationRepository()
        self.incident_repo = incident_repo or IncidentRepository()
        self.service_repo = service_repo or ServiceRepository()
        self.audit_service = audit_service or AuditService()

    async def propose_action(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        incident_id: uuid.UUID,
        data: ActionCreateRequest,
        actor_user_id: uuid.UUID | None,
        correlation_id: str | None = None,
    ) -> RemediationAction:
        """Validate context, propose a new remediation action, and record an audit event."""
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
        correlation_id: str | None = None,
    ) -> RemediationAction:
        """Transition action from PENDING_APPROVAL to APPROVED."""
        action = await self.remediation_repo.get_action_by_id(
            session, organization_id, action_id, for_update=True
        )
        if action is None:
            raise EntityNotFound("RemediationAction", str(action_id))

        validate_action_transition(action.status, ActionStatus.APPROVED)
        old_status = action.status
        action.status = ActionStatus.APPROVED.value
        action.approved_by = actor_user_id
        action.version += 1

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
                "approved_by": str(actor_user_id) if actor_user_id else None,
                "version": action.version,
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
        """Transition action from PENDING_APPROVAL to REJECTED."""
        action = await self.remediation_repo.get_action_by_id(
            session, organization_id, action_id, for_update=True
        )
        if action is None:
            raise EntityNotFound("RemediationAction", str(action_id))

        validate_action_transition(action.status, ActionStatus.REJECTED)
        old_status = action.status
        action.status = ActionStatus.REJECTED.value
        action.version += 1

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
        """Create an execution attempt and transition action to EXECUTING.
        
        Enforces that action must be in APPROVED or EXECUTING state.
        """
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
