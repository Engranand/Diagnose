"""Incident service — business logic, state transitions, and audit atomicity."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Sequence

from sqlalchemy.ext.asyncio import AsyncSession

from diagnose.domain.exceptions import (
    ConflictError,
    EntityNotFound,
)
from diagnose.domain.incidents import (
    IncidentSeverity,
    IncidentStatus,
    validate_incident_transition,
)
from diagnose.models.incident import Incident
from diagnose.models.incident_event import IncidentEvent
from diagnose.repositories.incident import IncidentRepository
from diagnose.repositories.service import ServiceRepository
from diagnose.repositories.user import UserRepository
from diagnose.schemas.incident import (
    IncidentAssign,
    IncidentCreate,
    IncidentTransition,
    IncidentUpdate,
)
from diagnose.services.audit import AuditService


class IncidentService:
    """Operations for Incident management with strict state-machine enforcement and audit atomicity."""

    def __init__(
        self,
        incident_repository: IncidentRepository | None = None,
        service_repository: ServiceRepository | None = None,
        user_repository: UserRepository | None = None,
        audit_service: AuditService | None = None,
    ) -> None:
        self.incident_repo = incident_repository or IncidentRepository()
        self.service_repo = service_repository or ServiceRepository()
        self.user_repo = user_repository or UserRepository()
        self.audit_service = audit_service or AuditService()

    async def create_incident(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        actor_user_id: uuid.UUID | None,
        data: IncidentCreate,
        correlation_id: str | None = None,
        ip_address: str | None = None,
    ) -> Incident:
        """Create a new incident with initial DETECTED status in an atomic transaction."""
        # 1. Validate service belongs to this tenant
        service = await self.service_repo.get_by_id(
            session, organization_id=organization_id, service_id=data.service_id
        )
        if service is None:
            raise EntityNotFound("Service", str(data.service_id))

        # 2. Validate assigned user belongs to this tenant if provided
        if data.assigned_user_id is not None:
            user = await self.user_repo.get_by_id(
                session,
                user_id=data.assigned_user_id,
                organization_id=organization_id,
            )
            if user is None:
                raise EntityNotFound("User", str(data.assigned_user_id))

        # 3. Calculate next incident number monotonically within tenant
        incident_number = await self.incident_repo.get_next_incident_number(
            session, organization_id=organization_id
        )

        now = datetime.now(timezone.utc)
        incident = Incident(
            organization_id=organization_id,
            service_id=data.service_id,
            incident_number=incident_number,
            title=data.title,
            description=data.description,
            severity=data.severity.value,
            status=IncidentStatus.DETECTED.value,
            assigned_user_id=data.assigned_user_id,
            detected_at=now,
            version=1,
        )
        await self.incident_repo.create_incident(session, incident)

        # 4. Append initial timeline event
        event = IncidentEvent(
            organization_id=organization_id,
            incident_id=incident.id,
            event_type="INCIDENT_CREATED",
            actor_user_id=actor_user_id,
            from_status=None,
            to_status=IncidentStatus.DETECTED.value,
            message="Incident created and marked DETECTED",
            event_metadata={
                "severity": incident.severity,
                "service_id": str(incident.service_id),
                "incident_number": incident.incident_number,
            },
            created_at=now,
        )
        await self.incident_repo.create_event(session, event)

        # 5. Record transactional audit entry
        await self.audit_service.record(
            session=session,
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            action="INCIDENT_CREATED",
            entity_type="incident",
            entity_id=incident.id,
            old_values=None,
            new_values={
                "incident_number": incident.incident_number,
                "title": incident.title,
                "severity": incident.severity,
                "status": incident.status,
                "service_id": str(incident.service_id),
            },
            correlation_id=correlation_id,
            ip_address=ip_address,
        )

        # 6. Commit single atomic transaction
        await session.commit()
        await session.refresh(incident)
        return incident

    async def get_incident(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        incident_id: uuid.UUID,
    ) -> Incident:
        """Fetch an incident scoped strictly to the caller's tenant."""
        incident = await self.incident_repo.get_by_id(
            session, organization_id=organization_id, incident_id=incident_id
        )
        if incident is None:
            raise EntityNotFound("Incident", str(incident_id))
        return incident

    async def list_incidents(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        status: IncidentStatus | None = None,
        severity: IncidentSeverity | None = None,
        service_id: uuid.UUID | None = None,
        assigned_user_id: uuid.UUID | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[Sequence[Incident], int]:
        """List and count tenant incidents with filtering and pagination."""
        offset = (page - 1) * page_size
        return await self.incident_repo.list_incidents(
            session=session,
            organization_id=organization_id,
            status=status.value if status else None,
            severity=severity.value if severity else None,
            service_id=service_id,
            assigned_user_id=assigned_user_id,
            offset=offset,
            limit=page_size,
        )

    async def update_incident(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        actor_user_id: uuid.UUID | None,
        incident_id: uuid.UUID,
        data: IncidentUpdate,
        correlation_id: str | None = None,
        ip_address: str | None = None,
    ) -> Incident:
        """Update incident metadata (excluding status).

        Raises ConflictError if incident is CLOSED.
        """
        incident = await self.incident_repo.get_by_id(
            session,
            organization_id=organization_id,
            incident_id=incident_id,
            for_update=True,
        )
        if incident is None:
            raise EntityNotFound("Incident", str(incident_id))

        if incident.status == IncidentStatus.CLOSED.value:
            raise ConflictError("Cannot modify a closed incident")

        old_values: dict[str, object] = {
            "title": incident.title,
            "description": incident.description,
            "severity": incident.severity,
            "service_id": str(incident.service_id),
        }

        if data.service_id is not None and data.service_id != incident.service_id:
            service = await self.service_repo.get_by_id(
                session, organization_id=organization_id, service_id=data.service_id
            )
            if service is None:
                raise EntityNotFound("Service", str(data.service_id))
            incident.service_id = data.service_id

        if data.title is not None:
            incident.title = data.title
        if data.description is not None:
            incident.description = data.description
        if data.severity is not None:
            incident.severity = data.severity.value

        incident.version += 1

        new_values: dict[str, object] = {
            "title": incident.title,
            "description": incident.description,
            "severity": incident.severity,
            "service_id": str(incident.service_id),
        }

        # Event
        event = IncidentEvent(
            organization_id=organization_id,
            incident_id=incident.id,
            event_type="INCIDENT_UPDATED",
            actor_user_id=actor_user_id,
            from_status=incident.status,
            to_status=incident.status,
            message="Incident metadata updated",
            event_metadata=new_values,
        )
        await self.incident_repo.create_event(session, event)

        # Audit
        await self.audit_service.record(
            session=session,
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            action="INCIDENT_UPDATED",
            entity_type="incident",
            entity_id=incident.id,
            old_values=old_values,
            new_values=new_values,
            correlation_id=correlation_id,
            ip_address=ip_address,
        )

        await session.commit()
        await session.refresh(incident)
        return incident

    async def transition_incident(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        actor_user_id: uuid.UUID | None,
        incident_id: uuid.UUID,
        data: IncidentTransition,
        correlation_id: str | None = None,
        ip_address: str | None = None,
    ) -> Incident:
        """Execute a deterministic state transition adhering to the domain state machine.

        Timestamp rules:
        - ACKNOWLEDGED: sets acknowledged_at if not set.
        - RESOLVED: sets resolved_at.
        - CLOSED: sets closed_at.
        - RESOLVED -> INVESTIGATING: clears resolved_at (incident actively re-opened).
          Historical resolution is preserved in IncidentEvent and AuditLog.
        """
        incident = await self.incident_repo.get_by_id(
            session,
            organization_id=organization_id,
            incident_id=incident_id,
            for_update=True,
        )
        if incident is None:
            raise EntityNotFound("Incident", str(incident_id))

        if incident.status == IncidentStatus.CLOSED.value:
            raise ConflictError("Closed incident cannot undergo further lifecycle transitions")

        current_status, target_status = validate_incident_transition(
            incident.status, data.target_status
        )

        now = datetime.now(timezone.utc)
        old_status = incident.status

        # Timestamp application rules
        if target_status == IncidentStatus.ACKNOWLEDGED:
            if incident.acknowledged_at is None:
                incident.acknowledged_at = now
        elif target_status == IncidentStatus.RESOLVED:
            incident.resolved_at = now
        elif target_status == IncidentStatus.CLOSED:
            incident.closed_at = now
        elif current_status == IncidentStatus.RESOLVED and target_status == IncidentStatus.INVESTIGATING:
            # Re-opening: clear current resolved_at so state is not contradictory.
            # Past resolution time remains documented in append-only timeline events.
            incident.resolved_at = None

        incident.status = target_status.value
        incident.version += 1

        # Timeline event
        event = IncidentEvent(
            organization_id=organization_id,
            incident_id=incident.id,
            event_type="STATUS_CHANGED",
            actor_user_id=actor_user_id,
            from_status=old_status,
            to_status=target_status.value,
            message=data.message or f"Status changed from {old_status} to {target_status.value}",
            event_metadata={"reason": data.message},
            created_at=now,
        )
        await self.incident_repo.create_event(session, event)

        # Audit entry
        await self.audit_service.record(
            session=session,
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            action="INCIDENT_STATUS_CHANGED",
            entity_type="incident",
            entity_id=incident.id,
            old_values={"status": old_status},
            new_values={"status": target_status.value},
            correlation_id=correlation_id,
            ip_address=ip_address,
        )

        await session.commit()
        await session.refresh(incident)
        return incident

    async def assign_incident(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        actor_user_id: uuid.UUID | None,
        incident_id: uuid.UUID,
        data: IncidentAssign,
        correlation_id: str | None = None,
        ip_address: str | None = None,
    ) -> Incident:
        """Assign or unassign an incident to a user within the tenant."""
        incident = await self.incident_repo.get_by_id(
            session,
            organization_id=organization_id,
            incident_id=incident_id,
            for_update=True,
        )
        if incident is None:
            raise EntityNotFound("Incident", str(incident_id))

        if incident.status == IncidentStatus.CLOSED.value:
            raise ConflictError("Cannot assign a closed incident")

        if data.assigned_user_id is not None:
            user = await self.user_repo.get_by_id(
                session,
                user_id=data.assigned_user_id,
                organization_id=organization_id,
            )
            if user is None:
                raise EntityNotFound("User", str(data.assigned_user_id))

        old_assignee = incident.assigned_user_id
        incident.assigned_user_id = data.assigned_user_id
        incident.version += 1

        # Event
        msg = (
            f"Assigned to user {data.assigned_user_id}"
            if data.assigned_user_id
            else "Incident unassigned"
        )
        event = IncidentEvent(
            organization_id=organization_id,
            incident_id=incident.id,
            event_type="INCIDENT_ASSIGNED",
            actor_user_id=actor_user_id,
            from_status=incident.status,
            to_status=incident.status,
            message=msg,
            event_metadata={
                "assigned_user_id": str(data.assigned_user_id) if data.assigned_user_id else None
            },
        )
        await self.incident_repo.create_event(session, event)

        # Audit
        await self.audit_service.record(
            session=session,
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            action="INCIDENT_ASSIGNED",
            entity_type="incident",
            entity_id=incident.id,
            old_values={"assigned_user_id": str(old_assignee) if old_assignee else None},
            new_values={
                "assigned_user_id": str(data.assigned_user_id) if data.assigned_user_id else None
            },
            correlation_id=correlation_id,
            ip_address=ip_address,
        )

        await session.commit()
        await session.refresh(incident)
        return incident

    async def list_events(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        incident_id: uuid.UUID,
    ) -> Sequence[IncidentEvent]:
        """Retrieve chronological timeline events for a tenant incident."""
        # Ensure incident belongs to tenant (raises 404 if not found)
        await self.get_incident(session, organization_id, incident_id)
        return await self.incident_repo.list_events(session, organization_id, incident_id)
