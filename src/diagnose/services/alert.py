"""Alert service — ingestion, idempotency, lifecycle, and incident association."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Sequence

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from diagnose.domain.alerts import AlertSeverity, AlertStatus, should_escalate_severity
from diagnose.domain.exceptions import ConflictError, EntityNotFound
from diagnose.models.alert import Alert
from diagnose.repositories.alert import AlertRepository
from diagnose.repositories.incident import IncidentRepository
from diagnose.repositories.service import ServiceRepository
from diagnose.schemas.alert import AlertCreate, AlertUpdate
from diagnose.services.audit import AuditService


class AlertService:
    """Operations for alert ingestion, deduplication, and incident association."""

    def __init__(
        self,
        alert_repository: AlertRepository | None = None,
        service_repository: ServiceRepository | None = None,
        incident_repository: IncidentRepository | None = None,
        audit_service: AuditService | None = None,
    ) -> None:
        self.alert_repo = alert_repository or AlertRepository()
        self.service_repo = service_repository or ServiceRepository()
        self.incident_repo = incident_repository or IncidentRepository()
        self.audit_service = audit_service or AuditService()

    async def ingest_alert(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        actor_user_id: uuid.UUID | None,
        data: AlertCreate,
        correlation_id: str | None = None,
        ip_address: str | None = None,
    ) -> tuple[Alert, bool]:
        """Idempotently ingest an alert signal within the tenant.

        - Active alert with status == 'FIRING' and same fingerprint:
          Deduplicates, updates last_seen_at and escalates severity, returning HTTP 200 (is_created=False).
        - No active alert (or prior alerts are RESOLVED/SUPPRESSED):
          Creates a new alert occurrence with HTTP 201 (is_created=True).

        Returns:
            tuple[Alert, bool]: The alert instance and a boolean indicating if it was newly created.
        """
        now = datetime.now(timezone.utc)

        # Check for active (FIRING) alert with identical fingerprint in this tenant
        existing = await self.alert_repo.get_by_fingerprint(
            session,
            organization_id=organization_id,
            fingerprint=data.fingerprint,
            status=AlertStatus.FIRING.value,
            for_update=True,
        )

        if existing is not None:
            # Case A: Active FIRING alert exists -> Idempotent deduplication
            old_values = {
                "last_seen_at": existing.last_seen_at.isoformat() if existing.last_seen_at else None,
                "severity": existing.severity,
                "title": existing.title,
                "status": existing.status,
            }
            existing.last_seen_at = now
            if data.message is not None:
                existing.message = data.message
            if data.payload is not None:
                existing.payload = data.payload
            if data.title is not None:
                existing.title = data.title
            if data.severity is not None and should_escalate_severity(existing.severity, data.severity):
                existing.severity = data.severity.value

            new_values = {
                "last_seen_at": existing.last_seen_at.isoformat(),
                "severity": existing.severity,
                "title": existing.title,
                "status": existing.status,
            }

            await self.audit_service.record(
                session=session,
                organization_id=organization_id,
                actor_user_id=actor_user_id,
                action="ALERT_UPDATED",
                entity_type="alert",
                entity_id=existing.id,
                old_values=old_values,
                new_values=new_values,
                correlation_id=correlation_id,
                ip_address=ip_address,
            )

            await session.commit()
            await session.refresh(existing)
            return existing, False

        # Case B & C: No active FIRING alert found (all previous occurrences are RESOLVED/SUPPRESSED, or none exist).
        # Validate service belongs to tenant
        service = await self.service_repo.get_by_id(
            session, organization_id=organization_id, service_id=data.service_id
        )
        if service is None:
            raise EntityNotFound("Service", str(data.service_id))

        # If incident_id provided, validate tenant & service match
        if data.incident_id is not None:
            incident = await self.incident_repo.get_by_id(
                session, organization_id=organization_id, incident_id=data.incident_id
            )
            if incident is None:
                raise EntityNotFound("Incident", str(data.incident_id))
            if incident.service_id != data.service_id:
                raise ConflictError(
                    f"Alert service '{data.service_id}' does not match incident service '{incident.service_id}'"
                )

        alert = Alert(
            organization_id=organization_id,
            service_id=data.service_id,
            incident_id=data.incident_id,
            fingerprint=data.fingerprint,
            source=data.source,
            alert_type=data.alert_type,
            title=data.title,
            message=data.message,
            severity=data.severity.value,
            status=AlertStatus.FIRING.value,
            payload=data.payload,
            first_seen_at=now,
            last_seen_at=now,
        )

        try:
            async with session.begin_nested():
                await self.alert_repo.create_alert(session, alert)
        except IntegrityError:
            # Concurrent race condition: another transaction created an active alert with this fingerprint.
            # Rollback to savepoint is automatic; retrieve the winner's active alert and deduplicate.
            concurrent_active = await self.alert_repo.get_by_fingerprint(
                session,
                organization_id=organization_id,
                fingerprint=data.fingerprint,
                status=AlertStatus.FIRING.value,
                for_update=True,
            )
            if concurrent_active is not None:
                old_values = {
                    "last_seen_at": concurrent_active.last_seen_at.isoformat() if concurrent_active.last_seen_at else None,
                    "severity": concurrent_active.severity,
                    "title": concurrent_active.title,
                    "status": concurrent_active.status,
                }
                concurrent_active.last_seen_at = now
                if data.message is not None:
                    concurrent_active.message = data.message
                if data.payload is not None:
                    concurrent_active.payload = data.payload
                if data.title is not None:
                    concurrent_active.title = data.title
                if data.severity is not None and should_escalate_severity(concurrent_active.severity, data.severity):
                    concurrent_active.severity = data.severity.value

                new_values = {
                    "last_seen_at": concurrent_active.last_seen_at.isoformat(),
                    "severity": concurrent_active.severity,
                    "title": concurrent_active.title,
                    "status": concurrent_active.status,
                }
                await self.audit_service.record(
                    session=session,
                    organization_id=organization_id,
                    actor_user_id=actor_user_id,
                    action="ALERT_UPDATED",
                    entity_type="alert",
                    entity_id=concurrent_active.id,
                    old_values=old_values,
                    new_values=new_values,
                    correlation_id=correlation_id,
                    ip_address=ip_address,
                )
                await session.commit()
                await session.refresh(concurrent_active)
                return concurrent_active, False
            raise

        await self.audit_service.record(
            session=session,
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            action="ALERT_CREATED",
            entity_type="alert",
            entity_id=alert.id,
            old_values=None,
            new_values={
                "fingerprint": alert.fingerprint,
                "title": alert.title,
                "severity": alert.severity,
                "status": alert.status,
                "service_id": str(alert.service_id),
                "incident_id": str(alert.incident_id) if alert.incident_id else None,
            },
            correlation_id=correlation_id,
            ip_address=ip_address,
        )

        await session.commit()
        await session.refresh(alert)
        return alert, True

    async def get_alert(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        alert_id: uuid.UUID,
    ) -> Alert:
        """Fetch alert scoped strictly to organization."""
        alert = await self.alert_repo.get_by_id(
            session, organization_id=organization_id, alert_id=alert_id
        )
        if alert is None:
            raise EntityNotFound("Alert", str(alert_id))
        return alert

    async def list_alerts(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        status: AlertStatus | None = None,
        severity: AlertSeverity | None = None,
        service_id: uuid.UUID | None = None,
        incident_id: uuid.UUID | None = None,
        source: str | None = None,
        fingerprint: str | None = None,
        created_from: datetime | None = None,
        created_to: datetime | None = None,
        search: str | None = None,
        sort_by: str = "created_at",
        sort_order: str = "desc",
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[Sequence[Alert], int]:
        """List alerts with tenant scoping, filtering, search, sorting, and pagination."""
        return await self.alert_repo.list_alerts(
            session=session,
            organization_id=organization_id,
            status=status.value if status else None,
            severity=severity.value if severity else None,
            service_id=service_id,
            incident_id=incident_id,
            source=source,
            fingerprint=fingerprint,
            created_from=created_from,
            created_to=created_to,
            search=search,
            sort_by=sort_by,
            sort_order=sort_order,
            offset=offset,
            limit=limit,
        )

    async def update_alert(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        actor_user_id: uuid.UUID | None,
        alert_id: uuid.UUID,
        data: AlertUpdate,
        correlation_id: str | None = None,
        ip_address: str | None = None,
    ) -> Alert:
        """Update operational alert metadata (status, severity, message, payload)."""
        alert = await self.alert_repo.get_by_id(
            session, organization_id=organization_id, alert_id=alert_id, for_update=True
        )
        if alert is None:
            raise EntityNotFound("Alert", str(alert_id))

        old_values = {
            "status": alert.status,
            "severity": alert.severity,
            "title": alert.title,
            "message": alert.message,
        }

        if data.status is not None:
            alert.status = data.status.value
            if data.status == AlertStatus.RESOLVED:
                alert.resolved_at = datetime.now(timezone.utc)
            elif data.status == AlertStatus.FIRING:
                alert.resolved_at = None
        if data.severity is not None:
            alert.severity = data.severity.value
        if data.title is not None:
            alert.title = data.title
        if data.message is not None:
            alert.message = data.message
        if data.payload is not None:
            alert.payload = data.payload

        new_values = {
            "status": alert.status,
            "severity": alert.severity,
            "title": alert.title,
            "message": alert.message,
        }

        await self.audit_service.record(
            session=session,
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            action="ALERT_UPDATED",
            entity_type="alert",
            entity_id=alert.id,
            old_values=old_values,
            new_values=new_values,
            correlation_id=correlation_id,
            ip_address=ip_address,
        )

        await session.commit()
        await session.refresh(alert)
        return alert

    async def associate_incident(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        actor_user_id: uuid.UUID | None,
        alert_id: uuid.UUID,
        incident_id: uuid.UUID,
        correlation_id: str | None = None,
        ip_address: str | None = None,
    ) -> Alert:
        """Associate an alert with an incident within the same tenant and service."""
        alert = await self.alert_repo.get_by_id(
            session, organization_id=organization_id, alert_id=alert_id, for_update=True
        )
        if alert is None:
            raise EntityNotFound("Alert", str(alert_id))

        incident = await self.incident_repo.get_by_id(
            session, organization_id=organization_id, incident_id=incident_id
        )
        if incident is None:
            raise EntityNotFound("Incident", str(incident_id))

        if alert.service_id != incident.service_id:
            raise ConflictError(
                f"Alert service '{alert.service_id}' does not match incident service '{incident.service_id}'"
            )

        old_incident_id = alert.incident_id
        alert.incident_id = incident.id

        await self.audit_service.record(
            session=session,
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            action="ALERT_ASSOCIATED_WITH_INCIDENT",
            entity_type="alert",
            entity_id=alert.id,
            old_values={"incident_id": str(old_incident_id) if old_incident_id else None},
            new_values={"incident_id": str(incident.id)},
            correlation_id=correlation_id,
            ip_address=ip_address,
        )

        await session.commit()
        await session.refresh(alert)
        return alert
