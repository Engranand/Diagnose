"""Evidence service — immutable artifact ingestion, deduplication, and retrieval."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Sequence

from sqlalchemy.ext.asyncio import AsyncSession

from diagnose.domain.evidence import EvidenceType, compute_evidence_hash
from diagnose.domain.exceptions import ConflictError, EntityNotFound
from diagnose.models.evidence import Evidence
from diagnose.repositories.evidence import EvidenceRepository
from diagnose.repositories.incident import IncidentRepository
from diagnose.schemas.evidence import EvidenceCreate
from diagnose.services.audit import AuditService


class EvidenceService:
    """Operations for immutable evidence artifact collection and verification."""

    def __init__(
        self,
        evidence_repository: EvidenceRepository | None = None,
        incident_repository: IncidentRepository | None = None,
        audit_service: AuditService | None = None,
    ) -> None:
        self.evidence_repo = evidence_repository or EvidenceRepository()
        self.incident_repo = incident_repository or IncidentRepository()
        self.audit_service = audit_service or AuditService()

    async def create_evidence(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        incident_id: uuid.UUID,
        actor_user_id: uuid.UUID | None,
        data: EvidenceCreate,
        correlation_id: str | None = None,
        ip_address: str | None = None,
    ) -> Evidence:
        """Create an immutable evidence artifact for an incident within the tenant."""
        # 1. Validate incident exists in this tenant
        incident = await self.incident_repo.get_by_id(
            session, organization_id=organization_id, incident_id=incident_id
        )
        if incident is None:
            raise EntityNotFound("Incident", str(incident_id))

        # 2. Compute canonical server-side evidence hash
        evidence_hash = compute_evidence_hash(
            incident_id=incident_id,
            evidence_type=data.evidence_type,
            source=data.source,
            content=data.content,
            structured_data=data.structured_data,
            observed_at=data.observed_at,
        )

        # 3. Check for duplicates in tenant
        existing = await self.evidence_repo.get_by_hash(
            session, organization_id=organization_id, evidence_hash=evidence_hash
        )
        if existing is not None:
            raise ConflictError("Duplicate evidence artifact already ingested for this incident.")

        now = datetime.now(timezone.utc)
        evidence = Evidence(
            organization_id=organization_id,
            incident_id=incident_id,
            evidence_type=data.evidence_type.value,
            source=data.source,
            title=data.title,
            content=data.content,
            structured_data=data.structured_data,
            observed_at=data.observed_at,
            collected_at=now,
            collected_by_user_id=actor_user_id,
            reliability=data.reliability.value,
            evidence_metadata=data.metadata,
            evidence_hash=evidence_hash,
            created_at=now,
        )
        await self.evidence_repo.create_evidence(session, evidence)

        # 4. Record audit entry (without dumping large raw content)
        await self.audit_service.record(
            session=session,
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            action="EVIDENCE_CREATED",
            entity_type="evidence",
            entity_id=evidence.id,
            old_values=None,
            new_values={
                "incident_id": str(incident_id),
                "evidence_type": evidence.evidence_type,
                "source": evidence.source,
                "title": evidence.title,
                "evidence_hash": evidence_hash,
                "reliability": evidence.reliability,
            },
            correlation_id=correlation_id,
            ip_address=ip_address,
        )

        await session.commit()
        await session.refresh(evidence)
        return evidence

    async def get_evidence(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        evidence_id: uuid.UUID,
    ) -> Evidence:
        """Retrieve an evidence artifact scoped strictly to organization."""
        evidence = await self.evidence_repo.get_by_id(
            session, organization_id=organization_id, evidence_id=evidence_id
        )
        if evidence is None:
            raise EntityNotFound("Evidence", str(evidence_id))
        return evidence

    async def list_by_incident(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        incident_id: uuid.UUID,
        evidence_type: EvidenceType | None = None,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[Sequence[Evidence], int]:
        """List and count evidence items for an incident within the tenant."""
        # Ensure incident exists in tenant
        incident = await self.incident_repo.get_by_id(
            session, organization_id=organization_id, incident_id=incident_id
        )
        if incident is None:
            raise EntityNotFound("Incident", str(incident_id))

        offset = (page - 1) * page_size
        return await self.evidence_repo.list_by_incident(
            session=session,
            organization_id=organization_id,
            incident_id=incident_id,
            evidence_type=evidence_type.value if evidence_type else None,
            offset=offset,
            limit=page_size,
        )
