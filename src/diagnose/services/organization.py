"""Organization service."""

from __future__ import annotations

from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from diagnose.domain.exceptions import ConflictError, EntityNotFound
from diagnose.models.organization import Organization
from diagnose.repositories.organization import OrganizationRepository
from diagnose.schemas.organization import OrganizationUpdateRequest
from diagnose.services.audit import AuditService


class OrganizationService:
    """Business operations on Organization entities."""

    def __init__(
        self,
        repository: OrganizationRepository | None = None,
        audit_service: AuditService | None = None,
    ) -> None:
        self.repository = repository or OrganizationRepository()
        self.audit_service = audit_service or AuditService()

    async def get_by_id(
        self, session: AsyncSession, org_id: UUID
    ) -> Organization:
        """Fetch organization or raise EntityNotFound."""
        org = await self.repository.get_by_id(session, org_id)
        if org is None:
            raise EntityNotFound("Organization", str(org_id))
        return org

    async def update_organization(
        self,
        session: AsyncSession,
        org_id: UUID,
        actor_user_id: UUID,
        update_data: OrganizationUpdateRequest,
        correlation_id: str | None = None,
    ) -> Organization:
        """Update organization details (ADMIN only) with atomic audit logging."""
        org = await self.get_by_id(session, org_id)

        old_values: dict = {}
        new_values: dict = {}

        if update_data.slug is not None and update_data.slug != org.slug:
            existing = await self.repository.get_by_slug(session, update_data.slug)
            if existing is not None and existing.id != org.id:
                raise ConflictError(
                    f"Organization with slug '{update_data.slug}' already exists."
                )
            old_values["slug"] = org.slug
            new_values["slug"] = update_data.slug
            org.slug = update_data.slug

        if update_data.name is not None and update_data.name != org.name:
            old_values["name"] = org.name
            new_values["name"] = update_data.name
            org.name = update_data.name

        if new_values:
            await self.audit_service.record(
                session=session,
                organization_id=org.id,
                actor_user_id=actor_user_id,
                action="ORGANIZATION_UPDATED",
                entity_type="ORGANIZATION",
                entity_id=org.id,
                old_values=old_values,
                new_values=new_values,
                correlation_id=correlation_id,
            )
            await session.commit()
            await session.refresh(org)

        return org
