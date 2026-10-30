"""Service layer for Service catalog operations and audit logging."""

from __future__ import annotations

import uuid
from typing import Sequence

from sqlalchemy.ext.asyncio import AsyncSession

from diagnose.domain.exceptions import ConflictError, EntityNotFound
from diagnose.domain.services import (
    validate_service_name,
    validate_service_slug,
    validate_service_tier,
)
from diagnose.models.service import Service
from diagnose.repositories.service import ServiceRepository
from diagnose.schemas.service import ServiceCreate, ServiceUpdate
from diagnose.services.audit import AuditService


class ServiceService:
    """Manages service catalog lifecycle, validation, and audit recording."""

    def __init__(
        self,
        service_repository: ServiceRepository | None = None,
        audit_service: AuditService | None = None,
    ) -> None:
        self.repository = service_repository or ServiceRepository()
        self.audit = audit_service or AuditService()

    async def create_service(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        actor_user_id: uuid.UUID | None,
        data: ServiceCreate,
        correlation_id: str | None = None,
        ip_address: str | None = None,
    ) -> Service:
        """Create a new service in the specified organization."""
        validated_name = validate_service_name(data.name)
        validated_slug = validate_service_slug(data.slug)
        validated_tier = validate_service_tier(data.tier)

        existing = await self.repository.get_by_slug(session, organization_id, validated_slug)
        if existing:
            raise ConflictError(
                f"Service with slug '{validated_slug}' already exists in this organization"
            )

        service = Service(
            organization_id=organization_id,
            name=validated_name,
            slug=validated_slug,
            description=data.description,
            tier=validated_tier.value,
            is_active=True,
        )
        created_service = await self.repository.create(session, service)

        await self.audit.record(
            session=session,
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            action="SERVICE_CREATED",
            entity_type="service",
            entity_id=created_service.id,
            old_values=None,
            new_values={
                "name": created_service.name,
                "slug": created_service.slug,
                "description": created_service.description,
                "tier": created_service.tier,
                "is_active": created_service.is_active,
            },
            correlation_id=correlation_id,
            ip_address=ip_address,
        )

        await session.commit()
        await session.refresh(created_service)

        return created_service

    async def get_service(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        service_id: uuid.UUID,
    ) -> Service:
        """Retrieve a service by ID within the organization."""
        service = await self.repository.get_by_id(session, organization_id, service_id)
        if not service:
            raise EntityNotFound("Service", str(service_id))
        return service

    async def list_services(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        is_active: bool | None = None,
        tier: str | None = None,
    ) -> Sequence[Service]:
        """List all services for an organization."""
        validated_tier = None
        if tier is not None:
            validated_tier = validate_service_tier(tier).value
        return await self.repository.list_by_organization(
            session, organization_id, is_active=is_active, tier=validated_tier
        )

    async def update_service(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        actor_user_id: uuid.UUID | None,
        service_id: uuid.UUID,
        data: ServiceUpdate,
        correlation_id: str | None = None,
        ip_address: str | None = None,
    ) -> Service:
        """Update an existing service, recording audit logs."""
        service = await self.get_service(session, organization_id, service_id)

        old_values: dict[str, object] = {
            "name": service.name,
            "description": service.description,
            "tier": service.tier,
            "is_active": service.is_active,
        }

        action = "SERVICE_UPDATED"

        if data.name is not None:
            service.name = validate_service_name(data.name)
        if data.description is not None:
            service.description = data.description
        if data.tier is not None:
            service.tier = validate_service_tier(data.tier).value
        if data.is_active is not None:
            if service.is_active and not data.is_active:
                action = "SERVICE_DEACTIVATED"
            service.is_active = data.is_active

        new_values: dict[str, object] = {
            "name": service.name,
            "description": service.description,
            "tier": service.tier,
            "is_active": service.is_active,
        }

        await session.flush()

        await self.audit.record(
            session=session,
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            action=action,
            entity_type="service",
            entity_id=service.id,
            old_values=old_values,
            new_values=new_values,
            correlation_id=correlation_id,
            ip_address=ip_address,
        )

        await session.commit()
        await session.refresh(service)

        return service
