"""Repository for Alert data access."""

from __future__ import annotations

import uuid
from typing import Sequence

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from diagnose.models.alert import Alert


class AlertRepository:
    """Tenant-scoped repository for alerts."""

    async def create_alert(self, session: AsyncSession, alert: Alert) -> Alert:
        """Add a new alert entity to the session."""
        session.add(alert)
        await session.flush()
        return alert

    async def get_by_id(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        alert_id: uuid.UUID,
        for_update: bool = False,
    ) -> Alert | None:
        """Retrieve an alert by ID strictly scoped to an organization."""
        query = select(Alert).where(
            Alert.organization_id == organization_id,
            Alert.id == alert_id,
        )
        if for_update:
            query = query.with_for_update()
        result = await session.execute(query)
        return result.scalar_one_or_none()

    async def get_by_fingerprint(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        fingerprint: str,
        for_update: bool = False,
    ) -> Alert | None:
        """Retrieve an alert by fingerprint strictly scoped to an organization."""
        query = select(Alert).where(
            Alert.organization_id == organization_id,
            Alert.fingerprint == fingerprint,
        )
        if for_update:
            query = query.with_for_update()
        result = await session.execute(query)
        return result.scalar_one_or_none()

    async def list_alerts(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        status: str | None = None,
        severity: str | None = None,
        service_id: uuid.UUID | None = None,
        incident_id: uuid.UUID | None = None,
        source: str | None = None,
        fingerprint: str | None = None,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[Sequence[Alert], int]:
        """List and count alerts for an organization with optional filtering and pagination."""
        base_query = select(Alert).where(Alert.organization_id == organization_id)

        if status is not None:
            base_query = base_query.where(Alert.status == status)
        if severity is not None:
            base_query = base_query.where(Alert.severity == severity)
        if service_id is not None:
            base_query = base_query.where(Alert.service_id == service_id)
        if incident_id is not None:
            base_query = base_query.where(Alert.incident_id == incident_id)
        if source is not None:
            base_query = base_query.where(Alert.source == source)
        if fingerprint is not None:
            base_query = base_query.where(Alert.fingerprint == fingerprint)

        count_query = select(func.count()).select_from(base_query.subquery())
        total = (await session.execute(count_query)).scalar_one()

        items_query = (
            base_query.order_by(Alert.last_seen_at.desc())
            .offset(offset)
            .limit(limit)
        )
        items = (await session.execute(items_query)).scalars().all()

        return items, total
