"""Repository for RemediationAction and ActionExecution data access (Milestone 10.1)."""

from __future__ import annotations

import uuid
from typing import Sequence

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from diagnose.models.remediation import ActionExecution, RemediationAction


class RemediationRepository:
    """Tenant-scoped repository for remediation actions and executions."""

    async def create_action(
        self, session: AsyncSession, action: RemediationAction
    ) -> RemediationAction:
        """Add a new remediation action to the active session."""
        session.add(action)
        await session.flush()
        return action

    async def get_action_by_id(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        action_id: uuid.UUID,
        for_update: bool = False,
    ) -> RemediationAction | None:
        """Retrieve a remediation action strictly scoped to an organization."""
        query = (
            select(RemediationAction)
            .where(
                RemediationAction.organization_id == organization_id,
                RemediationAction.id == action_id,
            )
            .options(selectinload(RemediationAction.executions))
            .execution_options(populate_existing=True)
        )
        if for_update:
            query = query.with_for_update()
        result = await session.execute(query)
        return result.scalar_one_or_none()

    async def list_actions_for_incident(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        incident_id: uuid.UUID,
        status: str | None = None,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[Sequence[RemediationAction], int]:
        """List and count remediation actions for an incident within a tenant."""
        base_query = select(RemediationAction).where(
            RemediationAction.organization_id == organization_id,
            RemediationAction.incident_id == incident_id,
        )
        if status is not None:
            base_query = base_query.where(RemediationAction.status == status)

        count_query = select(func.count()).select_from(base_query.subquery())
        total_result = await session.execute(count_query)
        total = int(total_result.scalar_one() or 0)

        query = (
            base_query.order_by(RemediationAction.created_at.desc())
            .offset(offset)
            .limit(limit)
        )
        result = await session.execute(query)
        return result.scalars().all(), total

    async def create_execution(
        self, session: AsyncSession, execution: ActionExecution
    ) -> ActionExecution:
        """Record an execution attempt in the active session."""
        session.add(execution)
        await session.flush()
        return execution

    async def list_executions_for_action(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        action_id: uuid.UUID,
    ) -> Sequence[ActionExecution]:
        """List all execution attempts for an action ordered by creation."""
        query = (
            select(ActionExecution)
            .where(
                ActionExecution.organization_id == organization_id,
                ActionExecution.action_id == action_id,
            )
            .order_by(ActionExecution.created_at.asc())
        )
        result = await session.execute(query)
        return result.scalars().all()

    async def get_execution_by_id(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        execution_id: uuid.UUID,
    ) -> ActionExecution | None:
        """Retrieve an execution attempt strictly scoped to an organization."""
        query = select(ActionExecution).where(
            ActionExecution.organization_id == organization_id,
            ActionExecution.id == execution_id,
        )
        result = await session.execute(query)
        return result.scalar_one_or_none()

    async def get_latest_execution_for_action(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        action_id: uuid.UUID,
    ) -> ActionExecution | None:
        """Retrieve the latest execution attempt for an action."""
        query = (
            select(ActionExecution)
            .where(
                ActionExecution.organization_id == organization_id,
                ActionExecution.action_id == action_id,
            )
            .order_by(ActionExecution.created_at.desc())
            .limit(1)
        )
        result = await session.execute(query)
        return result.scalar_one_or_none()

    async def get_successful_execution_for_action(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        action_id: uuid.UUID,
    ) -> ActionExecution | None:
        """Retrieve any existing successful execution for the action in EXECUTE mode."""
        query = (
            select(ActionExecution)
            .where(
                ActionExecution.organization_id == organization_id,
                ActionExecution.action_id == action_id,
                ActionExecution.execution_mode == "EXECUTE",
                ActionExecution.status == "SUCCEEDED",
            )
            .order_by(ActionExecution.created_at.desc())
            .limit(1)
        )
        result = await session.execute(query)
        return result.scalar_one_or_none()
