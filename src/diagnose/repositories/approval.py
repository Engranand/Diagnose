"""Repository for Action Approval records (Milestone 10.4)."""

from __future__ import annotations

import uuid
from typing import Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from diagnose.models.approval import ActionApproval


class ApprovalRepository:
    """Data-access layer for immutable action approvals."""

    async def create_approval(
        self,
        session: AsyncSession,
        approval: ActionApproval,
    ) -> ActionApproval:
        """Persist a new action approval or rejection record."""
        session.add(approval)
        await session.flush()
        return approval

    async def list_approvals_for_action(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        action_id: uuid.UUID,
    ) -> Sequence[ActionApproval]:
        """List all approval and rejection records for an action, ordered chronologically."""
        stmt = (
            select(ActionApproval)
            .where(
                ActionApproval.organization_id == organization_id,
                ActionApproval.action_id == action_id,
            )
            .order_by(ActionApproval.created_at.asc())
        )
        result = await session.execute(stmt)
        return result.scalars().all()

    async def get_approval_by_id(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        approval_id: uuid.UUID,
    ) -> ActionApproval | None:
        """Fetch a specific approval record scoped to an organization."""
        stmt = select(ActionApproval).where(
            ActionApproval.organization_id == organization_id,
            ActionApproval.id == approval_id,
        )
        result = await session.execute(stmt)
        return result.scalar_one_or_none()
