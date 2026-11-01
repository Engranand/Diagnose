"""Repository for RemediationPolicy and PolicyEvaluation data access (Milestone 10.2)."""

from __future__ import annotations

import uuid
from typing import Sequence

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from diagnose.models.organization import Organization
from diagnose.models.policy import PolicyEvaluation, RemediationPolicy


class PolicyRepository:
    """Tenant-scoped repository for policies, evaluations, and organization revision locking."""

    async def lock_organization(
        self, session: AsyncSession, organization_id: uuid.UUID
    ) -> Organization | None:
        """Pessimistically lock organization row for update to serialize policy mutations and approvals."""
        query = (
            select(Organization)
            .where(Organization.id == organization_id)
            .with_for_update()
        )
        result = await session.execute(query)
        return result.scalar_one_or_none()

    async def increment_policy_set_version(
        self, session: AsyncSession, organization_id: uuid.UUID
    ) -> int:
        """Atomically increment and return the organization's policy_set_version."""
        stmt = (
            update(Organization)
            .where(Organization.id == organization_id)
            .values(
                policy_set_version=Organization.policy_set_version + 1,
                updated_at=func.now(),
            )
            .returning(Organization.policy_set_version)
        )
        result = await session.execute(stmt)
        return int(result.scalar_one())

    async def create_policy(
        self, session: AsyncSession, policy: RemediationPolicy
    ) -> RemediationPolicy:
        """Persist a new policy in the session."""
        session.add(policy)
        await session.flush()
        return policy

    async def get_policy_by_id(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        policy_id: uuid.UUID,
        for_update: bool = False,
    ) -> RemediationPolicy | None:
        """Retrieve a policy strictly scoped to an organization."""
        query = select(RemediationPolicy).where(
            RemediationPolicy.organization_id == organization_id,
            RemediationPolicy.id == policy_id,
        )
        if for_update:
            query = query.with_for_update()
        result = await session.execute(query)
        return result.scalar_one_or_none()

    async def list_active_policies_for_evaluation(
        self, session: AsyncSession, organization_id: uuid.UUID
    ) -> Sequence[RemediationPolicy]:
        """Fetch all currently active policies for an organization."""
        query = (
            select(RemediationPolicy)
            .where(
                RemediationPolicy.organization_id == organization_id,
                RemediationPolicy.is_active == True,  # noqa: E712
            )
            .order_by(RemediationPolicy.priority.asc(), RemediationPolicy.created_at.asc())
        )
        result = await session.execute(query)
        return result.scalars().all()

    async def list_policies(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        is_active: bool | None = None,
        action_type: str | None = None,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[Sequence[RemediationPolicy], int]:
        """List and count policies for an organization with optional filtering."""
        base_query = select(RemediationPolicy).where(
            RemediationPolicy.organization_id == organization_id
        )
        if is_active is not None:
            base_query = base_query.where(RemediationPolicy.is_active == is_active)
        if action_type is not None:
            base_query = base_query.where(RemediationPolicy.action_type == action_type)

        count_query = select(func.count()).select_from(base_query.subquery())
        total = int((await session.execute(count_query)).scalar_one() or 0)

        query = (
            base_query.order_by(RemediationPolicy.priority.asc(), RemediationPolicy.created_at.asc())
            .offset(offset)
            .limit(limit)
        )
        result = await session.execute(query)
        return result.scalars().all(), total

    async def create_evaluation(
        self, session: AsyncSession, evaluation: PolicyEvaluation
    ) -> PolicyEvaluation:
        """Persist a policy evaluation record in the session."""
        session.add(evaluation)
        await session.flush()
        return evaluation

    async def get_latest_evaluation_for_action(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        action_id: uuid.UUID,
    ) -> PolicyEvaluation | None:
        """Retrieve the most recent policy evaluation for a specific action."""
        query = (
            select(PolicyEvaluation)
            .where(
                PolicyEvaluation.organization_id == organization_id,
                PolicyEvaluation.action_id == action_id,
            )
            .order_by(PolicyEvaluation.created_at.desc())
            .limit(1)
        )
        result = await session.execute(query)
        return result.scalar_one_or_none()

    async def get_evaluation_by_id(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        evaluation_id: uuid.UUID,
    ) -> PolicyEvaluation | None:
        """Retrieve an evaluation record by ID strictly scoped to an organization."""
        query = select(PolicyEvaluation).where(
            PolicyEvaluation.organization_id == organization_id,
            PolicyEvaluation.id == evaluation_id,
        )
        result = await session.execute(query)
        return result.scalar_one_or_none()
