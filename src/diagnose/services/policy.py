"""Service layer for Remediation Policy management and deterministic policy evaluation (Milestone 10.2)."""

from __future__ import annotations

import uuid
from typing import Sequence

from sqlalchemy.ext.asyncio import AsyncSession

from diagnose.domain.exceptions import EntityNotFound
from diagnose.domain.policy import (
    PolicyEvaluationContext,
    evaluate_policies_deterministically,
)
from diagnose.models.policy import PolicyEvaluation, RemediationPolicy
from diagnose.repositories.organization import OrganizationRepository
from diagnose.repositories.policy import PolicyRepository
from diagnose.repositories.service import ServiceRepository
from diagnose.schemas.policy import PolicyCreateRequest, PolicyUpdateRequest
from diagnose.services.audit import AuditService


class PolicyService:
    """Operations for Policy management, revision bumping, and point-in-time evaluation."""

    def __init__(
        self,
        policy_repo: PolicyRepository | None = None,
        org_repo: OrganizationRepository | None = None,
        service_repo: ServiceRepository | None = None,
        audit_service: AuditService | None = None,
    ) -> None:
        self.policy_repo = policy_repo or PolicyRepository()
        self.org_repo = org_repo or OrganizationRepository()
        self.service_repo = service_repo or ServiceRepository()
        self.audit_service = audit_service or AuditService()

    async def create_policy(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        data: PolicyCreateRequest,
        actor_user_id: uuid.UUID | None,
        correlation_id: str | None = None,
    ) -> RemediationPolicy:
        """Create a new policy within the tenant, atomically bumping policy_set_version."""
        org = await self.policy_repo.lock_organization(session, organization_id)
        if org is None:
            raise EntityNotFound("Organization", str(organization_id))

        if data.service_id is not None:
            service = await self.service_repo.get_by_id(session, organization_id, data.service_id)
            if service is None:
                raise EntityNotFound("Service", str(data.service_id))

        policy = RemediationPolicy(
            organization_id=organization_id,
            name=data.name,
            description=data.description,
            service_id=data.service_id,
            service_tier=data.service_tier,
            action_type=data.action_type.value if data.action_type else None,
            risk_level=data.risk_level.value if data.risk_level else None,
            execution_mode=data.execution_mode.value if data.execution_mode else None,
            environment=data.environment,
            actor_role=data.actor_role.value if data.actor_role else None,
            decision=data.decision.value,
            priority=data.priority,
            is_active=data.is_active,
            version=1,
        )

        new_set_version = await self.policy_repo.increment_policy_set_version(
            session, organization_id
        )
        await self.policy_repo.create_policy(session, policy)

        await self.audit_service.record(
            session=session,
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            action="POLICY_CREATED",
            entity_type="RemediationPolicy",
            entity_id=policy.id,
            new_values={
                "name": policy.name,
                "decision": policy.decision,
                "priority": policy.priority,
                "policy_version": policy.version,
                "policy_set_version": new_set_version,
            },
            correlation_id=correlation_id,
        )
        await session.commit()
        await session.refresh(policy)
        return policy

    async def update_policy(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        policy_id: uuid.UUID,
        data: PolicyUpdateRequest,
        actor_user_id: uuid.UUID | None,
        correlation_id: str | None = None,
    ) -> RemediationPolicy:
        """Update policy parameters or toggle is_active, bumping policy version and policy_set_version."""
        org = await self.policy_repo.lock_organization(session, organization_id)
        if org is None:
            raise EntityNotFound("Organization", str(organization_id))

        policy = await self.policy_repo.get_policy_by_id(
            session, organization_id, policy_id, for_update=True
        )
        if policy is None:
            raise EntityNotFound("RemediationPolicy", str(policy_id))

        if data.service_id is not None:
            service = await self.service_repo.get_by_id(session, organization_id, data.service_id)
            if service is None:
                raise EntityNotFound("Service", str(data.service_id))

        old_active = policy.is_active
        old_decision = policy.decision
        old_priority = policy.priority

        if data.name is not None:
            policy.name = data.name
        if data.description is not None:
            policy.description = data.description
        if data.service_id is not None:
            policy.service_id = data.service_id
        if data.service_tier is not None:
            policy.service_tier = data.service_tier
        if data.action_type is not None:
            policy.action_type = data.action_type.value
        if data.risk_level is not None:
            policy.risk_level = data.risk_level.value
        if data.execution_mode is not None:
            policy.execution_mode = data.execution_mode.value
        if data.environment is not None:
            policy.environment = data.environment
        if data.actor_role is not None:
            policy.actor_role = data.actor_role.value
        if data.decision is not None:
            policy.decision = data.decision.value
        if data.priority is not None:
            policy.priority = data.priority
        if data.is_active is not None:
            policy.is_active = data.is_active

        policy.version += 1
        new_set_version = await self.policy_repo.increment_policy_set_version(
            session, organization_id
        )

        audit_action = "POLICY_UPDATED"
        if data.is_active is not None and data.is_active != old_active:
            audit_action = "POLICY_ACTIVATED" if data.is_active else "POLICY_DEACTIVATED"

        await self.audit_service.record(
            session=session,
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            action=audit_action,
            entity_type="RemediationPolicy",
            entity_id=policy.id,
            old_values={
                "is_active": old_active,
                "decision": old_decision,
                "priority": old_priority,
            },
            new_values={
                "is_active": policy.is_active,
                "decision": policy.decision,
                "priority": policy.priority,
                "policy_version": policy.version,
                "policy_set_version": new_set_version,
            },
            correlation_id=correlation_id,
        )
        await session.commit()
        await session.refresh(policy)
        return policy

    async def get_policy(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        policy_id: uuid.UUID,
    ) -> RemediationPolicy:
        """Fetch a policy strictly within the organization."""
        policy = await self.policy_repo.get_policy_by_id(session, organization_id, policy_id)
        if policy is None:
            raise EntityNotFound("RemediationPolicy", str(policy_id))
        return policy

    async def list_policies(
        self,
        session: AsyncSession,
        organization_id: uuid.UUID,
        is_active: bool | None = None,
        action_type: str | None = None,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[Sequence[RemediationPolicy], int]:
        """List and count policies for the organization."""
        return await self.policy_repo.list_policies(
            session=session,
            organization_id=organization_id,
            is_active=is_active,
            action_type=action_type,
            offset=offset,
            limit=limit,
        )

    async def evaluate_context_and_persist(
        self,
        session: AsyncSession,
        context: PolicyEvaluationContext,
        action_id: uuid.UUID | None = None,
        actor_user_id: uuid.UUID | None = None,
    ) -> PolicyEvaluation:
        """Run deterministic evaluation against current active policies and persist evaluation record."""
        org = await self.org_repo.get_by_id(session, context.organization_id)
        if org is None:
            raise EntityNotFound("Organization", str(context.organization_id))

        current_set_version = org.policy_set_version
        active_policies = await self.policy_repo.list_active_policies_for_evaluation(
            session, context.organization_id
        )

        res = evaluate_policies_deterministically(context, active_policies)

        evaluation = PolicyEvaluation(
            organization_id=context.organization_id,
            action_id=action_id,
            policy_id=res.winning_policy_id,
            policy_version=res.winning_policy_version,
            policy_set_version=current_set_version,
            decision=res.decision.value,
            context_hash=res.context_hash,
            context_snapshot=res.context_snapshot,
            winning_policy_snapshot=res.winning_policy_snapshot,
            all_matched_policies=res.all_matched_policies,
            reasons=res.reasons,
            evaluated_by=actor_user_id,
        )
        await self.policy_repo.create_evaluation(session, evaluation)
        return evaluation
