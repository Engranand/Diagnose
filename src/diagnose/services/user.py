"""User service — business logic and transactional mutation of user accounts."""

from __future__ import annotations

from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from diagnose.core.security import hash_password
from diagnose.domain.exceptions import (
    ConflictError,
    EntityNotFound,
    ValidationError,
)
from diagnose.models.user import User
from diagnose.repositories.user import UserRepository
from diagnose.schemas.user import (
    UserCreateRequest,
    UserMeUpdateRequest,
    UserUpdateRequest,
)
from diagnose.services.audit import AuditService


class UserService:
    """Operations for User management with strict tenant isolation and audit logging."""

    def __init__(
        self,
        repository: UserRepository | None = None,
        audit_service: AuditService | None = None,
    ) -> None:
        self.repository = repository or UserRepository()
        self.audit_service = audit_service or AuditService()

    async def get_by_id(
        self,
        session: AsyncSession,
        user_id: UUID,
        organization_id: UUID,
    ) -> User:
        """Fetch user within organization scope or raise EntityNotFound (404)."""
        user = await self.repository.get_by_id(
            session, user_id=user_id, organization_id=organization_id
        )
        if user is None:
            raise EntityNotFound("User", str(user_id))
        return user

    async def list_users(
        self,
        session: AsyncSession,
        organization_id: UUID,
    ) -> list[User]:
        """List all users within the caller's organization."""
        return await self.repository.list_by_organization(
            session, organization_id=organization_id
        )

    async def create_user(
        self,
        session: AsyncSession,
        organization_id: UUID,
        actor_user_id: UUID,
        create_data: UserCreateRequest,
        correlation_id: str | None = None,
    ) -> User:
        """Create a user strictly inside organization_id (ADMIN only)."""
        existing = await self.repository.get_by_email(
            session, email=create_data.email, organization_id=organization_id
        )
        if existing is not None:
            raise ConflictError(
                f"User with email '{create_data.email}' already exists in this organization."
            )

        hashed = hash_password(create_data.password)

        new_user = User(
            organization_id=organization_id,
            email=create_data.email,
            hashed_password=hashed,
            full_name=create_data.full_name,
            role=create_data.role.value,
            is_active=True,
        )

        user = await self.repository.create(session, new_user)

        # Record audit log without passwords or secrets
        await self.audit_service.record(
            session=session,
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            action="USER_CREATED",
            entity_type="USER",
            entity_id=user.id,
            new_values={
                "email": user.email,
                "role": user.role,
                "full_name": user.full_name,
            },
            correlation_id=correlation_id,
        )

        await session.commit()
        await session.refresh(user)
        return user

    async def update_user(
        self,
        session: AsyncSession,
        user_id: UUID,
        organization_id: UUID,
        actor_user_id: UUID,
        update_data: UserUpdateRequest,
        correlation_id: str | None = None,
    ) -> User:
        """Update another user (ADMIN only).

        Enforces:
        - Target user must belong to organization_id.
        - Actor cannot modify their own role.
        - Emits specific audit action: USER_ROLE_CHANGED, USER_DEACTIVATED, or USER_UPDATED.
        """
        user = await self.get_by_id(session, user_id, organization_id)

        # Do not allow users to modify their own role
        if actor_user_id == user_id and update_data.role is not None:
            if update_data.role.value != user.role:
                raise ValidationError("Users cannot modify their own role.")

        old_values: dict = {}
        new_values: dict = {}
        actions_to_record: list[str] = []

        if update_data.full_name is not None and update_data.full_name != user.full_name:
            old_values["full_name"] = user.full_name
            new_values["full_name"] = update_data.full_name
            user.full_name = update_data.full_name

        if update_data.role is not None and update_data.role.value != user.role:
            old_values["role"] = user.role
            new_values["role"] = update_data.role.value
            user.role = update_data.role.value
            actions_to_record.append("USER_ROLE_CHANGED")

        if update_data.is_active is not None and update_data.is_active != user.is_active:
            old_values["is_active"] = user.is_active
            new_values["is_active"] = update_data.is_active
            user.is_active = update_data.is_active
            if not update_data.is_active:
                actions_to_record.append("USER_DEACTIVATED")

        if not actions_to_record and new_values:
            actions_to_record.append("USER_UPDATED")

        if new_values:
            for action in actions_to_record:
                await self.audit_service.record(
                    session=session,
                    organization_id=organization_id,
                    actor_user_id=actor_user_id,
                    action=action,
                    entity_type="USER",
                    entity_id=user.id,
                    old_values=old_values,
                    new_values=new_values,
                    correlation_id=correlation_id,
                )
            await session.commit()
            await session.refresh(user)

        return user

    async def update_me(
        self,
        session: AsyncSession,
        user_id: UUID,
        organization_id: UUID,
        update_data: UserMeUpdateRequest,
        correlation_id: str | None = None,
    ) -> User:
        """Update self profile (full_name only; role/org immutable)."""
        user = await self.get_by_id(session, user_id, organization_id)

        if update_data.full_name is not None and update_data.full_name != user.full_name:
            old_val = user.full_name
            user.full_name = update_data.full_name
            await self.audit_service.record(
                session=session,
                organization_id=organization_id,
                actor_user_id=user_id,
                action="USER_UPDATED",
                entity_type="USER",
                entity_id=user.id,
                old_values={"full_name": old_val},
                new_values={"full_name": update_data.full_name},
                correlation_id=correlation_id,
            )
            await session.commit()
            await session.refresh(user)

        return user
