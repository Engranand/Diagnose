"""Domain-level exceptions.

These are raised by service and domain code and translated into HTTP
responses by the global exception handlers in
:mod:`diagnose.middleware.error_handler`.

Hierarchy::

    DomainException
    ├── AuthenticationError     → 401
    ├── EntityNotFound          → 404
    ├── InvalidStateTransition  → 409
    ├── AuthorizationError      → 403
    ├── ConflictError           → 409
    └── ValidationError         → 422
"""

from __future__ import annotations


class DomainException(Exception):
    """Base exception for all domain errors."""


class AuthenticationError(DomainException):
    """Raised when authentication credentials or token are invalid or missing."""

    def __init__(self, message: str = "Invalid authentication credentials.") -> None:
        super().__init__(message)


class EntityNotFound(DomainException):
    """Raised when a requested entity does not exist (or is not visible)."""

    def __init__(self, entity_type: str, entity_id: str | None = None) -> None:
        self.entity_type = entity_type
        self.entity_id = entity_id
        msg = f"{entity_type} not found"
        if entity_id:
            msg = f"{entity_type} with id '{entity_id}' not found"
        super().__init__(msg)


# Convenient alias
NotFoundError = EntityNotFound


class InvalidStateTransition(DomainException):
    """Raised when an entity state-machine transition is not allowed."""

    def __init__(
        self, entity_type: str, current_state: str, target_state: str
    ) -> None:
        self.entity_type = entity_type
        self.current_state = current_state
        self.target_state = target_state
        super().__init__(
            f"Invalid state transition for {entity_type}: "
            f"'{current_state}' → '{target_state}'"
        )


class AuthorizationError(DomainException):
    """Raised when the caller lacks permission for an operation."""

    def __init__(
        self,
        message: str = "You do not have permission to perform this action.",
    ) -> None:
        super().__init__(message)


class ConflictError(DomainException):
    """Raised on uniqueness violations or optimistic-locking conflicts."""

    def __init__(self, message: str) -> None:
        super().__init__(message)


class ValidationError(DomainException):
    """Raised when domain-level validation fails (beyond Pydantic parsing)."""

    def __init__(self, message: str) -> None:
        super().__init__(message)


class PolicyViolationError(DomainException):
    """Raised when an operation violates a remediation governance policy."""

    def __init__(self, message: str = "Operation prohibited by remediation governance policy.") -> None:
        super().__init__(message)


class ActionNotExecutableError(DomainException):
    """Raised when an action is not in an executable lifecycle state."""

    def __init__(self, message: str = "Action is not in an executable lifecycle state.") -> None:
        super().__init__(message)


class ExecutionValidationError(ValidationError):
    """Raised when remediation execution validation fails."""

    def __init__(self, message: str = "Execution validation failed.") -> None:
        super().__init__(message)


class SeparationOfDutiesError(AuthorizationError):
    """Raised when the proposer of an action attempts to approve it."""

    def __init__(
        self,
        message: str = "Separation of duties violation: action proposer cannot approve their own action.",
    ) -> None:
        super().__init__(message)


class DryRunHashMismatchError(ValidationError):
    """Raised when the provided dry run plan hash does not match the actual execution plan hash."""

    def __init__(
        self,
        message: str = "Dry run plan hash mismatch: action execution plan has changed or does not match approval target.",
    ) -> None:
        super().__init__(message)


class ExecutionPreconditionError(DomainException):
    """Raised when one or more execution preconditions fail before entering execution."""

    def __init__(self, message: str = "Execution preconditions not satisfied.") -> None:
        super().__init__(message)


class UnsupportedExecutorError(DomainException):
    """Raised when an unknown or unregistered executor type is requested."""

    def __init__(self, message: str = "Unsupported or unregistered executor type.") -> None:
        super().__init__(message)
