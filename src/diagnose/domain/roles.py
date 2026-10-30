"""Domain-level role and permission definitions.

Implements role-based access control (RBAC) rules.
Permissions are explicit and never scattered as raw strings.
"""

from __future__ import annotations

from enum import StrEnum


class Role(StrEnum):
    """User roles available in the platform."""

    ADMIN = "ADMIN"
    ENGINEER = "ENGINEER"
    RESPONDER = "RESPONDER"
    VIEWER = "VIEWER"


class Permission(StrEnum):
    """Fine-grained domain permissions."""

    MANAGE_ORGANIZATION = "manage:organization"
    MANAGE_USERS = "manage:users"
    CREATE_INCIDENT = "create:incident"
    TRANSITION_INCIDENT = "transition:incident"
    ASSIGN_INCIDENT = "assign:incident"
    CLOSE_INCIDENT = "close:incident"
    ADD_EVIDENCE = "add:evidence"
    MANAGE_SERVICES = "manage:services"
    VIEW_INCIDENTS = "view:incidents"
    VIEW_AUDIT_LOGS = "view:audit_logs"
    MANAGE_ALERTS = "manage:alerts"
    VIEW_ALERTS = "view:alerts"
    ASSOCIATE_ALERT = "associate:alert"
    VIEW_EVIDENCE = "view:evidence"
    VIEW_JOBS = "view:jobs"
    TRIGGER_JOB = "trigger:job"
    CREATE_INVESTIGATION = "create:investigation"
    EXECUTE_INVESTIGATION = "execute:investigation"
    VIEW_INVESTIGATIONS = "view:investigations"


ROLE_PERMISSIONS: dict[Role, set[Permission]] = {
    Role.ADMIN: {
        Permission.MANAGE_ORGANIZATION,
        Permission.MANAGE_USERS,
        Permission.CREATE_INCIDENT,
        Permission.TRANSITION_INCIDENT,
        Permission.ASSIGN_INCIDENT,
        Permission.CLOSE_INCIDENT,
        Permission.ADD_EVIDENCE,
        Permission.MANAGE_SERVICES,
        Permission.VIEW_INCIDENTS,
        Permission.VIEW_AUDIT_LOGS,
        Permission.MANAGE_ALERTS,
        Permission.VIEW_ALERTS,
        Permission.ASSOCIATE_ALERT,
        Permission.VIEW_EVIDENCE,
        Permission.VIEW_JOBS,
        Permission.TRIGGER_JOB,
        Permission.CREATE_INVESTIGATION,
        Permission.EXECUTE_INVESTIGATION,
        Permission.VIEW_INVESTIGATIONS,
    },
    Role.ENGINEER: {
        Permission.CREATE_INCIDENT,
        Permission.TRANSITION_INCIDENT,
        Permission.ASSIGN_INCIDENT,
        Permission.CLOSE_INCIDENT,
        Permission.ADD_EVIDENCE,
        Permission.MANAGE_SERVICES,
        Permission.VIEW_INCIDENTS,
        Permission.MANAGE_ALERTS,
        Permission.VIEW_ALERTS,
        Permission.ASSOCIATE_ALERT,
        Permission.VIEW_EVIDENCE,
        Permission.VIEW_JOBS,
        Permission.TRIGGER_JOB,
        Permission.CREATE_INVESTIGATION,
        Permission.EXECUTE_INVESTIGATION,
        Permission.VIEW_INVESTIGATIONS,
    },
    Role.RESPONDER: {
        Permission.CREATE_INCIDENT,
        Permission.TRANSITION_INCIDENT,
        Permission.ASSIGN_INCIDENT,
        Permission.CLOSE_INCIDENT,
        Permission.ADD_EVIDENCE,
        Permission.VIEW_INCIDENTS,
        Permission.VIEW_ALERTS,
        Permission.ASSOCIATE_ALERT,
        Permission.VIEW_EVIDENCE,
        Permission.VIEW_JOBS,
        Permission.CREATE_INVESTIGATION,
        Permission.EXECUTE_INVESTIGATION,
        Permission.VIEW_INVESTIGATIONS,
    },
    Role.VIEWER: {
        Permission.VIEW_INCIDENTS,
        Permission.VIEW_ALERTS,
        Permission.VIEW_EVIDENCE,
        Permission.VIEW_JOBS,
        Permission.VIEW_INVESTIGATIONS,
    },
}


def has_permission(role: Role | str, permission: Permission | str) -> bool:
    """Check if the given role has the requested permission."""
    try:
        r = Role(role) if isinstance(role, str) else role
        p = Permission(permission) if isinstance(permission, str) else permission
    except ValueError:
        return False
    return p in ROLE_PERMISSIONS.get(r, set())
