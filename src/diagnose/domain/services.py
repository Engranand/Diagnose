"""Service domain definitions and validation rules."""

from __future__ import annotations

import re
from enum import StrEnum

from diagnose.domain.exceptions import ValidationError

SLUG_REGEX = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


class ServiceTier(StrEnum):
    """Operational criticality tier for services."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


def validate_service_name(name: str) -> str:
    """Validate and sanitize service name."""
    if not isinstance(name, str):
        raise ValidationError("Service name must be a string")
    cleaned = name.strip()
    if not cleaned:
        raise ValidationError("Service name cannot be empty")
    if len(cleaned) > 255:
        raise ValidationError("Service name cannot exceed 255 characters")
    return cleaned


def validate_service_slug(slug: str) -> str:
    """Validate slug format."""
    if not isinstance(slug, str):
        raise ValidationError("Service slug must be a string")
    cleaned = slug.strip().lower()
    if not cleaned:
        raise ValidationError("Service slug cannot be empty")
    if len(cleaned) < 2 or len(cleaned) > 100:
        raise ValidationError("Service slug must be between 2 and 100 characters")
    if not SLUG_REGEX.match(cleaned):
        raise ValidationError(
            "Service slug must contain only lowercase alphanumeric characters and hyphens, "
            "and cannot start or end with a hyphen"
        )
    return cleaned


def validate_service_tier(tier: str | ServiceTier) -> ServiceTier:
    """Validate and normalize service tier."""
    if isinstance(tier, ServiceTier):
        return tier
    if not isinstance(tier, str):
        raise ValidationError("Service tier must be a string")
    try:
        return ServiceTier(tier.upper())
    except ValueError:
        valid_tiers = ", ".join(t.value for t in ServiceTier)
        raise ValidationError(
            f"Invalid service tier '{tier}'. Must be one of: {valid_tiers}"
        )
