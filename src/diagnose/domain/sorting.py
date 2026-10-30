"""Sorting allowlists and date-range validation utilities for query safety."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from sqlalchemy import UnaryExpression
from sqlalchemy.orm import InstrumentedAttribute

from diagnose.domain.exceptions import ValidationError


class SortOrder(StrEnum):
    """Allowed sort directions."""

    ASC = "asc"
    DESC = "desc"


def validate_sort_field(
    sort_by: str | None,
    allowed_columns: dict[str, InstrumentedAttribute[Any]],
    default_field: str,
    sort_order: str = "desc",
    tie_breaker_column: InstrumentedAttribute[Any] | None = None,
) -> list[UnaryExpression[Any] | InstrumentedAttribute[Any]]:
    """Validate and build an explicit, SQL-injection safe SQLAlchemy ORDER BY clause.

    Raises:
        ValidationError (HTTP 422) if sort_by or sort_order is not allowed.
    """
    effective_field = sort_by or default_field
    if effective_field not in allowed_columns:
        allowed = sorted(list(allowed_columns.keys()))
        raise ValidationError(
            f"Invalid sort field '{effective_field}'. Supported fields: {allowed}"
        )

    order_str = sort_order.lower()
    if order_str not in ("asc", "desc"):
        raise ValidationError(
            f"Invalid sort order '{sort_order}'. Supported orders: ['asc', 'desc']"
        )

    col = allowed_columns[effective_field]
    clauses: list[UnaryExpression[Any] | InstrumentedAttribute[Any]] = [
        col.asc() if order_str == "asc" else col.desc()
    ]

    # Deterministic tie-breaker
    if tie_breaker_column is not None and tie_breaker_column is not col:
        clauses.append(tie_breaker_column.asc())

    return clauses


def ensure_timezone_aware(dt: datetime | None) -> datetime | None:
    """Ensure a timestamp has a timezone attached (assumes UTC if naive)."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def validate_date_range(
    from_dt: datetime | None,
    to_dt: datetime | None,
    from_name: str = "created_from",
    to_name: str = "created_to",
) -> tuple[datetime | None, datetime | None]:
    """Validate that from_dt <= to_dt with timezone awareness.

    Raises:
        ValidationError (HTTP 422) if from_dt > to_dt.
    """
    tz_from = ensure_timezone_aware(from_dt)
    tz_to = ensure_timezone_aware(to_dt)

    if tz_from is not None and tz_to is not None and tz_from > tz_to:
        raise ValidationError(
            f"Invalid date range: {from_name} ({tz_from.isoformat()}) "
            f"cannot be greater than {to_name} ({tz_to.isoformat()})"
        )

    return tz_from, tz_to
