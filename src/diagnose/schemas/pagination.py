"""Reusable pagination schemas and request dependencies."""

from __future__ import annotations

import math
from typing import Generic, TypeVar

from fastapi import Query
from pydantic import BaseModel, Field

from diagnose.domain.exceptions import ValidationError

T = TypeVar("T")


class PaginationParams:
    """Common query parameter parser for limit/offset and page/page_size pagination."""

    def __init__(
        self,
        limit: int | None = Query(
            default=None,
            ge=1,
            le=100,
            description="Maximum number of items to return (max 100)",
        ),
        offset: int | None = Query(
            default=None,
            ge=0,
            description="Number of items to skip (min 0)",
        ),
        page: int | None = Query(
            default=None,
            ge=1,
            description="Page number (1-indexed)",
        ),
        page_size: int | None = Query(
            default=None,
            ge=1,
            le=100,
            description="Number of items per page (max 100)",
        ),
    ) -> None:
        has_offset_mode = limit is not None or offset is not None
        has_page_mode = page is not None or page_size is not None

        if has_offset_mode and has_page_mode:
            raise ValidationError(
                "Mixed pagination parameters: choose either (limit, offset) or (page, page_size), not both."
            )

        if has_page_mode:
            self.page_size = page_size if page_size is not None else 50
            self.page = page if page is not None else 1
            self.limit = self.page_size
            self.offset = (self.page - 1) * self.page_size
        else:
            self.limit = limit if limit is not None else 50
            self.offset = offset if offset is not None else 0
            self.page = (self.offset // self.limit) + 1
            self.page_size = self.limit

    def calculate_pages(self, total: int) -> int:
        """Compute the total number of pages for a given item count."""
        return math.ceil(total / self.limit) if total > 0 else 1


class PaginatedResponse(BaseModel, Generic[T]):
    """Standard generic envelope for paginated collections."""

    items: list[T]
    total: int = Field(ge=0, description="Total matching items across all pages")
    page: int = Field(ge=1, description="Current page number")
    page_size: int = Field(ge=1, le=100, description="Requested page size")
    pages: int = Field(ge=1, description="Total available pages")
