"""Domain definitions, enums, limits, and exceptions for LLM Investigation (Milestone 9)."""

from __future__ import annotations

from enum import StrEnum
from typing import Final

from diagnose.domain.exceptions import DomainException, ValidationError


class AnalysisStatus(StrEnum):
    """Lifecycle status of an LLM investigation analysis."""

    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


# ── PROMPT VERSIONING ────────────────────────────────────────────────────────
PROMPT_VERSION: Final[str] = "m9-v1"

# ── OUTPUT LIMITS ────────────────────────────────────────────────────────────
MAX_SUMMARY_LENGTH: Final[int] = 5000
MAX_REASONING_LENGTH: Final[int] = 5000
MAX_KEY_FINDINGS: Final[int] = 20
MAX_EVIDENCE_REFS: Final[int] = 50
MAX_NEXT_CHECKS: Final[int] = 20
MAX_REMEDIATION_SUGGESTIONS: Final[int] = 20


# ── DOMAIN EXCEPTIONS ────────────────────────────────────────────────────────
class LLMError(DomainException):
    """Base exception for LLM operations."""


class LLMValidationError(ValidationError):
    """Raised when generated analysis violates grounding or schema constraints."""


class LLMProviderUnavailableError(LLMError):
    """Raised when the LLM provider fails to respond or returns server errors."""


class LLMTimeoutError(LLMError):
    """Raised when the LLM provider times out."""
