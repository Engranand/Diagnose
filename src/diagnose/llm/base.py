"""Abstract base class for LLM providers (Milestone 9)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from diagnose.llm.context import InvestigationContext
from diagnose.schemas.llm import InvestigationAnalysisOutput


class LLMProvider(ABC):
    """Abstract interface for LLM analysis generation."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Name of the provider (e.g. 'mock', 'openai')."""
        ...

    @property
    @abstractmethod
    def model_name(self) -> str:
        """Name of the underlying model (e.g. 'mock-gpt-4o', 'gpt-4o-mini')."""
        ...

    @abstractmethod
    async def generate_analysis(
        self,
        context: InvestigationContext,
        system_prompt: str,
        user_prompt: str,
    ) -> tuple[InvestigationAnalysisOutput, dict[str, Any]]:
        """Generate structured incident analysis grounded in the provided context.

        Returns:
            Tuple of (parsed_output, model_metadata).
        """
        ...

    @abstractmethod
    async def health_check(self) -> bool:
        """Verify provider availability and configuration."""
        ...
