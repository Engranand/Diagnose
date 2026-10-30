"""Provider resolution factory (Milestone 9)."""

from __future__ import annotations

import os

from diagnose.llm.base import LLMProvider
from diagnose.llm.providers.mock import MockLLMProvider
from diagnose.llm.providers.openai import OpenAILLMProvider
from diagnose.settings import Settings


def get_llm_provider(settings: Settings) -> LLMProvider:
    """Resolve and instantiate the configured LLM provider.

    Checks environment variables LLM_PROVIDER or settings.LLM_PROVIDER.
    Defaults to MockLLMProvider if configured as 'mock' or if OpenAI credentials are missing.
    """
    provider_type = (os.environ.get("LLM_PROVIDER") or settings.LLM_PROVIDER or "mock").strip().lower()
    model_name = os.environ.get("LLM_MODEL") or settings.LLM_MODEL or "mock-gpt-4o"
    api_key = os.environ.get("LLM_API_KEY") or settings.LLM_API_KEY
    base_url = os.environ.get("LLM_BASE_URL") or settings.LLM_BASE_URL
    timeout_seconds = int(os.environ.get("LLM_TIMEOUT_SECONDS") or settings.LLM_TIMEOUT_SECONDS)

    if provider_type == "openai":
        return OpenAILLMProvider(
            api_key=api_key,
            model_name=model_name,
            base_url=base_url,
            timeout_seconds=timeout_seconds,
        )

    return MockLLMProvider(model_name=model_name)
