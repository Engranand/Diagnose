"""OpenAI-compatible HTTP LLM Provider implementation (Milestone 9)."""

from __future__ import annotations

import json
from typing import Any

import httpx
import structlog
from pydantic import ValidationError

from diagnose.domain.llm import (
    LLMProviderUnavailableError,
    LLMTimeoutError,
    LLMValidationError,
)
from diagnose.llm.base import LLMProvider
from diagnose.llm.context import InvestigationContext
from diagnose.schemas.llm import InvestigationAnalysisOutput

log = structlog.get_logger()


class OpenAILLMProvider(LLMProvider):
    """OpenAI-compatible HTTP provider using async httpx."""

    def __init__(
        self,
        api_key: str | None,
        model_name: str = "gpt-4o-mini",
        base_url: str | None = None,
        timeout_seconds: int = 30,
    ) -> None:
        self._api_key = api_key
        self._model_name = model_name
        self._base_url = (base_url or "https://api.openai.com/v1").rstrip("/")
        self._timeout_seconds = timeout_seconds

    @property
    def provider_name(self) -> str:
        return "openai"

    @property
    def model_name(self) -> str:
        return self._model_name

    async def health_check(self) -> bool:
        """Check if provider credentials and base URL are configured."""
        return bool(self._api_key and len(self._api_key.strip()) > 0)

    async def generate_analysis(
        self,
        context: InvestigationContext,
        system_prompt: str,
        user_prompt: str,
    ) -> tuple[InvestigationAnalysisOutput, dict[str, Any]]:
        """Call OpenAI chat completion with JSON mode and validate response against strict schema."""
        if not self._api_key:
            raise LLMProviderUnavailableError(
                "OpenAI LLM Provider is not configured with an API key."
            )

        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }

        payload = {
            "model": self._model_name,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0.0,
        }

        url = f"{self._base_url}/chat/completions"

        try:
            async with httpx.AsyncClient(timeout=self._timeout_seconds) as client:
                response = await client.post(url, headers=headers, json=payload)

            if response.status_code == 429:
                raise LLMProviderUnavailableError("OpenAI rate limit exceeded (HTTP 429).")
            elif response.status_code >= 500:
                raise LLMProviderUnavailableError(
                    f"OpenAI service returned server error (HTTP {response.status_code})."
                )
            elif response.status_code != 200:
                raise LLMProviderUnavailableError(
                    f"OpenAI service returned error HTTP {response.status_code}."
                )

            data = response.json()
            choices = data.get("choices", [])
            if not choices:
                raise LLMValidationError("OpenAI returned response with empty choices list.")

            content_text = choices[0].get("message", {}).get("content", "")
            if not content_text:
                raise LLMValidationError("OpenAI returned message with empty content.")

            try:
                parsed_json = json.loads(content_text)
            except json.JSONDecodeError as exc:
                raise LLMValidationError(f"OpenAI output was not valid JSON: {exc}") from exc

            try:
                output = InvestigationAnalysisOutput.model_validate(parsed_json)
            except ValidationError as exc:
                raise LLMValidationError(f"OpenAI JSON failed schema validation: {exc}") from exc

            usage = data.get("usage", {})
            metadata = {
                "provider": "openai",
                "model": self._model_name,
                "usage": usage,
            }
            return output, metadata

        except httpx.TimeoutException as exc:
            raise LLMTimeoutError(
                f"OpenAI provider request timed out after {self._timeout_seconds} seconds."
            ) from exc
        except httpx.RequestError as exc:
            raise LLMProviderUnavailableError(
                f"Failed to communicate with OpenAI provider: {exc.__class__.__name__}"
            ) from exc
