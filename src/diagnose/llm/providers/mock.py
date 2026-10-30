"""Deterministic Mock LLM Provider for offline testing and local execution (Milestone 9)."""

from __future__ import annotations

import asyncio
from typing import Any
from uuid import UUID

from diagnose.domain.investigation import ConfidenceBand
from diagnose.domain.llm import (
    LLMProviderUnavailableError,
    LLMTimeoutError,
    LLMValidationError,
)
from diagnose.llm.base import LLMProvider
from diagnose.llm.context import InvestigationContext
from diagnose.schemas.llm import HypothesisAssessment, InvestigationAnalysisOutput


class MockLLMProvider(LLMProvider):
    """Deterministic, offline LLM provider that reasons strictly using supplied M8 context."""

    def __init__(
        self,
        model_name: str = "mock-gpt-4o",
        simulate_timeout: bool = False,
        simulate_unavailable: bool = False,
        simulate_invalid_json: bool = False,
        simulate_unknown_evidence_ref: bool = False,
        simulate_oversized_output: bool = False,
    ) -> None:
        self._model_name = model_name
        self.simulate_timeout = simulate_timeout
        self.simulate_unavailable = simulate_unavailable
        self.simulate_invalid_json = simulate_invalid_json
        self.simulate_unknown_evidence_ref = simulate_unknown_evidence_ref
        self.simulate_oversized_output = simulate_oversized_output

    @property
    def provider_name(self) -> str:
        return "mock"

    @property
    def model_name(self) -> str:
        return self._model_name

    async def health_check(self) -> bool:
        return not self.simulate_unavailable

    async def generate_analysis(
        self,
        context: InvestigationContext,
        system_prompt: str,
        user_prompt: str,
    ) -> tuple[InvestigationAnalysisOutput, dict[str, Any]]:
        if self.simulate_timeout:
            raise LLMTimeoutError("Mock provider simulated request timeout.")

        if self.simulate_unavailable:
            raise LLMProviderUnavailableError("Mock provider simulated service unavailable (503).")

        if self.simulate_invalid_json:
            raise LLMValidationError("Mock provider returned unparseable non-JSON output.")

        # Extract top hypothesis and assessments from context
        top_hypo = context.hypotheses[0] if context.hypotheses else None
        primary_id = UUID(top_hypo.id) if top_hypo else None

        assessments: list[HypothesisAssessment] = []
        for h in context.hypotheses:
            # Collect evidence refs that belong to this hypothesis and are in valid_evidence_ids
            h_evidence_refs = [
                el.evidence_id for el in h.evidence_links
                if el.evidence_id in context.valid_evidence_ids
            ]
            if not h_evidence_refs and context.valid_evidence_ids:
                h_evidence_refs = [context.valid_evidence_ids[0]]

            # Convert confidence band safely
            try:
                band = ConfidenceBand(h.confidence)
            except ValueError:
                band = ConfidenceBand.MEDIUM

            assessments.append(
                HypothesisAssessment(
                    hypothesis_id=UUID(h.id),
                    assessment=f"Evaluated hypothesis '{h.title}' with confidence {band.value}.",
                    reasoning=f"Evidence links corroborate score {h.score:.2f} based on deterministic timeline telemetry.",
                    evidence_refs=h_evidence_refs,
                    confidence_band=band,
                )
            )

        # Supporting and contradicting evidence from context
        supp_refs: list[str] = []
        contra_refs: list[str] = []
        if top_hypo:
            for el in top_hypo.evidence_links:
                if el.evidence_id in context.valid_evidence_ids:
                    if el.relationship == "SUPPORTING":
                        supp_refs.append(el.evidence_id)
                    elif el.relationship == "CONTRADICTING":
                        contra_refs.append(el.evidence_id)

        # Fallback to general evidence if none explicitly linked
        if not supp_refs and context.valid_evidence_ids:
            supp_refs = [context.valid_evidence_ids[0]]

        # Injected fault for testing: cite an unlisted/fabricated evidence ID
        if self.simulate_unknown_evidence_ref:
            supp_refs.append("fabricated-evidence-id-99999")

        key_findings = [
            f"Observed {item.event_type} event: {item.summary}"
            for item in context.timeline[:5]
        ]
        if not key_findings:
            key_findings = [f"Incident #{context.incident.incident_number} detected on service '{context.service.name if context.service else 'unknown'}'."]

        summary_text = (
            f"Root cause analysis for Incident #{context.incident.incident_number}: {context.incident.title}. "
            f"The primary supported hypothesis is '{top_hypo.title if top_hypo else 'Undetermined'}'."
        )
        if self.simulate_oversized_output:
            summary_text = summary_text + ("X" * 6000)

        output = InvestigationAnalysisOutput(
            summary=summary_text,
            primary_hypothesis_id=primary_id,
            hypothesis_assessments=assessments,
            key_findings=key_findings,
            supporting_evidence=supp_refs,
            contradicting_evidence=contra_refs,
            missing_evidence=[
                "Detailed connection pool saturation metrics leading up to failure onset.",
                "Downstream dependency latency breakdown.",
            ],
            next_checks=[
                "Verify database connection pool capacity and max client limits.",
                "Audit recent deployment changelog for connection lifecycle leaks.",
            ],
            remediation_suggestions=[
                "Increase database connection pool size if resources allow (requires engineering review).",
                "Implement aggressive circuit breaker around checkout database calls.",
            ],
            limitations="Analysis is grounded in automated telemetry captured during incident window; manual confirmation required before altering production configs.",
            model_metadata={
                "provider": "mock",
                "model": self._model_name,
                "prompt_tokens": 1250,
                "completion_tokens": 420,
            },
        )

        metadata = {
            "provider": "mock",
            "model": self._model_name,
            "simulated": True,
        }
        return output, metadata
