"""Post-generation claim and evidence grounding validator (Milestone 9).

Ensures the LLM output does NOT hallucinate evidence IDs, hypotheses, or exceed constraints.
"""

from __future__ import annotations

from uuid import UUID

from diagnose.domain.investigation import ConfidenceBand
from diagnose.domain.llm import (
    LLMValidationError,
    MAX_EVIDENCE_REFS,
    MAX_KEY_FINDINGS,
    MAX_NEXT_CHECKS,
    MAX_REASONING_LENGTH,
    MAX_REMEDIATION_SUGGESTIONS,
    MAX_SUMMARY_LENGTH,
)
from diagnose.llm.context import InvestigationContext
from diagnose.schemas.llm import InvestigationAnalysisOutput


def validate_analysis(
    output: InvestigationAnalysisOutput,
    context: InvestigationContext,
) -> None:
    """Validate that the structured analysis is strictly grounded in the supplied context.

    Raises:
        LLMValidationError: If any evidence ref or hypothesis ID is fabricated,
            or if size/length constraints are violated.
    """
    valid_evidence = set(context.valid_evidence_ids)
    valid_hypotheses = {str(h_id) for h_id in context.valid_hypothesis_ids}

    # 1. Validate primary hypothesis if present
    if output.primary_hypothesis_id is not None:
        primary_id_str = str(output.primary_hypothesis_id)
        if primary_id_str not in valid_hypotheses:
            raise LLMValidationError(
                f"Fabricated primary_hypothesis_id '{primary_id_str}' does not exist in investigation."
            )

    # 2. Validate hypothesis assessments
    for assessment in output.hypothesis_assessments:
        hypo_id_str = str(assessment.hypothesis_id)
        if hypo_id_str not in valid_hypotheses:
            raise LLMValidationError(
                f"Fabricated hypothesis_id '{hypo_id_str}' in hypothesis_assessments does not exist in investigation."
            )

        if not isinstance(assessment.confidence_band, ConfidenceBand):
            raise LLMValidationError(
                f"Invalid confidence_band '{assessment.confidence_band}' for hypothesis '{hypo_id_str}'."
            )

        # Validate evidence references inside each assessment
        for ref in assessment.evidence_refs:
            if ref not in valid_evidence:
                raise LLMValidationError(
                    f"Fabricated evidence ref '{ref}' in assessment for hypothesis '{hypo_id_str}' was not in supplied telemetry."
                )

    # 3. Validate top-level supporting evidence citations
    for ref in output.supporting_evidence:
        if ref not in valid_evidence:
            raise LLMValidationError(
                f"Fabricated evidence ref '{ref}' in supporting_evidence was not in supplied telemetry."
            )

    # 4. Validate top-level contradicting evidence citations
    for ref in output.contradicting_evidence:
        if ref not in valid_evidence:
            raise LLMValidationError(
                f"Fabricated evidence ref '{ref}' in contradicting_evidence was not in supplied telemetry."
            )

    # 5. Enforce output bounds and length constraints
    if len(output.summary) > MAX_SUMMARY_LENGTH:
        raise LLMValidationError(
            f"Summary length ({len(output.summary)}) exceeds maximum allowed ({MAX_SUMMARY_LENGTH})."
        )

    if len(output.limitations) > MAX_SUMMARY_LENGTH:
        raise LLMValidationError(
            f"Limitations length ({len(output.limitations)}) exceeds maximum allowed ({MAX_SUMMARY_LENGTH})."
        )

    if len(output.key_findings) > MAX_KEY_FINDINGS:
        raise LLMValidationError(
            f"Key findings count ({len(output.key_findings)}) exceeds limit ({MAX_KEY_FINDINGS})."
        )

    if len(output.supporting_evidence) > MAX_EVIDENCE_REFS:
        raise LLMValidationError(
            f"Supporting evidence citations count ({len(output.supporting_evidence)}) exceeds limit ({MAX_EVIDENCE_REFS})."
        )

    if len(output.contradicting_evidence) > MAX_EVIDENCE_REFS:
        raise LLMValidationError(
            f"Contradicting evidence citations count ({len(output.contradicting_evidence)}) exceeds limit ({MAX_EVIDENCE_REFS})."
        )

    if len(output.next_checks) > MAX_NEXT_CHECKS:
        raise LLMValidationError(
            f"Next checks count ({len(output.next_checks)}) exceeds limit ({MAX_NEXT_CHECKS})."
        )

    if len(output.remediation_suggestions) > MAX_REMEDIATION_SUGGESTIONS:
        raise LLMValidationError(
            f"Remediation suggestions count ({len(output.remediation_suggestions)}) exceeds limit ({MAX_REMEDIATION_SUGGESTIONS})."
        )
