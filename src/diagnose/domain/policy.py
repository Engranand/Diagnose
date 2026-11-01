"""Domain models, enums, specificity scoring, and deterministic conflict resolution for Remediation Policies (Milestone 10.2)."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Sequence

from pydantic import BaseModel, ConfigDict

from diagnose.domain.remediation import ActionType, ExecutionMode, RiskLevel
from diagnose.domain.roles import Role


class PolicyDecision(StrEnum):
    """Authoritative outcome of a policy evaluation."""

    ALLOW = "ALLOW"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    DENY = "DENY"


class PolicyEvaluationContext(BaseModel):
    """Canonical, immutable context for evaluating remediation policies."""

    organization_id: uuid.UUID
    incident_id: uuid.UUID
    service_id: uuid.UUID
    service_tier: str
    action_type: ActionType
    risk_level: RiskLevel
    execution_mode: ExecutionMode
    environment: str = "UNKNOWN"
    actor_id: uuid.UUID | None = None
    actor_role: Role
    action_id: uuid.UUID | None = None

    model_config = ConfigDict(frozen=True)

    def canonical_json(self) -> str:
        """Produce deterministic canonical JSON with sorted keys and compact separators."""
        data = {
            "action_id": str(self.action_id) if self.action_id else None,
            "action_type": self.action_type.value,
            "actor_id": str(self.actor_id) if self.actor_id else None,
            "actor_role": self.actor_role.value,
            "environment": self.environment,
            "execution_mode": self.execution_mode.value,
            "incident_id": str(self.incident_id),
            "organization_id": str(self.organization_id),
            "risk_level": self.risk_level.value,
            "service_id": str(self.service_id),
            "service_tier": self.service_tier,
        }
        return json.dumps(data, sort_keys=True, separators=(",", ":"))

    def compute_hash(self) -> str:
        """Compute SHA-256 digest of canonical JSON representation."""
        return hashlib.sha256(self.canonical_json().encode("utf-8")).hexdigest()


def calculate_specificity_score(
    service_id: uuid.UUID | None,
    action_type: str | None,
    risk_level: str | None,
    service_tier: str | None,
    environment: str | None,
    actor_role: str | None,
    execution_mode: str | None,
) -> int:
    """Calculate integer specificity score in [0..7].

    Each non-null explicit constraint contributes +1. Wildcard/None contributes 0.
    """
    score = 0
    if service_id is not None:
        score += 1
    if action_type is not None:
        score += 1
    if risk_level is not None:
        score += 1
    if service_tier is not None:
        score += 1
    if environment is not None:
        score += 1
    if actor_role is not None:
        score += 1
    if execution_mode is not None:
        score += 1
    return score


class PolicyEvaluationResult(BaseModel):
    """Structured evaluation output with comprehensive audit metadata."""

    decision: PolicyDecision
    winning_policy_id: uuid.UUID | None = None
    winning_policy_version: int | None = None
    winning_policy_snapshot: dict[str, Any] | None = None
    all_matched_policies: list[dict[str, Any]] = []
    reasons: list[str] = []
    context_hash: str
    context_snapshot: dict[str, Any]


def evaluate_policies_deterministically(
    context: PolicyEvaluationContext,
    active_policies: Sequence[Any],
) -> PolicyEvaluationResult:
    """Evaluate active policies against context using the strict 7-step resolution algorithm.

    1. Candidate collection (matching all non-null dimensions).
    2. Safety override: DENY > REQUIRE_APPROVAL > ALLOW.
    3. Within winning class: lowest priority integer wins.
    4. Equal priority: highest specificity score wins.
    5. Equal specificity: created_at ASC, id ASC tie-breaker.
    6. Safe fallback when 0 policies match.
    """
    context_hash = context.compute_hash()
    context_snapshot = json.loads(context.canonical_json())

    # Step 1: Collect matching candidates
    matched_candidates: list[dict[str, Any]] = []
    for p in active_policies:
        # Match dimensions: None = wildcard
        if p.service_id is not None and p.service_id != context.service_id:
            continue
        if p.action_type is not None and p.action_type != context.action_type.value:
            continue
        if p.risk_level is not None and p.risk_level != context.risk_level.value:
            continue
        if p.service_tier is not None and p.service_tier != context.service_tier:
            continue
        if p.environment is not None and p.environment != context.environment:
            continue
        if p.actor_role is not None and p.actor_role != context.actor_role.value:
            continue
        if p.execution_mode is not None and p.execution_mode != context.execution_mode.value:
            continue

        spec_score = calculate_specificity_score(
            service_id=p.service_id,
            action_type=p.action_type,
            risk_level=p.risk_level,
            service_tier=p.service_tier,
            environment=p.environment,
            actor_role=p.actor_role,
            execution_mode=p.execution_mode,
        )

        matched_candidates.append(
            {
                "policy": p,
                "policy_id": p.id,
                "name": p.name,
                "version": p.version,
                "decision": p.decision,
                "priority": p.priority,
                "specificity": spec_score,
                "created_at": p.created_at,
            }
        )

    # If zero active policies match: Safe Fallback
    if not matched_candidates:
        if context.execution_mode == ExecutionMode.DRY_RUN:
            fallback_decision = PolicyDecision.REQUIRE_APPROVAL
            reason = "No matching active policy; safe fallback to REQUIRE_APPROVAL for DRY_RUN mode."
        else:
            if context.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
                fallback_decision = PolicyDecision.DENY
                reason = f"No matching active policy; safe fallback to DENY for EXECUTE mode on {context.risk_level.value} risk action."
            else:
                fallback_decision = PolicyDecision.REQUIRE_APPROVAL
                reason = "No matching active policy; safe fallback to REQUIRE_APPROVAL for EXECUTE mode."

        return PolicyEvaluationResult(
            decision=fallback_decision,
            winning_policy_id=None,
            winning_policy_version=None,
            winning_policy_snapshot=None,
            all_matched_policies=[],
            reasons=[reason],
            context_hash=context_hash,
            context_snapshot=context_snapshot,
        )

    # Step 2-4: Determine winning decision class
    # 2. DENY overrides everything
    deny_pool = [c for c in matched_candidates if c["decision"] == PolicyDecision.DENY.value]
    req_pool = [c for c in matched_candidates if c["decision"] == PolicyDecision.REQUIRE_APPROVAL.value]
    allow_pool = [c for c in matched_candidates if c["decision"] == PolicyDecision.ALLOW.value]

    if deny_pool:
        winning_class = PolicyDecision.DENY
        candidate_pool = deny_pool
        class_reason = f"DENY decision class selected ({len(deny_pool)} matching DENY policy/policies override ALLOW and REQUIRE_APPROVAL)."
    elif req_pool:
        winning_class = PolicyDecision.REQUIRE_APPROVAL
        candidate_pool = req_pool
        class_reason = f"REQUIRE_APPROVAL decision class selected ({len(req_pool)} matching REQUIRE_APPROVAL policy/policies override ALLOW)."
    else:
        winning_class = PolicyDecision.ALLOW
        candidate_pool = allow_pool
        class_reason = f"ALLOW decision class selected ({len(allow_pool)} matching ALLOW policy/policies with zero DENY or REQUIRE_APPROVAL restrictions)."

    # Step 5: Filter for lowest priority number
    min_priority = min(c["priority"] for c in candidate_pool)
    priority_pool = [c for c in candidate_pool if c["priority"] == min_priority]

    # Step 6: Filter for highest specificity score
    max_specificity = max(c["specificity"] for c in priority_pool)
    specificity_pool = [c for c in priority_pool if c["specificity"] == max_specificity]

    # Step 7: Deterministic final tie-break: created_at ASC, id ASC
    sorted_pool = sorted(
        specificity_pool,
        key=lambda c: (c["created_at"] if c["created_at"] is not None else datetime.min.replace(tzinfo=timezone.utc), c["policy_id"]),
    )
    winner_dict = sorted_pool[0]
    winning_policy = winner_dict["policy"]

    # Build winning policy snapshot
    winning_snapshot = {
        "id": str(winning_policy.id),
        "name": winning_policy.name,
        "version": winning_policy.version,
        "decision": winning_policy.decision,
        "priority": winning_policy.priority,
        "specificity": winner_dict["specificity"],
        "dimensions": {
            "service_id": str(winning_policy.service_id) if winning_policy.service_id else None,
            "action_type": winning_policy.action_type,
            "risk_level": winning_policy.risk_level,
            "service_tier": winning_policy.service_tier,
            "environment": winning_policy.environment,
            "actor_role": winning_policy.actor_role,
            "execution_mode": winning_policy.execution_mode,
        },
    }

    # Summary of all matched candidates for audit
    matched_summary = [
        {
            "policy_id": str(c["policy_id"]),
            "name": c["name"],
            "version": c["version"],
            "decision": c["decision"],
            "priority": c["priority"],
            "specificity": c["specificity"],
            "is_winner": (c["policy_id"] == winning_policy.id),
        }
        for c in matched_candidates
    ]

    reasons = [
        f"Evaluated {len(active_policies)} active policies; {len(matched_candidates)} matched context dimensions.",
        class_reason,
        f"Winning policy '{winning_policy.name}' (id: {winning_policy.id}, v{winning_policy.version}) selected: priority={winning_policy.priority}, specificity={winner_dict['specificity']}.",
    ]

    return PolicyEvaluationResult(
        decision=winning_class,
        winning_policy_id=winning_policy.id,
        winning_policy_version=winning_policy.version,
        winning_policy_snapshot=winning_snapshot,
        all_matched_policies=matched_summary,
        reasons=reasons,
        context_hash=context_hash,
        context_snapshot=context_snapshot,
    )
