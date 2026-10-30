"""Evidence domain models, enums, and content hashing."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any


class EvidenceType(StrEnum):
    """Categories of investigation artifacts."""

    LOG = "LOG"
    METRIC = "METRIC"
    TRACE = "TRACE"
    ALERT = "ALERT"
    DEPLOYMENT = "DEPLOYMENT"
    CONFIG = "CONFIG"
    EVENT = "EVENT"
    DOCUMENT = "DOCUMENT"
    OTHER = "OTHER"


class EvidenceReliability(StrEnum):
    """Assessed reliability of evidence artifact."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


def compute_evidence_hash(
    incident_id: uuid.UUID,
    evidence_type: str | EvidenceType,
    source: str,
    content: str | None = None,
    structured_data: dict[str, Any] | None = None,
    observed_at: datetime | None = None,
) -> str:
    """Compute a deterministic SHA-256 fingerprint for evidence deduplication.

    SHA-256(incident_id + evidence_type + normalized source + normalized content + canonical JSON + observed_at)
    """
    hasher = hashlib.sha256()
    hasher.update(str(incident_id).encode("utf-8"))

    type_str = evidence_type.value if isinstance(evidence_type, EvidenceType) else str(evidence_type)
    hasher.update(type_str.upper().strip().encode("utf-8"))
    hasher.update(source.strip().lower().encode("utf-8"))

    norm_content = (content or "").strip()
    hasher.update(norm_content.encode("utf-8"))

    if structured_data is not None:
        norm_json = json.dumps(structured_data, sort_keys=True, separators=(",", ":"))
        hasher.update(norm_json.encode("utf-8"))
    else:
        hasher.update(b"")

    if observed_at is not None:
        hasher.update(observed_at.isoformat().encode("utf-8"))
    else:
        hasher.update(b"")

    return hasher.hexdigest()
