"""Milestone 7 Tests: API Hardening, Pagination, Filtering, Sorting, Search, Rate Limiting, Request Limits, Error Consistency & Security."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import uuid
import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from diagnose.core.security import create_access_token
from diagnose.domain.alerts import AlertSeverity, AlertStatus
from diagnose.domain.evidence import EvidenceReliability, EvidenceType
from diagnose.domain.incidents import IncidentSeverity, IncidentStatus
from diagnose.domain.jobs import JobStatus
from diagnose.domain.roles import Role
from diagnose.models.alert import Alert
from diagnose.models.audit_log import AuditLog
from diagnose.models.evidence import Evidence
from diagnose.models.incident import Incident
from diagnose.models.job import Job
from diagnose.models.service import Service
from diagnose.models.user import User
from tests.factories import (
    auth_headers_for,
    create_test_incident,
    create_test_organization,
    create_test_service,
    create_test_user,
)
from tests.fake_redis import FakeAsyncRedis


# ── 1. PAGINATION ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_default_pagination_and_custom_pages(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Requirement 1: Default pagination returns page 1 with default page_size 50."""
    org = await create_test_organization(db_session)
    user = await create_test_user(db_session, org.id, role=Role.ADMIN)
    svc = await create_test_service(db_session, org.id)

    # Create 3 incidents
    for i in range(3):
        await create_test_incident(db_session, org.id, svc.id, title=f"Inc {i}")

    # Default pagination
    resp = await client.get("/api/v1/incidents", headers=auth_headers_for(user))
    assert resp.status_code == 200
    data = resp.json()
    assert data["page"] == 1
    assert data["page_size"] == 50
    assert data["total"] >= 3
    assert len(data["items"]) >= 3

    # Custom page and page_size
    resp_custom = await client.get(
        "/api/v1/incidents?page=1&page_size=2", headers=auth_headers_for(user)
    )
    assert resp_custom.status_code == 200
    custom_data = resp_custom.json()
    assert custom_data["page"] == 1
    assert custom_data["page_size"] == 2
    assert len(custom_data["items"]) == 2

    # Limit and offset alternative parameters
    resp_offset = await client.get(
        "/api/v1/incidents?limit=2&offset=1", headers=auth_headers_for(user)
    )
    assert resp_offset.status_code == 200
    offset_data = resp_offset.json()
    assert offset_data["page_size"] == 2
    assert len(offset_data["items"]) == 2


@pytest.mark.asyncio
async def test_maximum_page_size_enforced(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Requirement 1, 7: Page size strictly capped at 100; >100 returns 422."""
    org = await create_test_organization(db_session)
    user = await create_test_user(db_session, org.id, role=Role.ADMIN)

    # 100 is allowed
    r100 = await client.get("/api/v1/incidents?page_size=100", headers=auth_headers_for(user))
    assert r100.status_code == 200

    # 101 is rejected with 422
    r101 = await client.get("/api/v1/incidents?page_size=101", headers=auth_headers_for(user))
    assert r101.status_code == 422
    assert r101.json()["error"]["code"] == "VALIDATION_ERROR"

    # limit=101 also rejected
    r_limit = await client.get("/api/v1/incidents?limit=101", headers=auth_headers_for(user))
    assert r_limit.status_code == 422
    assert r_limit.json()["error"]["code"] == "VALIDATION_ERROR"


@pytest.mark.asyncio
async def test_invalid_negative_pagination_returns_422(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Requirement 1: Negative offset, page 0, or negative limit return 422."""
    org = await create_test_organization(db_session)
    user = await create_test_user(db_session, org.id, role=Role.ADMIN)

    for invalid_param in ["page=0", "page=-1", "page_size=0", "page_size=-5", "offset=-1", "limit=-10"]:
        resp = await client.get(f"/api/v1/incidents?{invalid_param}", headers=auth_headers_for(user))
        assert resp.status_code == 422, f"Expected 422 for {invalid_param}, got {resp.status_code}"
        assert resp.json()["error"]["code"] == "VALIDATION_ERROR"


@pytest.mark.asyncio
async def test_stable_deterministic_ordering_with_tie_breaker(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Requirement 1, 3: Multiple items with identical timestamp return identical stable ordering."""
    org = await create_test_organization(db_session)
    user = await create_test_user(db_session, org.id, role=Role.ADMIN)
    svc = await create_test_service(db_session, org.id)

    fixed_time = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    for i in range(5):
        inc = Incident(
            id=uuid.uuid4(),
            organization_id=org.id,
            service_id=svc.id,
            title=f"Same Time Incident {i}",
            incident_number=100 + i,
            severity="MEDIUM",
            status="DETECTED",
            created_at=fixed_time,
            updated_at=fixed_time,
        )
        db_session.add(inc)
    await db_session.commit()

    r1 = await client.get("/api/v1/incidents?sort_by=created_at&sort_order=asc", headers=auth_headers_for(user))
    r2 = await client.get("/api/v1/incidents?sort_by=created_at&sort_order=asc", headers=auth_headers_for(user))

    ids1 = [item["id"] for item in r1.json()["items"]]
    ids2 = [item["id"] for item in r2.json()["items"]]
    assert ids1 == ids2, "Tie breaker must ensure identical deterministic ordering"


# ── 2. FILTERING ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_incident_filters(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Requirement 2: Incidents filtered by status, severity, service_id, assigned_user_id, created_from/to."""
    org = await create_test_organization(db_session)
    user = await create_test_user(db_session, org.id, role=Role.ADMIN)
    svc1 = await create_test_service(db_session, org.id, name="Svc 1")
    svc2 = await create_test_service(db_session, org.id, name="Svc 2")

    t1 = datetime(2026, 5, 1, 10, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 5, 10, 10, 0, 0, tzinfo=timezone.utc)

    # Incident 1
    i1 = Incident(
        id=uuid.uuid4(),
        organization_id=org.id,
        service_id=svc1.id,
        title="Payment Crash",
        incident_number=1,
        severity="CRITICAL",
        status="INVESTIGATING",
        assigned_user_id=user.id,
        created_at=t1,
        updated_at=t1,
    )
    # Incident 2
    i2 = Incident(
        id=uuid.uuid4(),
        organization_id=org.id,
        service_id=svc2.id,
        title="Slow UI",
        incident_number=2,
        severity="LOW",
        status="RESOLVED",
        assigned_user_id=None,
        created_at=t2,
        updated_at=t2,
    )
    db_session.add_all([i1, i2])
    await db_session.commit()

    headers = auth_headers_for(user)

    # Filter by severity
    r_crit = await client.get("/api/v1/incidents?severity=CRITICAL", headers=headers)
    assert r_crit.status_code == 200
    items = r_crit.json()["items"]
    assert any(x["id"] == str(i1.id) for x in items)
    assert not any(x["id"] == str(i2.id) for x in items)

    # Filter by service_id
    r_svc = await client.get(f"/api/v1/incidents?service_id={svc2.id}", headers=headers)
    assert any(x["id"] == str(i2.id) for x in r_svc.json()["items"])
    assert not any(x["id"] == str(i1.id) for x in r_svc.json()["items"])

    # Filter by assignee
    r_assign = await client.get(f"/api/v1/incidents?assigned_user_id={user.id}", headers=headers)
    assert any(x["id"] == str(i1.id) for x in r_assign.json()["items"])

    # Filter by date range
    r_date = await client.get(
        "/api/v1/incidents?created_from=2026-05-08T00:00:00Z&created_to=2026-05-15T00:00:00Z",
        headers=headers,
    )
    items_date = r_date.json()["items"]
    assert any(x["id"] == str(i2.id) for x in items_date)
    assert not any(x["id"] == str(i1.id) for x in items_date)


@pytest.mark.asyncio
async def test_alert_filters(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Requirement 2: Alerts filtered by status, severity, service_id, incident_id, created_from/to."""
    org = await create_test_organization(db_session)
    user = await create_test_user(db_session, org.id, role=Role.ADMIN)
    svc = await create_test_service(db_session, org.id)
    inc = await create_test_incident(db_session, org.id, svc.id)

    a1 = Alert(
        id=uuid.uuid4(),
        organization_id=org.id,
        service_id=svc.id,
        incident_id=inc.id,
        fingerprint="fp-filter-1",
        source="datadog",
        alert_type="latency",
        title="High Latency Warning",
        severity="HIGH",
        status="FIRING",
        created_at=datetime(2026, 6, 1, tzinfo=timezone.utc),
        last_seen_at=datetime(2026, 6, 1, tzinfo=timezone.utc),
    )
    a2 = Alert(
        id=uuid.uuid4(),
        organization_id=org.id,
        service_id=svc.id,
        incident_id=None,
        fingerprint="fp-filter-2",
        source="cloudwatch",
        alert_type="cpu",
        title="High CPU Warning",
        severity="LOW",
        status="RESOLVED",
        created_at=datetime(2026, 6, 15, tzinfo=timezone.utc),
        last_seen_at=datetime(2026, 6, 15, tzinfo=timezone.utc),
    )
    db_session.add_all([a1, a2])
    await db_session.commit()

    headers = auth_headers_for(user)

    # Filter by status
    r_stat = await client.get("/api/v1/alerts?status=FIRING", headers=headers)
    assert any(x["id"] == str(a1.id) for x in r_stat.json()["items"])
    assert not any(x["id"] == str(a2.id) for x in r_stat.json()["items"])

    # Filter by incident_id
    r_inc = await client.get(f"/api/v1/alerts?incident_id={inc.id}", headers=headers)
    assert any(x["id"] == str(a1.id) for x in r_inc.json()["items"])
    assert not any(x["id"] == str(a2.id) for x in r_inc.json()["items"])


@pytest.mark.asyncio
async def test_evidence_filters(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Requirement 2: Evidence filtered by incident_id, evidence_type, reliability, observed_from/to."""
    org = await create_test_organization(db_session)
    user = await create_test_user(db_session, org.id, role=Role.ADMIN)
    svc = await create_test_service(db_session, org.id)
    inc = await create_test_incident(db_session, org.id, svc.id)

    e1 = Evidence(
        id=uuid.uuid4(),
        organization_id=org.id,
        incident_id=inc.id,
        evidence_type="LOG",
        source="loki",
        title="Server Exception Trace",
        reliability="HIGH",
        evidence_hash=uuid.uuid4().hex,
        observed_at=datetime(2026, 7, 1, 10, 0, 0, tzinfo=timezone.utc),
    )
    e2 = Evidence(
        id=uuid.uuid4(),
        organization_id=org.id,
        incident_id=inc.id,
        evidence_type="METRIC",
        source="prom",
        title="CPU Spike",
        reliability="LOW",
        evidence_hash=uuid.uuid4().hex,
        observed_at=datetime(2026, 7, 20, 10, 0, 0, tzinfo=timezone.utc),
    )
    db_session.add_all([e1, e2])
    await db_session.commit()

    headers = auth_headers_for(user)

    # Filter by evidence_type
    r_type = await client.get(f"/api/v1/incidents/{inc.id}/evidence?evidence_type=LOG", headers=headers)
    assert any(x["id"] == str(e1.id) for x in r_type.json()["items"])
    assert not any(x["id"] == str(e2.id) for x in r_type.json()["items"])

    # Filter by reliability
    r_rel = await client.get(f"/api/v1/incidents/{inc.id}/evidence?reliability=HIGH", headers=headers)
    assert any(x["id"] == str(e1.id) for x in r_rel.json()["items"])
    assert not any(x["id"] == str(e2.id) for x in r_rel.json()["items"])

    # Filter by observed date range
    r_date = await client.get(
        f"/api/v1/incidents/{inc.id}/evidence?observed_from=2026-07-15T00:00:00Z&observed_to=2026-07-25T00:00:00Z",
        headers=headers,
    )
    items = r_date.json()["items"]
    assert any(x["id"] == str(e2.id) for x in items)
    assert not any(x["id"] == str(e1.id) for x in items)


@pytest.mark.asyncio
async def test_job_and_audit_filters(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Requirement 2: Job and Audit Log filters."""
    org = await create_test_organization(db_session)
    user = await create_test_user(db_session, org.id, role=Role.ADMIN)

    # Job
    j1 = Job(
        id=uuid.uuid4(),
        organization_id=org.id,
        job_type="SEND_NOTIFICATION",
        status="SUCCEEDED",
        available_at=datetime.now(timezone.utc),
        created_at=datetime(2026, 8, 1, tzinfo=timezone.utc),
    )
    j2 = Job(
        id=uuid.uuid4(),
        organization_id=org.id,
        job_type="DATA_INDEX",
        status="DEAD",
        available_at=datetime.now(timezone.utc),
        created_at=datetime(2026, 8, 10, tzinfo=timezone.utc),
    )
    db_session.add_all([j1, j2])

    # Audit
    a1 = AuditLog(
        id=uuid.uuid4(),
        organization_id=org.id,
        actor_user_id=user.id,
        action="USER_CREATED",
        entity_type="user",
        entity_id=user.id,
        created_at=datetime(2026, 8, 1, tzinfo=timezone.utc),
    )
    a2 = AuditLog(
        id=uuid.uuid4(),
        organization_id=org.id,
        actor_user_id=None,
        action="JOB_DISPATCHED",
        entity_type="job",
        entity_id=j1.id,
        created_at=datetime(2026, 8, 10, tzinfo=timezone.utc),
    )
    db_session.add_all([a1, a2])
    await db_session.commit()

    headers = auth_headers_for(user)

    # Filter Jobs
    r_job = await client.get("/api/v1/jobs?status=SUCCEEDED", headers=headers)
    assert any(x["id"] == str(j1.id) for x in r_job.json()["items"])
    assert not any(x["id"] == str(j2.id) for x in r_job.json()["items"])

    # Filter Audit Logs
    r_audit = await client.get("/api/v1/audit-logs?action=USER_CREATED", headers=headers)
    assert r_audit.status_code == 200
    assert any(x["id"] == str(a1.id) for x in r_audit.json()["items"])
    assert not any(x["id"] == str(a2.id) for x in r_audit.json()["items"])


# ── 3. SORTING ───────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_sorting_allowlist_and_rejection(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Requirement 3: Allowed sort fields work; invalid sort fields return 422."""
    org = await create_test_organization(db_session)
    user = await create_test_user(db_session, org.id, role=Role.ADMIN)
    svc = await create_test_service(db_session, org.id)

    # Create 2 incidents with different updated_at
    i1 = await create_test_incident(db_session, org.id, svc.id, title="Inc A", severity="LOW")
    i2 = await create_test_incident(db_session, org.id, svc.id, title="Inc B", severity="CRITICAL")

    headers = auth_headers_for(user)

    # Valid sort fields
    for valid_sort in ["created_at", "updated_at", "severity", "status"]:
        resp = await client.get(f"/api/v1/incidents?sort_by={valid_sort}&sort_order=asc", headers=headers)
        assert resp.status_code == 200, f"Expected 200 for sort_by={valid_sort}"

    # Invalid sort field returns 422
    for invalid_sort in ["password", "unknown_field", "service_name", "; DROP TABLE incidents;"]:
        resp = await client.get(f"/api/v1/incidents?sort_by={invalid_sort}", headers=headers)
        assert resp.status_code == 422
        assert resp.json()["error"]["code"] == "VALIDATION_ERROR"

    # Invalid sort order returns 422
    resp_order = await client.get("/api/v1/incidents?sort_order=sideways", headers=headers)
    assert resp_order.status_code == 422


# ── 4. SEARCH ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_server_side_search_functionality(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Requirement 4: Server-side search on incidents, services, and alerts."""
    org = await create_test_organization(db_session)
    user = await create_test_user(db_session, org.id, role=Role.ADMIN)

    # 1. Services search
    svc1 = await create_test_service(db_session, org.id, name="Auth Engine", slug="auth-engine")
    svc2 = await create_test_service(db_session, org.id, name="Payment Service", slug="payment-service")

    headers = auth_headers_for(user)
    r_svc = await client.get("/api/v1/services?search=Payment", headers=headers)
    assert r_svc.status_code == 200
    svc_names = [s["name"] for s in r_svc.json()]
    assert "Payment Service" in svc_names
    assert "Auth Engine" not in svc_names

    # 2. Incidents search (title + description)
    inc1 = Incident(
        id=uuid.uuid4(),
        organization_id=org.id,
        service_id=svc1.id,
        title="Database Deadlock in Shard 3",
        description="Deadlock occurred during bulk user insert",
        incident_number=501,
        severity="HIGH",
        status="INVESTIGATING",
    )
    inc2 = Incident(
        id=uuid.uuid4(),
        organization_id=org.id,
        service_id=svc2.id,
        title="Redis Memory Exceeded",
        description="Cache cluster node evicted keys",
        incident_number=502,
        severity="MEDIUM",
        status="DETECTED",
    )
    db_session.add_all([inc1, inc2])
    await db_session.commit()

    r_inc = await client.get("/api/v1/incidents?search=Deadlock", headers=headers)
    assert any(x["id"] == str(inc1.id) for x in r_inc.json()["items"])
    assert not any(x["id"] == str(inc2.id) for x in r_inc.json()["items"])

    # Search in description
    r_inc_desc = await client.get("/api/v1/incidents?search=bulk+user", headers=headers)
    assert any(x["id"] == str(inc1.id) for x in r_inc_desc.json()["items"])

    # 3. Search length validation (>100 characters returns 422)
    long_search = "a" * 101
    r_long = await client.get(f"/api/v1/incidents?search={long_search}", headers=headers)
    assert r_long.status_code == 422
    assert r_long.json()["error"]["code"] == "VALIDATION_ERROR"


# ── 5. DATE RANGE VALIDATION ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_date_range_validation(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Requirement 5: created_from > created_to returns 422."""
    org = await create_test_organization(db_session)
    user = await create_test_user(db_session, org.id, role=Role.ADMIN)

    headers = auth_headers_for(user)

    # Valid range returns 200
    r_valid = await client.get(
        "/api/v1/incidents?created_from=2026-01-01T00:00:00Z&created_to=2026-01-02T00:00:00Z",
        headers=headers,
    )
    assert r_valid.status_code == 200

    # Invalid range (from > to) returns 422
    r_invalid = await client.get(
        "/api/v1/incidents?created_from=2026-01-02T00:00:00Z&created_to=2026-01-01T00:00:00Z",
        headers=headers,
    )
    assert r_invalid.status_code == 422
    assert r_invalid.json()["error"]["code"] == "VALIDATION_ERROR"
    assert "cannot be greater than" in r_invalid.json()["error"]["message"]


# ── 6. RATE LIMITING ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_rate_limiting_exhaustion_and_retry_after(
    app, client: AsyncClient, db_session: AsyncSession
) -> None:
    """Requirement 6: Hitting rate limit returns 429 with Retry-After header and envelope."""
    org = await create_test_organization(db_session)
    user = await create_test_user(db_session, org.id, role=Role.ADMIN)

    # Temporarily set limit to 3 for this test
    from diagnose.middleware.rate_limit import RateLimitMiddleware
    for mw in app.user_middleware:
        if mw.cls == RateLimitMiddleware:
            mw.kwargs["rate_limit_per_minute"] = 3

    # Use in-memory double to guarantee test isolation
    fake_redis = FakeAsyncRedis()
    app.state.redis = fake_redis

    headers = auth_headers_for(user)

    # First 3 succeed
    for i in range(3):
        res = await client.get("/api/v1/services", headers=headers)
        assert res.status_code == 200

    # 4th request exceeds rate limit -> 429
    res_exceeded = await client.get("/api/v1/services", headers=headers)
    assert res_exceeded.status_code == 429
    assert "Retry-After" in res_exceeded.headers
    data = res_exceeded.json()
    assert data["error"]["code"] == "RATE_LIMIT_EXCEEDED"
    assert "retry_after" in data["error"]["details"]
    assert "correlation_id" in data["error"]

    # Health endpoint is exempt and still returns 200
    r_health = await client.get("/api/v1/health")
    assert r_health.status_code == 200


@pytest.mark.asyncio
async def test_rate_limiting_redis_unavailable_fails_open(
    app, client: AsyncClient, db_session: AsyncSession
) -> None:
    """Requirement 6: When Redis fails/unavailable, API fails open safely without 500 error."""
    org = await create_test_organization(db_session)
    user = await create_test_user(db_session, org.id, role=Role.ADMIN)

    # Simulate broken Redis
    failing_redis = FakeAsyncRedis()
    failing_redis.simulate_failure = True
    app.state.redis = failing_redis

    headers = auth_headers_for(user)
    # Must fail open (return 200) rather than failing closed (500)
    res = await client.get("/api/v1/services", headers=headers)
    assert res.status_code == 200


# ── 7. REQUEST LIMITS ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_oversized_request_payload_returns_413(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Requirement 7: Payloads exceeding 2MB return 413 REQUEST_TOO_LARGE."""
    org = await create_test_organization(db_session)
    user = await create_test_user(db_session, org.id, role=Role.ADMIN)

    # 2.5 MB payload
    oversized_data = {"name": "Svc", "slug": "svc", "tier": "LOW", "description": "x" * (2500 * 1024)}

    res = await client.post(
        "/api/v1/services",
        json=oversized_data,
        headers=auth_headers_for(user),
    )
    assert res.status_code == 413
    assert res.json()["error"]["code"] == "REQUEST_TOO_LARGE"


@pytest.mark.asyncio
async def test_excessive_query_string_length_returns_400(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Requirement 7: Query strings exceeding 2048 chars return 400 QUERY_TOO_LONG."""
    org = await create_test_organization(db_session)
    user = await create_test_user(db_session, org.id, role=Role.ADMIN)

    huge_query = "x=" + ("a" * 2100)
    res = await client.get(f"/api/v1/services?{huge_query}", headers=auth_headers_for(user))
    assert res.status_code == 400
    assert res.json()["error"]["code"] == "QUERY_TOO_LONG"


# ── 8. ERROR CONSISTENCY ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_error_consistency_envelope_and_status_codes(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Requirement 8: Standard error envelope across 401, 403, 404, 409, 422."""
    org = await create_test_organization(db_session)
    user = await create_test_user(db_session, org.id, role=Role.VIEWER)

    # 401 Unauthenticated
    r401 = await client.get("/api/v1/services")
    assert r401.status_code == 401
    assert r401.json()["error"]["code"] == "UNAUTHORIZED"
    assert "correlation_id" in r401.json()["error"]

    # 403 Forbidden (viewer cannot create service)
    r403 = await client.post(
        "/api/v1/services",
        json={"name": "Forbidden Svc", "slug": "forbidden-svc", "tier": "LOW"},
        headers=auth_headers_for(user),
    )
    assert r403.status_code == 403
    assert r403.json()["error"]["code"] == "FORBIDDEN"
    assert "correlation_id" in r403.json()["error"]

    # 404 Not Found
    r404 = await client.get(
        f"/api/v1/services/{uuid.uuid4()}",
        headers=auth_headers_for(user),
    )
    assert r404.status_code == 404
    assert r404.json()["error"]["code"] == "NOT_FOUND"

    # 422 Validation (with authorized admin user)
    admin = await create_test_user(db_session, org.id, role=Role.ADMIN)
    r422 = await client.post(
        "/api/v1/services",
        json={"invalid_body": True},
        headers=auth_headers_for(admin),
    )
    assert r422.status_code == 422
    assert r422.json()["error"]["code"] == "VALIDATION_ERROR"


# ── 10. SECURITY HARDENING ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_cross_tenant_isolation_in_search_and_filter(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Requirement 10: Cross-tenant search and filter never leaks foreign records."""
    org_a = await create_test_organization(db_session, name="Org Alpha")
    org_b = await create_test_organization(db_session, name="Org Beta")

    user_a = await create_test_user(db_session, org_a.id, role=Role.ADMIN)
    user_b = await create_test_user(db_session, org_b.id, role=Role.ADMIN)

    svc_b = await create_test_service(db_session, org_b.id, name="Secret Foreign Service", slug="foreign-secret")
    inc_b = await create_test_incident(db_session, org_b.id, svc_b.id, title="Confidential Security Incident")

    # User A tries to search for User B's service
    res_svc = await client.get(
        "/api/v1/services?search=Secret",
        headers=auth_headers_for(user_a),
    )
    assert res_svc.status_code == 200
    assert len(res_svc.json()) == 0

    # User A tries to search for User B's incident
    res_inc = await client.get(
        "/api/v1/incidents?search=Confidential",
        headers=auth_headers_for(user_a),
    )
    assert res_inc.status_code == 200
    assert len(res_inc.json()["items"]) == 0

    # User A tries to filter incidents by User B's service_id
    res_filter = await client.get(
        f"/api/v1/incidents?service_id={svc_b.id}",
        headers=auth_headers_for(user_a),
    )
    assert res_filter.status_code == 200
    assert len(res_filter.json()["items"]) == 0


# ── 11. CROSS-TENANT DIRECT ACCESS ERROR SEMANTICS ────────────────────────────


@pytest.mark.asyncio
async def test_cross_tenant_direct_access_returns_enumeration_resistant_404(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Requirement: Direct resource lookup for foreign tenant returns enumeration-resistant 404, never 403."""
    org_a = await create_test_organization(db_session, name="Org Alpha Res")
    org_b = await create_test_organization(db_session, name="Org Beta Res")

    user_a = await create_test_user(db_session, org_a.id, role=Role.ADMIN)
    user_b = await create_test_user(db_session, org_b.id, role=Role.ADMIN)

    # Org A resources
    svc_a = await create_test_service(db_session, org_a.id, name="Svc Alpha", slug="svc-alpha")
    inc_a = await create_test_incident(db_session, org_a.id, svc_a.id, title="Incident Alpha")

    alert_a = Alert(
        id=uuid.uuid4(),
        organization_id=org_a.id,
        service_id=svc_a.id,
        fingerprint=f"fp-alpha-{uuid.uuid4().hex[:6]}",
        source="prometheus",
        alert_type="cpu",
        title="High CPU Alpha",
        severity=AlertSeverity.HIGH.value,
        status=AlertStatus.FIRING.value,
    )
    evidence_a = Evidence(
        id=uuid.uuid4(),
        organization_id=org_a.id,
        incident_id=inc_a.id,
        evidence_type=EvidenceType.LOG.value,
        title="App Crash Log Alpha",
        source="datadog",
        content="App crash traceback: null pointer exception",
        structured_data={"trace": "null pointer"},
        evidence_hash=uuid.uuid4().hex,
        reliability=EvidenceReliability.HIGH.value,
    )
    job_a = Job(
        id=uuid.uuid4(),
        organization_id=org_a.id,
        job_type="test_job",
        payload={"task": "sync"},
        status=JobStatus.PENDING.value,
    )
    db_session.add_all([alert_a, evidence_a, job_a])
    await db_session.commit()

    headers_a = auth_headers_for(user_a)
    headers_b = auth_headers_for(user_b)

    endpoints = [
        (f"/api/v1/services/{svc_a.id}", "Service"),
        (f"/api/v1/incidents/{inc_a.id}", "Incident"),
        (f"/api/v1/alerts/{alert_a.id}", "Alert"),
        (f"/api/v1/evidence/{evidence_a.id}", "Evidence"),
        (f"/api/v1/jobs/{job_a.id}", "Job"),
    ]

    for path, entity_name in endpoints:
        # 1. Tenant A accesses own resource -> 200 OK
        resp_a = await client.get(path, headers=headers_a)
        assert resp_a.status_code == 200, f"Tenant A should access own {entity_name}"
        assert resp_a.json()["id"] == (str(svc_a.id) if entity_name == "Service" else resp_a.json()["id"])

        # 2. Tenant B accesses Tenant A's resource -> 404 NOT_FOUND (enumeration resistant, not 403)
        resp_b = await client.get(path, headers=headers_b)
        assert resp_b.status_code == 404, f"Tenant B must receive 404 for {entity_name}, not 403"
        err_b = resp_b.json()["error"]
        assert err_b["code"] == "NOT_FOUND"
        assert "correlation_id" in err_b

        # 3. Completely nonexistent UUID also returns identical 404 NOT_FOUND
        random_id = uuid.uuid4()
        resp_rand = await client.get(path.rsplit("/", 1)[0] + f"/{random_id}", headers=headers_b)
        assert resp_rand.status_code == 404
        assert resp_rand.json()["error"]["code"] == "NOT_FOUND"


# ── 12. PAGINATION MIXED MODE REJECTION ───────────────────────────────────────


@pytest.mark.asyncio
async def test_pagination_mixed_mode_rejection(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Requirement: Supplying both offset-based and page-based parameters is rejected with 422."""
    org = await create_test_organization(db_session)
    user = await create_test_user(db_session, org.id, role=Role.ADMIN)
    headers = auth_headers_for(user)

    # 1. limit + offset only -> 200 OK
    r1 = await client.get("/api/v1/incidents?limit=10&offset=0", headers=headers)
    assert r1.status_code == 200

    # 2. page + page_size only -> 200 OK
    r2 = await client.get("/api/v1/incidents?page=1&page_size=10", headers=headers)
    assert r2.status_code == 200

    # 3. Both supplied simultaneously -> 422 VALIDATION_ERROR
    r3 = await client.get(
        "/api/v1/incidents?page=2&page_size=20&limit=100&offset=0", headers=headers
    )
    assert r3.status_code == 422
    assert r3.json()["error"]["code"] == "VALIDATION_ERROR"
    assert "Mixed pagination parameters" in r3.json()["error"]["message"]

    # 4. Partial mixed combination: page + limit -> 422
    r4 = await client.get("/api/v1/incidents?page=1&limit=10", headers=headers)
    assert r4.status_code == 422
    assert r4.json()["error"]["code"] == "VALIDATION_ERROR"

    # 5. Partial mixed combination: page_size + offset -> 422
    r5 = await client.get("/api/v1/incidents?page_size=10&offset=5", headers=headers)
    assert r5.status_code == 422
    assert r5.json()["error"]["code"] == "VALIDATION_ERROR"


# ── 13. RATE LIMITING USER ISOLATION & RECOVERY ───────────────────────────────


@pytest.mark.asyncio
async def test_rate_limiting_user_isolation_and_recovery(
    app, client: AsyncClient, db_session: AsyncSession
) -> None:
    """Requirement: Rate limiting is per-user scoped by tenant; Redis outage fails open and recovers."""
    org_a = await create_test_organization(db_session, name="RateLimit Org A")
    org_b = await create_test_organization(db_session, name="RateLimit Org B")

    user_a1 = await create_test_user(db_session, org_a.id, role=Role.ADMIN)
    user_a2 = await create_test_user(db_session, org_a.id, role=Role.VIEWER)
    user_b1 = await create_test_user(db_session, org_b.id, role=Role.ADMIN)

    from diagnose.middleware.rate_limit import RateLimitMiddleware
    # Set rate limit to 2 for this test
    for mw in app.user_middleware:
        if mw.cls == RateLimitMiddleware:
            mw.kwargs["rate_limit_per_minute"] = 2

    def _get_rl_mw():
        curr = getattr(app, "middleware_stack", None)
        while curr is not None:
            if isinstance(curr, RateLimitMiddleware):
                return curr
            curr = getattr(curr, "app", None)
        return None

    fake_redis = FakeAsyncRedis()
    app.state.redis = fake_redis

    headers_a1 = auth_headers_for(user_a1)
    headers_a2 = auth_headers_for(user_a2)
    headers_b1 = auth_headers_for(user_b1)

    # 1. User A1 makes 2 requests (reaches limit)
    assert (await client.get("/api/v1/services", headers=headers_a1)).status_code == 200

    # Ensure running middleware instance has limit=2
    rl_mw = _get_rl_mw()
    if rl_mw is not None:
        rl_mw.rate_limit_per_minute = 2
        rl_mw._circuit_breaker_until = 0.0

    assert (await client.get("/api/v1/services", headers=headers_a1)).status_code == 200

    # 3rd request for User A1 is throttled -> 429
    r_a1_throttled = await client.get("/api/v1/services", headers=headers_a1)
    assert r_a1_throttled.status_code == 429
    assert r_a1_throttled.json()["error"]["code"] == "RATE_LIMIT_EXCEEDED"

    # 2. User A2 in SAME tenant has independent bucket -> 200 OK
    assert (await client.get("/api/v1/services", headers=headers_a2)).status_code == 200

    # 3. User B1 in DIFFERENT tenant has independent bucket -> 200 OK
    assert (await client.get("/api/v1/services", headers=headers_b1)).status_code == 200

    # 4. Redis failure -> fails open safely (returns 200, no 500)
    fake_redis.simulate_failure = True
    r_fail_open = await client.get("/api/v1/services", headers=headers_a1)
    assert r_fail_open.status_code == 200

    # 5. Redis recovers and circuit breaker elapses -> rate limiting resumes
    fake_redis.simulate_failure = False
    rl_mw = _get_rl_mw()
    if rl_mw is not None:
        rl_mw._circuit_breaker_until = 0.0  # Reset circuit breaker
    r_resumed = await client.get("/api/v1/services", headers=headers_a1)
    assert r_resumed.status_code == 429
    assert r_resumed.json()["error"]["code"] == "RATE_LIMIT_EXCEEDED"

    # Reset limit to 120 so other tests are unaffected
    if rl_mw is not None:
        rl_mw.rate_limit_per_minute = 120

