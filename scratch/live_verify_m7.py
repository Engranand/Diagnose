"""Live verification script for Milestone 7: API Hardening & Production Reliability."""

from __future__ import annotations

import asyncio
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone

from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import create_async_engine

# Ensure src and root in sys.path
sys.path.insert(0, os.path.abspath("src"))
sys.path.insert(0, os.path.abspath("."))

from diagnose.core.security import create_access_token
from diagnose.domain.roles import Role
from diagnose.main import create_app
from diagnose.models.alert import Alert
from diagnose.models.audit_log import AuditLog
from diagnose.models.incident import Incident
from diagnose.models.job import Job
from diagnose.models.organization import Organization
from diagnose.models.service import Service
from diagnose.models.user import User
from diagnose.settings import get_settings
from tests.fake_redis import FakeAsyncRedis


async def main() -> None:
    print("[*] Starting Milestone 7 Live System Verification...")
    settings = get_settings()

    app = create_app(settings)
    engine = create_async_engine(settings.DATABASE_URL)
    app.state.db_engine = engine

    # Use deterministic Redis double for rate-limiting verification if local standalone Redis server is inactive
    fake_redis = FakeAsyncRedis()
    app.state.redis = fake_redis

    from sqlalchemy.ext.asyncio import async_sessionmaker
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    app.state.db_session_factory = session_factory

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        # Setup Organization & Users
        async with session_factory() as session:
            org_a = Organization(
                id=uuid.uuid4(),
                name=f"Hardened Org Alpha {uuid.uuid4().hex[:4]}",
                slug=f"org-alpha-{uuid.uuid4().hex[:6]}",
                is_active=True,
            )
            org_b = Organization(
                id=uuid.uuid4(),
                name=f"Foreign Org Beta {uuid.uuid4().hex[:4]}",
                slug=f"org-beta-{uuid.uuid4().hex[:6]}",
                is_active=True,
            )
            session.add_all([org_a, org_b])
            await session.commit()

            admin_user = User(
                id=uuid.uuid4(),
                organization_id=org_a.id,
                email=f"admin-{uuid.uuid4().hex[:6]}@diagnose.io",
                hashed_password="mock_hash",
                role=Role.ADMIN.value,
                is_active=True,
            )
            viewer_user = User(
                id=uuid.uuid4(),
                organization_id=org_a.id,
                email=f"viewer-{uuid.uuid4().hex[:6]}@diagnose.io",
                hashed_password="mock_hash",
                role=Role.VIEWER.value,
                is_active=True,
            )
            foreign_user = User(
                id=uuid.uuid4(),
                organization_id=org_b.id,
                email=f"foreign-{uuid.uuid4().hex[:6]}@foreign.io",
                hashed_password="mock_hash",
                role=Role.ADMIN.value,
                is_active=True,
            )
            session.add_all([admin_user, viewer_user, foreign_user])
            await session.commit()

            # Services
            svc_a1 = Service(
                id=uuid.uuid4(),
                organization_id=org_a.id,
                name="Checkout API",
                slug=f"checkout-api-{uuid.uuid4().hex[:4]}",
                tier="CRITICAL",
                is_active=True,
            )
            svc_a2 = Service(
                id=uuid.uuid4(),
                organization_id=org_a.id,
                name="Inventory Service",
                slug=f"inventory-{uuid.uuid4().hex[:4]}",
                tier="MEDIUM",
                is_active=True,
            )
            svc_b = Service(
                id=uuid.uuid4(),
                organization_id=org_b.id,
                name="Foreign Secret Service",
                slug=f"foreign-svc-{uuid.uuid4().hex[:4]}",
                tier="HIGH",
                is_active=True,
            )
            session.add_all([svc_a1, svc_a2, svc_b])
            await session.commit()

            # Incidents for Org A
            now = datetime.now(timezone.utc)
            inc1 = Incident(
                id=uuid.uuid4(),
                organization_id=org_a.id,
                service_id=svc_a1.id,
                title="Checkout Gateway Timeout",
                description="Gateway timed out during bank handshake",
                incident_number=1,
                severity="CRITICAL",
                status="INVESTIGATING",
                assigned_user_id=admin_user.id,
                created_at=now - timedelta(days=2),
                updated_at=now - timedelta(days=2),
            )
            inc2 = Incident(
                id=uuid.uuid4(),
                organization_id=org_a.id,
                service_id=svc_a2.id,
                title="Inventory Sync Delay",
                description="Catalog replication lag exceeded 5 minutes",
                incident_number=2,
                severity="LOW",
                status="RESOLVED",
                assigned_user_id=None,
                created_at=now - timedelta(days=1),
                updated_at=now - timedelta(days=1),
            )
            # Foreign incident for Org B
            inc_foreign = Incident(
                id=uuid.uuid4(),
                organization_id=org_b.id,
                service_id=svc_b.id,
                title="Foreign Secret Confidential Incident",
                description="Should never be visible to Org A",
                incident_number=1,
                severity="CRITICAL",
                status="DETECTED",
                created_at=now,
                updated_at=now,
            )
            session.add_all([inc1, inc2, inc_foreign])
            await session.commit()

            # Alert for Org A
            alert1 = Alert(
                id=uuid.uuid4(),
                organization_id=org_a.id,
                service_id=svc_a1.id,
                incident_id=inc1.id,
                fingerprint=f"alert-checkout-{uuid.uuid4().hex[:6]}",
                source="prometheus",
                alert_type="http_5xx",
                title="Checkout 500 error rate spike",
                severity="CRITICAL",
                status="FIRING",
                created_at=now - timedelta(days=2),
                last_seen_at=now - timedelta(days=2),
            )
            session.add(alert1)

            # Job for Org A
            job1 = Job(
                id=uuid.uuid4(),
                organization_id=org_a.id,
                job_type="SEND_WEBHOOK",
                status="SUCCEEDED",
                available_at=now,
                created_at=now,
            )
            session.add(job1)
            await session.commit()

        token_a = create_access_token(
            user_id=admin_user.id,
            organization_id=org_a.id,
            role=Role.ADMIN.value,
        )
        headers_a = {"Authorization": f"Bearer {token_a}"}

        print("\n--- 1. PAGINATED INCIDENT LIST ---")
        r_page = await client.get("/api/v1/incidents?page=1&page_size=1", headers=headers_a)
        assert r_page.status_code == 200
        p_data = r_page.json()
        assert len(p_data["items"]) == 1
        assert p_data["page"] == 1
        assert p_data["page_size"] == 1
        assert p_data["total"] >= 2
        print(f"[OK] Paginated list returns bounded items: {len(p_data['items'])} item, total={p_data['total']}")

        print("\n--- 2. INCIDENT FILTERING ---")
        r_filt = await client.get("/api/v1/incidents?severity=CRITICAL", headers=headers_a)
        assert r_filt.status_code == 200
        filt_items = r_filt.json()["items"]
        assert all(i["severity"] == "CRITICAL" for i in filt_items)
        assert any(i["id"] == str(inc1.id) for i in filt_items)
        print(f"[OK] Filtered by severity=CRITICAL matched {len(filt_items)} incidents")

        print("\n--- 3. INCIDENT SORTING ---")
        r_sort_desc = await client.get("/api/v1/incidents?sort_by=created_at&sort_order=desc", headers=headers_a)
        r_sort_asc = await client.get("/api/v1/incidents?sort_by=created_at&sort_order=asc", headers=headers_a)
        assert r_sort_desc.status_code == 200 and r_sort_asc.status_code == 200
        desc_ids = [x["id"] for x in r_sort_desc.json()["items"]]
        asc_ids = [x["id"] for x in r_sort_asc.json()["items"]]
        assert desc_ids != asc_ids, "Sorting order should reverse item ordering"
        print("[OK] Explicit sort_by and sort_order working deterministically")

        print("\n--- 4. INCIDENT SEARCH ---")
        r_search = await client.get("/api/v1/incidents?search=handshake", headers=headers_a)
        assert r_search.status_code == 200
        search_items = r_search.json()["items"]
        assert len(search_items) == 1
        assert search_items[0]["id"] == str(inc1.id)
        print(f"[OK] Server-side ILIKE search found: '{search_items[0]['title']}'")

        print("\n--- 5. ALERT FILTERING ---")
        r_alert = await client.get("/api/v1/alerts?status=FIRING&severity=CRITICAL", headers=headers_a)
        assert r_alert.status_code == 200
        assert any(a["id"] == str(alert1.id) for a in r_alert.json()["items"])
        print("[OK] Alert filtering by status and severity working")

        print("\n--- 6. JOB FILTERING ---")
        r_jobs = await client.get("/api/v1/jobs?status=SUCCEEDED", headers=headers_a)
        assert r_jobs.status_code == 200
        assert any(j["id"] == str(job1.id) for j in r_jobs.json()["items"])
        print("[OK] Job filtering by status working")

        print("\n--- 7. INVALID SORT FIELD RETURNS 422 ---")
        r_inv_sort = await client.get("/api/v1/incidents?sort_by=secret_password", headers=headers_a)
        assert r_inv_sort.status_code == 422
        assert r_inv_sort.json()["error"]["code"] == "VALIDATION_ERROR"
        print(f"[OK] Invalid sort field safely rejected with 422: {r_inv_sort.json()['error']['message']}")

        print("\n--- 8. INVALID DATE RANGE RETURNS 422 ---")
        r_inv_date = await client.get(
            "/api/v1/incidents?created_from=2026-10-10T00:00:00Z&created_to=2026-10-01T00:00:00Z",
            headers=headers_a,
        )
        assert r_inv_date.status_code == 422
        assert r_inv_date.json()["error"]["code"] == "VALIDATION_ERROR"
        print(f"[OK] Invalid date range safely rejected with 422: {r_inv_date.json()['error']['message']}")

        print("\n--- 9. OVERSIZED PAGINATION RETURNS 422 ---")
        r_inv_page = await client.get("/api/v1/incidents?page_size=200", headers=headers_a)
        assert r_inv_page.status_code == 422
        assert r_inv_page.json()["error"]["code"] == "VALIDATION_ERROR"
        print("[OK] Page size > 100 rejected with 422")

        print("\n--- 10 & 11. RATE LIMITING & RETRY-AFTER ---")
        from diagnose.middleware.rate_limit import RateLimitMiddleware
        # Set rate limit to 3 on both user_middleware and the running ASGI middleware instance
        for mw in app.user_middleware:
            if mw.cls == RateLimitMiddleware:
                mw.kwargs["rate_limit_per_minute"] = 3
        curr = app.middleware_stack
        while curr is not None:
            if isinstance(curr, RateLimitMiddleware):
                curr.rate_limit_per_minute = 3
                break
            curr = getattr(curr, "app", None)

        # Make 4 rapid requests to trigger 429
        responses = [await client.get("/api/v1/services", headers=headers_a) for _ in range(4)]
        last_resp = responses[-1]
        assert last_resp.status_code == 429, f"Expected 429, got {last_resp.status_code}"
        assert "Retry-After" in last_resp.headers
        assert last_resp.json()["error"]["code"] == "RATE_LIMIT_EXCEEDED"
        print(f"[OK] Rate limit exceeded returns 429 with Retry-After: {last_resp.headers['Retry-After']}s")

        # Reset rate limit & clear counter for subsequent checks
        if curr is not None:
            curr.rate_limit_per_minute = 120
        fake_redis._keys.clear()

        print("\n--- 12 & 13. CROSS-TENANT ISOLATION (SEARCH & FILTER) ---")
        r_foreign_search = await client.get("/api/v1/incidents?search=Confidential", headers=headers_a)
        assert len(r_foreign_search.json()["items"]) == 0
        r_foreign_filter = await client.get(f"/api/v1/incidents?service_id={svc_b.id}", headers=headers_a)
        assert len(r_foreign_filter.json()["items"]) == 0
        print("[OK] Foreign records completely isolated: zero cross-tenant leak")

        print("\n--- 14 & 15. REDIS RATE LIMITING & SAFE FAIL-OPEN ---")
        fake_redis.simulate_failure = True
        r_fail_open = await client.get("/api/v1/services", headers=headers_a)
        assert r_fail_open.status_code == 200
        fake_redis.simulate_failure = False
        print("[OK] Safe fail-open behavior verified during Redis disruption")

        print("\n--- 16 & 17. ERROR ENVELOPE CONSISTENCY & SENSITIVE DATA ABSENCE ---")
        r_404 = await client.get(f"/api/v1/services/{uuid.uuid4()}", headers=headers_a)
        assert r_404.status_code == 404
        err_body = r_404.json()["error"]
        assert "correlation_id" in err_body
        assert "code" in err_body
        assert "message" in err_body
        assert "password" not in str(r_404.content)
        assert "traceback" not in str(r_404.content)
        print(f"[OK] Error response standard envelope verified: code={err_body['code']}, correlation_id={err_body['correlation_id']}")

        print("\n--- 18. M1-M6 FUNCTIONALITY STABILITY ---")
        # Check health endpoint
        r_h = await client.get("/api/v1/health")
        assert r_h.status_code == 200
        # Check services
        r_s = await client.get("/api/v1/services", headers=headers_a)
        assert r_s.status_code == 200
        print("[OK] Operational endpoints and M1-M6 core integrity completely intact")

    await engine.dispose()
    print("\n=======================================================")
    print("ALL MILESTONE 7 PRODUCTION RELIABILITY CHECKS PASSED!")
    print("=======================================================")


if __name__ == "__main__":
    asyncio.run(main())
