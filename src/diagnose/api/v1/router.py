"""Aggregated v1 API router."""

from __future__ import annotations

from fastapi import APIRouter

from diagnose.api.v1.alerts import router as alerts_router
from diagnose.api.v1.audit_logs import router as audit_logs_router
from diagnose.api.v1.auth import router as auth_router
from diagnose.api.v1.evidence import router as evidence_router
from diagnose.api.v1.health import router as health_router
from diagnose.api.v1.incidents import router as incidents_router
from diagnose.api.v1.investigations import (
    incident_investigations_router,
    router as investigations_router,
)
from diagnose.api.v1.jobs import router as jobs_router
from diagnose.api.v1.organizations import router as organizations_router
from diagnose.api.v1.services import router as services_router
from diagnose.api.v1.users import router as users_router

v1_router = APIRouter()
v1_router.include_router(health_router)
v1_router.include_router(auth_router)
v1_router.include_router(organizations_router)
v1_router.include_router(users_router)
v1_router.include_router(services_router)
v1_router.include_router(incidents_router)
v1_router.include_router(incident_investigations_router)
v1_router.include_router(investigations_router)
v1_router.include_router(alerts_router)
v1_router.include_router(evidence_router)
v1_router.include_router(jobs_router)
v1_router.include_router(audit_logs_router)
