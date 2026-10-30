"""Aggregated v1 API router."""

from __future__ import annotations

from fastapi import APIRouter

from diagnose.api.v1.health import router as health_router

v1_router = APIRouter()
v1_router.include_router(health_router)
