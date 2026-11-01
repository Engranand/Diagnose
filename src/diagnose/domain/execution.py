"""Controlled Remediation Execution domain models, abstractions, and registry (Milestone 10.5).

Enforces an explicit executor boundary where:
1. Authorization decisions are NOT made by the executor.
2. Only explicitly registered executors may run.
3. Unknown executor types fail closed.
4. ZERO subprocess, shell, SSH, Docker, Kubernetes, or cloud SDK calls are executed.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
import uuid

from diagnose.domain.exceptions import UnsupportedExecutorError
from diagnose.domain.remediation import (
    ActionType,
    ExecutionMode,
    ExecutorType,
    RiskLevel,
)


@dataclass(frozen=True)
class ExecutionContext:
    """Immutable context provided to an executor for a single execution attempt."""

    organization_id: uuid.UUID
    action_id: uuid.UUID
    incident_id: uuid.UUID
    service_id: uuid.UUID
    action_type: ActionType
    risk_level: RiskLevel
    execution_mode: ExecutionMode
    environment: str = "production"
    plan_hash: str | None = None
    parameters: dict[str, Any] = field(default_factory=dict)
    actor_user_id: uuid.UUID | None = None
    actor_role: str | None = None
    correlation_id: str | None = None


@dataclass(frozen=True)
class ExecutionResult:
    """Outcome produced by an executor."""

    success: bool
    output: dict[str, Any]
    error: str | None = None
    simulated: bool = True
    executor_type: str = "SIMULATOR"


class BaseExecutor(abc.ABC):
    """Abstract interface for all remediation action executors."""

    @abc.abstractmethod
    async def execute(
        self,
        context: ExecutionContext,
    ) -> ExecutionResult:
        """Execute the remediation intervention and return deterministic outcome."""
        raise NotImplementedError


class SimulatedExecutor(BaseExecutor):
    """Deterministic in-memory simulation executor.
    
    Guarantees:
    - Never touches the OS or shell
    - Never spawns subprocesses
    - Never connects to network, cloud, Docker, or Kubernetes APIs
    - Never mutates infrastructure
    """

    async def execute(
        self,
        context: ExecutionContext,
    ) -> ExecutionResult:
        """Produce deterministic simulated execution result."""
        # Simulated failure can be triggered via parameter override for testing failure paths
        should_fail = bool(context.parameters.get("__simulate_failure", False))
        if should_fail:
            error_msg = str(context.parameters.get("__failure_reason", "Simulated execution failure."))
            return ExecutionResult(
                success=False,
                output={
                    "simulated": True,
                    "executor": "SIMULATOR",
                    "action_id": str(context.action_id),
                    "action_type": context.action_type.value,
                    "plan_hash": context.plan_hash,
                    "result": "SIMULATED_FAILURE",
                    "error": error_msg,
                },
                error=error_msg,
                simulated=True,
                executor_type=ExecutorType.SIMULATOR.value,
            )

        output: dict[str, Any] = {
            "simulated": True,
            "executor": "SIMULATOR",
            "action_id": str(context.action_id),
            "action_type": context.action_type.value,
            "service_id": str(context.service_id),
            "plan_hash": context.plan_hash,
            "result": "SIMULATED_SUCCESS",
            "status": "COMPLETED",
            "execution_timestamp": datetime.now(timezone.utc).isoformat(),
            "applied_parameters": {
                k: v for k, v in context.parameters.items() if not k.startswith("__")
            },
        }
        return ExecutionResult(
            success=True,
            output=output,
            error=None,
            simulated=True,
            executor_type=ExecutorType.SIMULATOR.value,
        )


class ExecutorRegistry:
    """Deterministic, fail-closed registry of authorized executor implementations."""

    def __init__(self) -> None:
        self._executors: dict[str, BaseExecutor] = {
            ExecutorType.SIMULATOR.value: SimulatedExecutor(),
        }

    def get(self, executor_type: ExecutorType | str) -> BaseExecutor:
        """Retrieve the executor instance for the requested type. Fails closed if unknown."""
        type_str = executor_type.value if isinstance(executor_type, ExecutorType) else str(executor_type).upper()
        executor = self._executors.get(type_str)
        if executor is None:
            raise UnsupportedExecutorError(
                f"Executor type '{type_str}' is not supported or registered. Execution failed closed."
            )
        return executor
