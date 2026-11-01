"""Deterministic domain foundation for Remediation Action Dry-Run Executor (Milestone 10.3).

ABSOLUTE SAFETY BOUNDARY:
- Pure in-memory domain models and plan generation
- ZERO subprocess, shell, SSH, Docker, Kubernetes, or cloud SDK calls
- ZERO filesystem mutation outside normal DB persistence
- Answers: "If this remediation action were executed, what would happen?"
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
import hashlib
import json
from typing import Any
import uuid

from diagnose.domain.remediation import (
    ActionStatus,
    ActionType,
    ExecutionMode,
    ExecutorType,
)


class DryRunStatus(StrEnum):
    """Lifecycle status for a dry-run execution attempt."""

    DRY_RUN_PENDING = "DRY_RUN_PENDING"
    DRY_RUN_RUNNING = "DRY_RUN_RUNNING"
    DRY_RUN_SUCCESS = "DRY_RUN_SUCCESS"
    DRY_RUN_FAILED = "DRY_RUN_FAILED"


FORBIDDEN_EXECUTION_TOKENS = (
    "bash",
    "sh",
    "sudo",
    "rm -rf",
    "curl",
    "wget",
    "eval(",
    "exec(",
    "subprocess",
    "chmod",
    "chown",
    "mkfs",
    "dd if=",
)

FORBIDDEN_SECRET_KEYS = (
    "password",
    "secret",
    "private_key",
    "root_token",
    "api_secret",
    "access_token",
)


@dataclass(frozen=True)
class DryRunStep:
    """Ordered deterministic step within an execution plan."""

    order: int
    name: str
    description: str
    target: str
    action: str
    parameters: dict[str, Any] = field(default_factory=dict)
    estimated_duration_sec: float = 5.0
    is_reversible: bool = True
    rollback_step: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "order": self.order,
            "name": self.name,
            "description": self.description,
            "target": self.target,
            "action": self.action,
            "parameters": self.parameters,
            "estimated_duration_sec": self.estimated_duration_sec,
            "is_reversible": self.is_reversible,
            "rollback_step": self.rollback_step,
        }


@dataclass
class ExecutionValidationResult:
    """Result of validating an action before dry-run execution."""

    is_valid: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    checked_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass(frozen=True)
class DryRunPlan:
    """Deterministic dry-run execution plan."""

    action_id: uuid.UUID
    organization_id: uuid.UUID
    action_type: str
    service_id: uuid.UUID
    service_name: str
    environment: str
    executor_type: str
    execution_mode: str
    normalized_parameters: dict[str, Any]
    ordered_steps: list[DryRunStep]
    expected_effects: list[str]
    safety_checks: list[str]
    warnings: list[str]
    plan_hash: str

    def canonical_dict(self) -> dict[str, Any]:
        """Return canonical dictionary for deterministic hashing."""
        return {
            "action_id": str(self.action_id),
            "organization_id": str(self.organization_id),
            "action_type": str(self.action_type),
            "service_id": str(self.service_id),
            "service_name": self.service_name,
            "environment": self.environment,
            "executor_type": str(self.executor_type),
            "execution_mode": str(self.execution_mode),
            "normalized_parameters": self.normalized_parameters,
            "ordered_steps": [s.to_dict() for s in self.ordered_steps],
            "expected_effects": sorted(self.expected_effects),
            "safety_checks": sorted(self.safety_checks),
        }

    @classmethod
    def compute_hash(
        cls,
        action_id: uuid.UUID,
        organization_id: uuid.UUID,
        action_type: str,
        service_id: uuid.UUID,
        service_name: str,
        environment: str,
        executor_type: str,
        execution_mode: str,
        normalized_parameters: dict[str, Any],
        ordered_steps: list[DryRunStep],
        expected_effects: list[str],
        safety_checks: list[str],
    ) -> str:
        """Compute SHA-256 hash across canonical plan representation."""
        payload = {
            "action_id": str(action_id),
            "organization_id": str(organization_id),
            "action_type": str(action_type),
            "service_id": str(service_id),
            "service_name": service_name,
            "environment": environment,
            "executor_type": str(executor_type),
            "execution_mode": str(execution_mode),
            "normalized_parameters": normalized_parameters,
            "ordered_steps": [s.to_dict() for s in ordered_steps],
            "expected_effects": sorted(expected_effects),
            "safety_checks": sorted(safety_checks),
        }
        canonical_str = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": str(self.action_id),
            "organization_id": str(self.organization_id),
            "action_type": self.action_type,
            "service_id": str(self.service_id),
            "service_name": self.service_name,
            "environment": self.environment,
            "executor_type": self.executor_type,
            "execution_mode": self.execution_mode,
            "normalized_parameters": self.normalized_parameters,
            "ordered_steps": [s.to_dict() for s in self.ordered_steps],
            "expected_effects": self.expected_effects,
            "safety_checks": self.safety_checks,
            "warnings": self.warnings,
            "plan_hash": self.plan_hash,
        }


@dataclass
class DryRunResult:
    """Outcome of a dry-run execution."""

    status: DryRunStatus
    action_id: uuid.UUID
    execution_id: uuid.UUID
    plan: DryRunPlan | None
    simulated_outcome: str
    safety_checks_passed: bool
    expected_effects: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    no_real_execution: bool = True
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "action_id": str(self.action_id),
            "execution_id": str(self.execution_id),
            "plan": self.plan.to_dict() if self.plan else None,
            "simulated_outcome": self.simulated_outcome,
            "safety_checks_passed": self.safety_checks_passed,
            "expected_effects": self.expected_effects,
            "warnings": self.warnings,
            "errors": self.errors,
            "no_real_execution": self.no_real_execution,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat(),
        }


class ExecutionValidator:
    """Validates remediation actions and parameters prior to dry-run execution."""

    @staticmethod
    def _inspect_for_forbidden_tokens(data: Any, path: str = "") -> list[str]:
        """Recursively scan parameters for forbidden shell/exec injection tokens."""
        violations: list[str] = []
        if isinstance(data, str):
            lower = data.lower()
            for token in FORBIDDEN_EXECUTION_TOKENS:
                if token in lower:
                    violations.append(f"Forbidden execution token '{token}' detected at {path or 'root'}")
        elif isinstance(data, dict):
            for k, v in data.items():
                current_path = f"{path}.{k}" if path else str(k)
                lower_k = str(k).lower()
                for token in FORBIDDEN_EXECUTION_TOKENS:
                    if token in lower_k:
                        violations.append(f"Forbidden execution token '{token}' in key at {current_path}")
                violations.extend(ExecutionValidator._inspect_for_forbidden_tokens(v, current_path))
        elif isinstance(data, (list, tuple)):
            for idx, item in enumerate(data):
                violations.extend(ExecutionValidator._inspect_for_forbidden_tokens(item, f"{path}[{idx}]"))
        return violations

    @classmethod
    def validate(
        cls,
        action: Any,
        service: Any,
        parameters: dict[str, Any] | None,
        requested_executor_type: str = "SIMULATOR",
        requested_execution_mode: str = "DRY_RUN",
    ) -> ExecutionValidationResult:
        """Perform comprehensive deterministic validation."""
        errors: list[str] = []
        warnings: list[str] = []
        params = parameters or {}

        # 1. Action lifecycle check
        status_val = getattr(action, "status", None)
        if status_val != ActionStatus.APPROVED:
            errors.append(f"Action must be in APPROVED state for execution (currently '{status_val}')")

        # 2. Service compatibility and tenant boundary
        if service is None:
            errors.append("Target service does not exist")
        else:
            if getattr(action, "service_id", None) != getattr(service, "id", None):
                errors.append("Action service_id does not match target service")
            if getattr(action, "organization_id", None) != getattr(service, "organization_id", None):
                errors.append("Cross-tenant service reference is forbidden")

        # 3. Environment safety check
        env = params.get("environment")
        if not env:
            env = getattr(service, "environment", None) if hasattr(service, "environment") else None
        if not env or str(env).upper() in ("UNKNOWN", "NONE"):
            warnings.append("Target service environment is UNKNOWN. Conservative execution simulation applied.")

        # 4. Executor type & execution mode validation
        allowed_executors = {ExecutorType.SIMULATOR, ExecutorType.SYSTEM, ExecutorType.MANUAL}
        try:
            ex_type = ExecutorType(requested_executor_type)
            if ex_type not in allowed_executors:
                errors.append(f"Unsupported executor type: '{requested_executor_type}'")
        except ValueError:
            errors.append(f"Unsupported executor type: '{requested_executor_type}'")

        if requested_execution_mode != ExecutionMode.DRY_RUN:
            errors.append(f"Execution mode '{requested_execution_mode}' is not supported in M10.3 (DRY_RUN only)")

        # 5. Injection & forbidden mechanism scan
        violations = cls._inspect_for_forbidden_tokens(params)
        errors.extend(violations)

        # 6. Action-type specific parameter validation
        action_type = getattr(action, "action_type", None)
        if action_type == ActionType.RESTART_SERVICE:
            grace = params.get("grace_period_seconds", 30)
            if not isinstance(grace, (int, float)) or grace < 0 or grace > 3600:
                errors.append("grace_period_seconds must be a number between 0 and 3600")
            restart_type = params.get("restart_type", "rolling")
            if restart_type not in ("rolling", "immediate"):
                errors.append("restart_type must be 'rolling' or 'immediate'")

        elif action_type == ActionType.SCALE_SERVICE:
            if "replicas" not in params:
                errors.append("SCALE_SERVICE requires 'replicas' parameter")
            else:
                replicas = params.get("replicas")
                if not isinstance(replicas, int) or replicas < 1 or replicas > 50:
                    errors.append("replicas must be an integer between 1 and 50")

        elif action_type == ActionType.ROLLBACK_DEPLOYMENT:
            target_version = params.get("target_version")
            if target_version is not None and (not isinstance(target_version, str) or not target_version.strip()):
                errors.append("target_version must be a non-empty string if provided")

        elif action_type == ActionType.UPDATE_CONFIGURATION:
            config_keys = params.get("config_keys")
            if not config_keys or not isinstance(config_keys, dict):
                errors.append("UPDATE_CONFIGURATION requires non-empty dictionary 'config_keys'")
            else:
                for k in config_keys.keys():
                    for forbidden in FORBIDDEN_SECRET_KEYS:
                        if forbidden in str(k).lower():
                            errors.append(f"Configuration key '{k}' contains forbidden credential token '{forbidden}'")

        elif action_type == ActionType.RUN_DIAGNOSTIC:
            diag_type = params.get("diagnostic_type", "health_check")
            allowed_diags = {"health_check", "metrics_snapshot", "stack_trace", "dependency_ping"}
            if diag_type not in allowed_diags:
                errors.append(f"diagnostic_type must be one of {sorted(allowed_diags)}")
            timeout = params.get("timeout_seconds", 60)
            if not isinstance(timeout, int) or timeout < 1 or timeout > 300:
                errors.append("timeout_seconds must be an integer between 1 and 300")

        return ExecutionValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
        )


class DryRunPlanBuilder:
    """Builds deterministic execution plans for validated remediation actions."""

    @classmethod
    def build_plan(
        cls,
        action: Any,
        service: Any,
        parameters: dict[str, Any] | None,
        warnings: list[str] | None = None,
        executor_type: str = "SIMULATOR",
        execution_mode: str = "DRY_RUN",
    ) -> DryRunPlan:
        """Construct deterministic steps, effects, and calculate plan hash."""
        params = dict(parameters or {})
        action_type = getattr(action, "action_type", None)
        service_name = getattr(service, "name", "unknown-service")
        service_id = getattr(service, "id", action.service_id)
        org_id = getattr(action, "organization_id")
        action_id = getattr(action, "id")
        env = params.get("environment")
        if not env:
            env = getattr(service, "environment", None) if hasattr(service, "environment") else None
        env = str(env or "UNKNOWN")
        plan_warnings = list(warnings or [])

        ordered_steps: list[DryRunStep] = []
        expected_effects: list[str] = []
        safety_checks: list[str] = []
        normalized_params: dict[str, Any] = {}

        if action_type == ActionType.RESTART_SERVICE:
            grace = int(params.get("grace_period_seconds", 30))
            restart_type = str(params.get("restart_type", "rolling"))
            normalized_params = {"grace_period_seconds": grace, "restart_type": restart_type}

            ordered_steps = [
                DryRunStep(
                    order=1,
                    name="pre_restart_health_check",
                    description=f"Verify target service '{service_name}' liveness probes before restart",
                    target=service_name,
                    action="verify_liveness",
                    parameters={"timeout_sec": 5},
                    estimated_duration_sec=5.0,
                    is_reversible=True,
                ),
                DryRunStep(
                    order=2,
                    name="traffic_drain",
                    description=f"Remove '{service_name}' instances from load balancer routing and drain connections",
                    target=service_name,
                    action="drain_traffic",
                    parameters={"grace_period_sec": grace},
                    estimated_duration_sec=float(grace),
                    is_reversible=True,
                    rollback_step="reattach_load_balancer",
                ),
                DryRunStep(
                    order=3,
                    name="issue_terminate_signal",
                    description=f"Send SIGTERM to process group of '{service_name}'",
                    target=service_name,
                    action="send_sigterm",
                    parameters={"signal": "SIGTERM"},
                    estimated_duration_sec=3.0,
                    is_reversible=False,
                ),
                DryRunStep(
                    order=4,
                    name="spawn_service_instances",
                    description=f"Spawn fresh worker processes for '{service_name}'",
                    target=service_name,
                    action="spawn_instances",
                    parameters={"restart_type": restart_type},
                    estimated_duration_sec=10.0,
                    is_reversible=False,
                ),
                DryRunStep(
                    order=5,
                    name="verify_readiness",
                    description=f"Execute readiness probe on newly initialized instances of '{service_name}'",
                    target=service_name,
                    action="verify_readiness",
                    parameters={"retries": 3, "interval_sec": 2},
                    estimated_duration_sec=6.0,
                    is_reversible=True,
                ),
                DryRunStep(
                    order=6,
                    name="restore_traffic_routing",
                    description=f"Re-attach '{service_name}' instances to active routing pool",
                    target=service_name,
                    action="restore_traffic",
                    parameters={},
                    estimated_duration_sec=2.0,
                    is_reversible=True,
                ),
            ]
            expected_effects = [
                "Graceful drainage of in-flight client connections",
                f"Service process group bounced via {restart_type} sequence",
                "Transient replica capacity reduction during restart cycle",
                "Reclamation of leaked memory and reset of open network connections",
            ]
            safety_checks = [
                "Target service catalog registration verified",
                "Minimum healthy replica threshold preserved throughout rolling bounce",
                "Rollback procedure available via load-balancer re-route",
            ]

        elif action_type == ActionType.SCALE_SERVICE:
            replicas = int(params.get("replicas", 2))
            normalized_params = {"replicas": replicas}

            ordered_steps = [
                DryRunStep(
                    order=1,
                    name="query_current_capacity",
                    description=f"Inspect currently active replica count for '{service_name}'",
                    target=service_name,
                    action="query_capacity",
                    parameters={},
                    estimated_duration_sec=2.0,
                    is_reversible=True,
                ),
                DryRunStep(
                    order=2,
                    name="verify_cluster_quota",
                    description="Verify CPU and memory quotas accommodate requested replica allocation",
                    target=service_name,
                    action="verify_quota",
                    parameters={"target_replicas": replicas},
                    estimated_duration_sec=3.0,
                    is_reversible=True,
                ),
                DryRunStep(
                    order=3,
                    name="adjust_replica_target",
                    description=f"Update deployment target replicas to {replicas} for '{service_name}'",
                    target=service_name,
                    action="update_replica_count",
                    parameters={"replicas": replicas},
                    estimated_duration_sec=5.0,
                    is_reversible=True,
                    rollback_step="restore_previous_replica_count",
                ),
                DryRunStep(
                    order=4,
                    name="await_instance_readiness",
                    description="Wait for scaled instances to pass health and readiness checks",
                    target=service_name,
                    action="await_readiness",
                    parameters={"timeout_sec": 30},
                    estimated_duration_sec=15.0,
                    is_reversible=True,
                ),
                DryRunStep(
                    order=5,
                    name="register_routing_endpoints",
                    description=f"Register newly initialized instances of '{service_name}' in routing table",
                    target=service_name,
                    action="register_endpoints",
                    parameters={"replicas": replicas},
                    estimated_duration_sec=2.0,
                    is_reversible=True,
                ),
            ]
            expected_effects = [
                f"Service replica count scaled to {replicas}",
                "Adjusted cluster throughput capacity and resource reservation",
            ]
            safety_checks = [
                "Target replica count strictly within bounds [1..50]",
                "Cluster resource headroom sufficient for requested scaling",
            ]

        elif action_type == ActionType.ROLLBACK_DEPLOYMENT:
            target_version = str(params.get("target_version", "previous-stable"))
            normalized_params = {"target_version": target_version}

            ordered_steps = [
                DryRunStep(
                    order=1,
                    name="verify_target_artifact",
                    description=f"Confirm presence and cryptographic integrity of revision '{target_version}'",
                    target=service_name,
                    action="verify_artifact",
                    parameters={"target_version": target_version},
                    estimated_duration_sec=4.0,
                    is_reversible=True,
                ),
                DryRunStep(
                    order=2,
                    name="create_rollback_release",
                    description=f"Generate rollback deployment manifest targeting revision '{target_version}'",
                    target=service_name,
                    action="create_rollback_manifest",
                    parameters={"target_version": target_version},
                    estimated_duration_sec=3.0,
                    is_reversible=True,
                ),
                DryRunStep(
                    order=3,
                    name="rolling_deploy_rollback",
                    description=f"Deploy revision '{target_version}' using canary/rolling deployment strategy",
                    target=service_name,
                    action="rolling_deploy",
                    parameters={"target_version": target_version},
                    estimated_duration_sec=25.0,
                    is_reversible=True,
                    rollback_step="redeploy_prior_revision",
                ),
                DryRunStep(
                    order=4,
                    name="verify_rollback_health",
                    description=f"Verify telemetry and error budgets on reverted version '{target_version}'",
                    target=service_name,
                    action="verify_telemetry",
                    parameters={},
                    estimated_duration_sec=10.0,
                    is_reversible=True,
                ),
            ]
            expected_effects = [
                f"Service binary and assets reverted to revision '{target_version}'",
                "Traffic redirected to verified prior stable release",
            ]
            safety_checks = [
                "Target release artifact exists and passed vulnerability scans",
                "Database schema backwards compatibility confirmed",
            ]

        elif action_type == ActionType.UPDATE_CONFIGURATION:
            config_keys = dict(params.get("config_keys", {}))
            apply_strat = str(params.get("apply_strategy", "reload"))
            normalized_params = {"config_keys": config_keys, "apply_strategy": apply_strat}

            ordered_steps = [
                DryRunStep(
                    order=1,
                    name="validate_config_schema",
                    description=f"Validate schema and constraints for updated keys: {list(config_keys.keys())}",
                    target=service_name,
                    action="validate_schema",
                    parameters={"keys": list(config_keys.keys())},
                    estimated_duration_sec=2.0,
                    is_reversible=True,
                ),
                DryRunStep(
                    order=2,
                    name="stage_config_update",
                    description="Write updated configuration payload to configuration repository",
                    target=service_name,
                    action="stage_config",
                    parameters={"keys": list(config_keys.keys())},
                    estimated_duration_sec=3.0,
                    is_reversible=True,
                    rollback_step="restore_staged_configuration",
                ),
                DryRunStep(
                    order=3,
                    name="signal_config_reload",
                    description=f"Signal '{service_name}' worker processes to reload configuration",
                    target=service_name,
                    action="signal_reload",
                    parameters={"apply_strategy": apply_strat},
                    estimated_duration_sec=5.0,
                    is_reversible=True,
                ),
                DryRunStep(
                    order=4,
                    name="verify_config_acknowledgement",
                    description=f"Verify '{service_name}' acknowledged new configuration parameters without errors",
                    target=service_name,
                    action="verify_config_ack",
                    parameters={},
                    estimated_duration_sec=4.0,
                    is_reversible=True,
                ),
            ]
            expected_effects = [
                f"Configuration parameters {list(config_keys.keys())} applied via {apply_strat}",
                "Runtime behavior updated without cold process restart",
            ]
            safety_checks = [
                "Configuration parameter syntax and value ranges verified",
                "No forbidden credentials or unencrypted secrets detected in configuration keys",
            ]

        elif action_type == ActionType.RUN_DIAGNOSTIC:
            diag_type = str(params.get("diagnostic_type", "health_check"))
            timeout_sec = int(params.get("timeout_seconds", 60))
            normalized_params = {"diagnostic_type": diag_type, "timeout_seconds": timeout_sec}

            ordered_steps = [
                DryRunStep(
                    order=1,
                    name="initialize_read_only_probe",
                    description=f"Initialize non-intrusive diagnostic probe ({diag_type}) on '{service_name}'",
                    target=service_name,
                    action="init_probe",
                    parameters={"diagnostic_type": diag_type},
                    estimated_duration_sec=2.0,
                    is_reversible=True,
                ),
                DryRunStep(
                    order=2,
                    name="collect_diagnostic_telemetry",
                    description=f"Capture telemetry, thread dump, or metrics snapshot with {timeout_sec}s timeout",
                    target=service_name,
                    action="collect_telemetry",
                    parameters={"timeout_sec": timeout_sec},
                    estimated_duration_sec=float(min(timeout_sec, 15)),
                    is_reversible=True,
                ),
                DryRunStep(
                    order=3,
                    name="aggregate_evidence_artifact",
                    description="Aggregate captured diagnostic output and prepare evidence attachment",
                    target=service_name,
                    action="compile_evidence",
                    parameters={},
                    estimated_duration_sec=3.0,
                    is_reversible=True,
                ),
            ]
            expected_effects = [
                f"Diagnostic telemetry ({diag_type}) collected without service disruption",
                "Zero state mutations or database changes applied",
            ]
            safety_checks = [
                "Diagnostic probe is strictly read-only and non-invasive",
                f"Probe execution timeout capped at {timeout_sec}s",
            ]

        plan_hash = DryRunPlan.compute_hash(
            action_id=action_id,
            organization_id=org_id,
            action_type=action_type,
            service_id=service_id,
            service_name=service_name,
            environment=env,
            executor_type=executor_type,
            execution_mode=execution_mode,
            normalized_parameters=normalized_params,
            ordered_steps=ordered_steps,
            expected_effects=expected_effects,
            safety_checks=safety_checks,
        )

        return DryRunPlan(
            action_id=action_id,
            organization_id=org_id,
            action_type=action_type,
            service_id=service_id,
            service_name=service_name,
            environment=env,
            executor_type=executor_type,
            execution_mode=execution_mode,
            normalized_parameters=normalized_params,
            ordered_steps=ordered_steps,
            expected_effects=expected_effects,
            safety_checks=safety_checks,
            warnings=plan_warnings,
            plan_hash=plan_hash,
        )
