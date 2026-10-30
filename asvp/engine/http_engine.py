"""Built-in HTTP probe engine implementing the ScanWorker seam (AR-3)."""

from __future__ import annotations

from asvp.checks.generator import PlannedCheck
from asvp.engine.executors import EXECUTORS
from asvp.engine.worker import CheckResult, ExecutionContext, ScanWorker


class HttpProbeEngine(ScanWorker):
    name = "asvp-http-probe"

    async def execute(self, check: PlannedCheck, ctx: ExecutionContext) -> CheckResult:
        executor = EXECUTORS.get(check.template.executor)
        if executor is None:
            return CheckResult(
                status="error",
                detail=f"no executor registered for '{check.template.executor}'",
            )
        try:
            return await executor(check, ctx)
        except Exception as exc:  # engine errors must never kill the scan
            return CheckResult(
                status="error",
                detail=f"executor raised {type(exc).__name__}: {exc}",
            )
