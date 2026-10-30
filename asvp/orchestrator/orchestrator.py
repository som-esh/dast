"""Scan orchestrator (AR-2, AR-7, FR-EXE-1..8).

Queue-based asynchronous execution: CI integrates via request + webhook or
status polling, never a blocking synchronous call. Per-environment
concurrency caps and per-target requests/sec throttling are enforced here,
regardless of worker-pool size.

In the production deployment each dequeued scan becomes a K8s Job in the
isolated worker namespace (AR-4); here it becomes an asyncio task executing
the same worker interface, with the production-CIDR guard applied before
any traffic is sent.
"""

from __future__ import annotations

import asyncio
from typing import Awaitable, Callable, Optional

import httpx

from asvp.checks.generator import CheckGenerator, GenerationResult, PlannedCheck
from asvp.config import get_config
from asvp.engine.adapters.base import ExternalEngine, RawFinding
from asvp.engine.crawler import ApiCrawler
from asvp.engine.worker import (
    CheckResult,
    ExecutionContext,
    ScanWorker,
    assert_target_allowed,
    resolve_identities,
)
from asvp.ingestion.store import SpecStore
from asvp.integrations.secrets import SecretsManager
from asvp.models.scan import ScanRequest, ScanStatus
from asvp.registry import ServiceRegistry
from asvp.storage import Store

CompletionHook = Callable[
    [
        ScanStatus,
        list[tuple[PlannedCheck, CheckResult]],
        GenerationResult,
        list[RawFinding],
    ],
    Awaitable[None],
]


class Throttle:
    """Per-target token spacing — caps requests/sec to one target env."""

    def __init__(self, rps: float):
        self._interval = 1.0 / max(rps, 0.1)
        self._lock = asyncio.Lock()
        self._next_slot = 0.0

    async def acquire(self) -> None:
        async with self._lock:
            loop = asyncio.get_running_loop()
            now = loop.time()
            wait = max(0.0, self._next_slot - now)
            self._next_slot = max(now, self._next_slot) + self._interval
        if wait > 0:
            await asyncio.sleep(wait)


class Orchestrator:
    def __init__(
        self,
        store: Store,
        spec_store: SpecStore,
        registry: ServiceRegistry,
        generator: CheckGenerator,
        worker: ScanWorker,
        secrets: SecretsManager,
        on_complete: Optional[CompletionHook] = None,
        client_factory: Optional[Callable[[], httpx.AsyncClient]] = None,
        target_rps: Optional[float] = None,
        external_engines: Optional[dict[str, ExternalEngine]] = None,
    ):
        cfg = get_config()
        self._store = store
        self._spec_store = spec_store
        self._registry = registry
        self._generator = generator
        self._worker = worker
        self._secrets = secrets
        self._on_complete = on_complete
        self._client_factory = client_factory or (
            lambda: httpx.AsyncClient(timeout=cfg.request_timeout_seconds)
        )
        self._target_rps = target_rps or cfg.default_target_rps
        self._external_engines = external_engines or {}
        self._crawler = ApiCrawler(self._client_factory)
        self._queue: asyncio.Queue[str] = asyncio.Queue()
        self._platform_sem = asyncio.Semaphore(cfg.max_concurrent_scans_platform)
        self._env_sems: dict[str, asyncio.Semaphore] = {}
        self._done_events: dict[str, asyncio.Event] = {}
        self._runners: list[asyncio.Task] = []
        self._started = False

    # ── lifecycle ───────────────────────────────────────────────────────

    async def start(self, runner_count: int = 8) -> None:
        if self._started:
            return
        self._started = True
        self._runners = [
            asyncio.create_task(self._runner_loop()) for _ in range(runner_count)
        ]

    async def stop(self) -> None:
        for t in self._runners:
            t.cancel()
        self._runners = []
        self._started = False

    # ── public API (FR-EXE-1, FR-EXE-5, FR-EXE-8) ───────────────────────

    async def submit(self, request: ScanRequest) -> ScanStatus:
        service = self._registry.get(request.service)
        if service is None:
            raise KeyError(f"service '{request.service}' is not onboarded")
        status = ScanStatus(request=request)
        self._save(status)
        self._store.append_event(
            "scan.requested", "scans", status.scan_id,
            request.model_dump(mode="json"), actor=request.requested_by,
        )
        self._done_events[status.scan_id] = asyncio.Event()
        await self._queue.put(status.scan_id)
        return status

    def get_status(self, scan_id: str) -> Optional[ScanStatus]:
        doc = self._store.get("scans", scan_id)
        return ScanStatus.model_validate(doc) if doc else None

    async def wait(self, scan_id: str, timeout: float = 300.0) -> ScanStatus:
        event = self._done_events.get(scan_id)
        if event is not None:
            await asyncio.wait_for(event.wait(), timeout=timeout)
        return self.get_status(scan_id)

    async def rerun_single_check(
        self, original: ScanRequest, check_id: str, endpoint_id: str
    ) -> ScanStatus:
        """FR-EXE-8 / FR-FND-4: fix-verification primitive."""
        request = original.model_copy(
            update={
                "only_check_id": check_id,
                "scope_endpoints": [endpoint_id] if endpoint_id != "(service)" else [],
                "requested_by": "fix-verification",
            }
        )
        status = await self.submit(request)
        return await self.wait(status.scan_id)

    # ── internals ───────────────────────────────────────────────────────

    def _save(self, status: ScanStatus) -> None:
        self._store.put("scans", status.scan_id, status.model_dump(mode="json"))

    def _env_sem(self, environment: str) -> asyncio.Semaphore:
        if environment not in self._env_sems:
            self._env_sems[environment] = asyncio.Semaphore(
                get_config().default_env_concurrency_cap
            )
        return self._env_sems[environment]

    async def _runner_loop(self) -> None:
        while True:
            scan_id = await self._queue.get()
            try:
                await self._run_scan(scan_id)
            except Exception as exc:
                status = self.get_status(scan_id)
                if status:
                    status.state = "failed"
                    status.error = f"{type(exc).__name__}: {exc}"
                    self._save(status)
            finally:
                event = self._done_events.get(scan_id)
                if event:
                    event.set()
                await self._notify_webhook(scan_id)
                self._queue.task_done()

    async def _run_scan(self, scan_id: str) -> None:
        status = self.get_status(scan_id)
        request = status.request
        service = self._registry.get(request.service)
        api = self._spec_store.get(request.service, request.spec_version)
        if api is None:
            raise RuntimeError(
                f"no spec for service '{request.service}' version '{request.spec_version}'"
            )

        target = request.target_url_override or service.environment_urls.get(
            request.environment
        )
        if not target:
            raise RuntimeError(
                f"no target URL configured for environment '{request.environment}'"
            )
        assert_target_allowed(target)  # AR-4 guard

        status.state = "running"
        from datetime import datetime, timezone

        status.started_at = datetime.now(timezone.utc).isoformat()
        self._save(status)

        identities = resolve_identities(service, self._secrets)
        auth_header = (
            {"Authorization": f"Bearer {identities[0].token}"} if identities else None
        )

        results: list[tuple[PlannedCheck, CheckResult]] = []
        external_findings: list[RawFinding] = []
        async with self._platform_sem, self._env_sem(request.environment):
            # ── crawler / spider pass (endpoint discovery) ──────────────
            scan_api = api
            crawl_enabled = (
                request.enable_crawler
                if request.enable_crawler is not None
                else service.crawl_enabled
            )
            # Crawler is GET-only/"safe" but is a full-suite activity; skip it
            # for single-check fix verification.
            if crawl_enabled and not request.only_check_id:
                crawl = await self._crawler.crawl(target, headers=auth_header)
                known = {e.endpoint_id for e in api.endpoints}
                new_eps = [e for e in crawl.endpoints if e.endpoint_id not in known]
                if new_eps:
                    scan_api = api.model_copy(deep=True)
                    scan_api.endpoints.extend(new_eps)
                status.discovered_endpoints = [e.endpoint_id for e in new_eps]
                self._store.append_event(
                    "scan.crawled", "scans", scan_id,
                    {"fetched": crawl.fetched, "discovered": len(new_eps),
                     "openapi_source": crawl.openapi_source},
                )

            generation = self._generator.generate(
                scan_api, service,
                environment=request.environment,
                mode=request.mode,
                scope_endpoints=request.scope_endpoints or None,
                only_check_id=request.only_check_id,
            )
            status.checks_planned = len(generation.checks)
            status.coverage_gaps = generation.coverage_gaps
            self._save(status)
            self._store.append_event(
                "scan.started", "scans", scan_id,
                {"checks_planned": status.checks_planned, "target": target},
            )

            # ── built-in HTTP probe engine ──────────────────────────────
            throttle = Throttle(self._target_rps)
            async with self._client_factory() as client:
                ctx = ExecutionContext(
                    base_url=target,
                    client=client,
                    service=service,
                    identities=identities,
                )
                ctx.throttle = throttle  # consumed by executors' _send
                for check in generation.checks:
                    result = await self._worker.execute(check, ctx)
                    results.append((check, result))
                    status.checks_executed += 1
                    if result.status == "fail":
                        status.checks_failed += 1

            # ── external engine passes (ZAP / Nuclei / Burp) ────────────
            external_findings = await self._run_external_engines(
                status, service, target, auth_header
            )

        status.state = "complete"
        status.finished_at = datetime.now(timezone.utc).isoformat()
        self._save(status)
        self._store.append_event(
            "scan.completed", "scans", scan_id,
            {
                "executed": status.checks_executed,
                "failed": status.checks_failed,
                "coverage_gaps": len(status.coverage_gaps),
                "engines_run": status.engines_run,
                "discovered": len(status.discovered_endpoints),
            },
        )

        if self._on_complete is not None:
            await self._on_complete(status, results, generation, external_findings)
            self._save(status)  # hook may attach findings / gate verdict

    async def _run_external_engines(
        self, status: ScanStatus, service, target: str, auth_header
    ) -> list[RawFinding]:
        request = status.request
        if request.only_check_id:  # fix verification re-runs one built-in check
            return []
        engine_names = (
            request.external_engines
            if request.external_engines is not None
            else service.external_engines
        )
        if not engine_names:
            return []
        allowed = (
            ["safe"]
            if request.mode == "safe"
            else service.allowed_destructiveness(request.environment)
        )
        findings: list[RawFinding] = []
        for name in engine_names:
            engine = self._external_engines.get(name)
            if engine is None:
                status.engines_skipped.append(f"{name} (not registered)")
                continue
            if engine.destructiveness not in allowed:
                status.engines_skipped.append(
                    f"{name} ({engine.destructiveness} not allowed in "
                    f"{request.mode} mode on '{request.environment}')"
                )
                continue
            if not engine.is_available():
                status.engines_skipped.append(f"{name} (binary/jar not configured)")
                continue
            try:
                raw = await engine.scan(target, headers=auth_header)
            except Exception as exc:  # an engine failure must not kill the scan
                status.engines_skipped.append(f"{name} (error: {type(exc).__name__})")
                self._store.append_event(
                    "scan.engine_error", "scans", status.scan_id,
                    {"engine": name, "error": str(exc)},
                )
                continue
            status.engines_run.append(name)
            findings.extend(raw)
            self._store.append_event(
                "scan.engine_completed", "scans", status.scan_id,
                {"engine": name, "findings": len(raw)},
            )
        return findings

    async def _notify_webhook(self, scan_id: str) -> None:
        """FR-EXE-5: webhook callbacks (best-effort)."""
        status = self.get_status(scan_id)
        if not status or not status.request.webhook_url:
            return
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                await client.post(
                    status.request.webhook_url,
                    json={
                        "scan_id": status.scan_id,
                        "state": status.state,
                        "checks_failed": status.checks_failed,
                        "gate_verdict": status.gate_verdict,
                    },
                )
        except httpx.HTTPError:
            pass  # poll API remains the fallback
