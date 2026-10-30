"""API crawler / spider endpoint discovery."""

from __future__ import annotations

import unittest

import httpx
from starlette.applications import Starlette
from starlette.responses import JSONResponse, HTMLResponse
from starlette.routing import Route

from asvp.engine.crawler import ApiCrawler
from asvp.models.scan import ScanRequest
from tests.conftest import DEMO_COLLECTION, make_platform, tier1_service


# ── a target that advertises an OpenAPI doc and links undocumented routes ──

OPENAPI = {
    "openapi": "3.0.0",
    "info": {"title": "discovered"},
    "paths": {
        "/api/v1/orders": {"get": {"operationId": "listOrders"}},
        "/api/v1/orders/{order_id}": {
            "get": {"operationId": "getOrder",
                    "parameters": [{"name": "order_id", "in": "path", "required": True}]}
        },
    },
}


async def home(request):
    return HTMLResponse('<a href="/legacy/admin">admin</a> <a href="/api/v1/orders">orders</a>')


async def openapi_doc(request):
    return JSONResponse(OPENAPI)


async def legacy_admin(request):
    return JSONResponse({"ok": True})


async def orders(request):
    return JSONResponse([])


def build_app() -> Starlette:
    return Starlette(routes=[
        Route("/", home),
        Route("/openapi.json", openapi_doc),
        Route("/legacy/admin", legacy_admin),
        Route("/api/v1/orders", orders),
    ])


def crawler_client_factory() -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=build_app()), timeout=10.0)


class TestCrawler(unittest.IsolatedAsyncioTestCase):
    async def test_discovers_openapi_and_links(self):
        crawler = ApiCrawler(crawler_client_factory, max_urls=50, max_depth=2)
        result = await crawler.crawl("http://svc.local")
        ids = {e.endpoint_id for e in result.endpoints}
        # from the OpenAPI doc
        self.assertIn("GET /api/v1/orders/{order_id}", ids)
        # undocumented route discovered via spidering the homepage link
        self.assertIn("GET /legacy/admin", ids)
        self.assertIsNotNone(result.openapi_source)
        self.assertTrue(all(e.discovered for e in result.endpoints))

    async def test_crawler_merges_into_scan_scope(self):
        platform = make_platform(client_factory_override=crawler_client_factory)
        await platform.orchestrator.start(runner_count=2)
        svc = tier1_service()
        svc.environment_urls["staging"] = "http://svc.local"
        svc.crawl_enabled = True
        platform.registry.register(svc)
        platform.ingest_spec(DEMO_COLLECTION, "payments-api")
        req = ScanRequest(service="payments-api", spec_version="latest",
                          environment="staging", profile="qa", mode="safe",
                          enable_crawler=True)
        status = await platform.orchestrator.submit(req)
        status = await platform.orchestrator.wait(status.scan_id, timeout=60)
        self.assertTrue(status.discovered_endpoints)
        self.assertIn("GET /legacy/admin", status.discovered_endpoints)
        await platform.close()


if __name__ == "__main__":
    unittest.main()
