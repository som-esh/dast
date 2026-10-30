"""API web crawler / spider — endpoint discovery.

Discovers API endpoints reachable from a base URL so the platform can:
  - surface undocumented endpoints responding at the gateway (improper
    inventory cue, OWASP API9; feeds coverage %, FR-ING-6),
  - widen scan coverage beyond what the Postman/OpenAPI source declares.

Discovery strategy, in order:
  1. Fetch well-known API description documents (OpenAPI/Swagger) and parse
     them into canonical endpoints.
  2. Breadth-first spider from the base URL, extracting URL-like references
     from HTML (href/src/action) and JSON response bodies, staying on-host,
     GET-only, bounded by max-urls and max-depth.
  3. Probe a small set of common API/management paths.

The crawler is read-only and GET-only by construction — destructiveness
class "safe". It never submits forms or mutates state.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Optional
from urllib.parse import urljoin, urlparse

import httpx

from asvp.config import get_config
from asvp.ingestion.openapi import parse_openapi_spec
from asvp.models.canonical import Endpoint

_OPENAPI_DISCOVERY_PATHS = (
    "/openapi.json",
    "/openapi.yaml",
    "/swagger.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/api-docs",
    "/swagger/v1/swagger.json",
)

_COMMON_API_PATHS = (
    "/api",
    "/api/v1",
    "/api/v2",
    "/health",
    "/healthz",
    "/status",
    "/metrics",
    "/actuator",
    "/graphql",
    "/.well-known/security.txt",
)

# URL-like references in HTML attributes and JSON string values.
_HREF_RE = re.compile(r"""(?:href|src|action)\s*=\s*["']([^"']+)["']""", re.I)
_JSON_URL_RE = re.compile(r'"((?:https?://|/)[^"\s]{1,200})"')


@dataclass
class CrawlResult:
    base_url: str
    discovered_urls: list[str] = field(default_factory=list)
    endpoints: list[Endpoint] = field(default_factory=list)
    openapi_source: Optional[str] = None
    fetched: int = 0


class ApiCrawler:
    def __init__(
        self,
        client_factory: Callable[[], httpx.AsyncClient],
        max_urls: Optional[int] = None,
        max_depth: Optional[int] = None,
    ):
        cfg = get_config()
        self._client_factory = client_factory
        self._max_urls = max_urls or cfg.crawler_max_urls
        self._max_depth = max_depth or cfg.crawler_max_depth

    async def crawl(
        self, base_url: str, headers: Optional[dict[str, str]] = None
    ) -> CrawlResult:
        result = CrawlResult(base_url=base_url)
        base_host = urlparse(base_url).netloc
        seen_paths: set[str] = set()

        async with self._client_factory() as client:
            # 1. OpenAPI/Swagger discovery
            for disc in _OPENAPI_DISCOVERY_PATHS:
                url = urljoin(base_url, disc)
                spec = await self._fetch_json(client, url, headers)
                if spec and ("paths" in spec or "swagger" in spec or "openapi" in spec):
                    api = parse_openapi_spec(spec, "discovered")
                    for ep in api.endpoints:
                        ep.discovered = True
                        if ep.endpoint_id not in seen_paths:
                            seen_paths.add(ep.endpoint_id)
                            result.endpoints.append(ep)
                    result.openapi_source = url
                    break

            # 2. BFS spider
            frontier: list[tuple[str, int]] = [(base_url, 0)]
            visited: set[str] = set()
            while frontier and result.fetched < self._max_urls:
                url, depth = frontier.pop(0)
                if url in visited or depth > self._max_depth:
                    continue
                visited.add(url)
                resp = await self._fetch(client, url, headers)
                if resp is None:
                    continue
                result.fetched += 1
                if resp.status_code < 400:
                    self._record_endpoint(url, base_host, seen_paths, result)
                for ref in self._extract_urls(resp):
                    absolute = urljoin(url, ref)
                    if urlparse(absolute).netloc == base_host and absolute not in visited:
                        frontier.append((absolute, depth + 1))

            # 3. Common-path probing
            for path in _COMMON_API_PATHS:
                if result.fetched >= self._max_urls:
                    break
                url = urljoin(base_url, path)
                resp = await self._fetch(client, url, headers)
                if resp is not None:
                    result.fetched += 1
                    if resp.status_code < 400:
                        self._record_endpoint(url, base_host, seen_paths, result)

        return result

    # ── helpers ──────────────────────────────────────────────────────────

    def _record_endpoint(
        self, url: str, base_host: str, seen: set[str], result: CrawlResult
    ) -> None:
        path = urlparse(url).path or "/"
        endpoint_id = f"GET {path}"
        if url not in result.discovered_urls:
            result.discovered_urls.append(url)
        if endpoint_id not in seen:
            seen.add(endpoint_id)
            result.endpoints.append(
                Endpoint(method="GET", path=path, name="(discovered)", discovered=True)
            )

    @staticmethod
    def _extract_urls(resp: httpx.Response) -> list[str]:
        ctype = resp.headers.get("content-type", "")
        text = resp.text[:200_000]
        refs: list[str] = []
        if "html" in ctype or "<" in text[:200]:
            refs += _HREF_RE.findall(text)
        if "json" in ctype or text.strip().startswith(("{", "[")):
            refs += [m for m in _JSON_URL_RE.findall(text) if "/" in m]
        # Keep only path-ish refs; drop assets and anchors.
        out = []
        for r in refs:
            if r.startswith(("#", "mailto:", "javascript:", "tel:")):
                continue
            if r.lower().endswith((".css", ".js", ".png", ".jpg", ".svg", ".ico", ".woff", ".woff2")):
                continue
            out.append(r)
        return out

    async def _fetch(
        self, client: httpx.AsyncClient, url: str, headers: Optional[dict]
    ) -> Optional[httpx.Response]:
        try:
            return await client.get(url, headers=headers, follow_redirects=True)
        except httpx.HTTPError:
            return None

    async def _fetch_json(
        self, client: httpx.AsyncClient, url: str, headers: Optional[dict]
    ) -> Optional[dict]:
        resp = await self._fetch(client, url, headers)
        if resp is None or resp.status_code >= 400:
            return None
        try:
            data = resp.json()
            return data if isinstance(data, dict) else None
        except ValueError:
            # Try YAML for openapi.yaml
            try:
                import yaml

                data = yaml.safe_load(resp.text)
                return data if isinstance(data, dict) else None
            except Exception:
                return None
