"""A deliberately-vulnerable demo target service.

Stands in for a non-production microservice so the engine has a real target
to exercise. It is mounted into the test HTTP client via httpx ASGITransport
(no socket, no port) so the demo and tests run hermetically — and so the
production-CIDR guard and NetworkPolicy posture are never even approached.

The vulnerabilities here are intentional and map to the check library:
  - BOLA: /accounts/{id} returns any account regardless of caller
  - missing auth on /accounts (no token required)
  - excessive data exposure (password_hash in the response)
  - mass assignment (honors is_admin from the body)
  - verbose errors (stack-trace-like body)
  - no rate limiting, permissive CORS, missing security headers
"""

from __future__ import annotations

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.routing import Route

_ACCOUNTS = {
    "1001": {"id": "1001", "owner": "alice", "balance": 500, "password_hash": "x7f3..."},
    "2002": {"id": "2002", "owner": "bob", "balance": 25, "password_hash": "a91b..."},
}


async def list_accounts(request: Request) -> Response:
    # Vulnerable: no authentication enforced.
    return JSONResponse(list(_ACCOUNTS.values()))


async def get_account(request: Request) -> Response:
    # Vulnerable: BOLA — no ownership check, returns any account; and leaks
    # password_hash (excessive data exposure).
    acc_id = request.path_params["account_id"]
    acc = _ACCOUNTS.get(acc_id)
    if not acc:
        # Vulnerable: verbose error.
        return PlainTextResponse(
            "Traceback (most recent call last):\n  File \"/srv/app/db.py\", line 42\n"
            "psycopg2.errors.UndefinedTable: relation does not exist",
            status_code=500,
        )
    return JSONResponse(acc)


async def create_transfer(request: Request) -> Response:
    body = await request.json()
    # Vulnerable: mass assignment — honors is_admin from the request body.
    resp = {"id": "txn-1", "amount": body.get("amount", 0), "is_admin": body.get("is_admin", False)}
    return JSONResponse(resp, status_code=200)


async def admin_config(request: Request) -> Response:
    # Vulnerable: BFLA — privileged endpoint with no role enforcement.
    return JSONResponse({"feature_flags": {"debug": True}})


async def health(request: Request) -> Response:
    return JSONResponse({"status": "ok"})


def build_vulnerable_app() -> Starlette:
    return Starlette(
        routes=[
            Route("/", health),
            Route("/accounts", list_accounts, methods=["GET"]),
            Route("/accounts/{account_id}", get_account, methods=["GET"]),
            Route("/transfers", create_transfer, methods=["POST"]),
            Route("/admin/config", admin_config, methods=["GET"]),
        ]
    )
