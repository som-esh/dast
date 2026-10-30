"""ASVP GitHub Action entrypoint (FR-GTE-3).

Requests a scan against the ASVP control plane, polls for the verdict
(AR-2: request + poll, never a blocking call), writes a PR-comment summary
(FR-DX-2: top findings + deep links, never a wall), and exits non-zero when
the gate blocks. Pure stdlib so the action needs no extra install.
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request


def _api(method: str, path: str, body: dict | None = None) -> dict:
    url = os.environ["ASVP_URL"].rstrip("/") + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {os.environ['ASVP_TOKEN']}")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read() or "{}")
    except urllib.error.HTTPError as exc:
        sys.stderr.write(f"ASVP API error {exc.code}: {exc.read().decode()}\n")
        raise


def _set_output(name: str, value: str) -> None:
    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a", encoding="utf-8") as fh:
            fh.write(f"{name}={value}\n")


def _write_pr_comment(markdown: str) -> None:
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(markdown + "\n")
    # Posting an actual PR review comment would use the GitHub API with
    # GITHUB_TOKEN here; the step summary is the always-available surface.


def main() -> int:
    changed = [e.strip() for e in os.environ.get("ASVP_CHANGED", "").split(",") if e.strip()]
    request = {
        "service": os.environ["ASVP_SERVICE"],
        "spec_version": "latest",
        "environment": os.environ["ASVP_ENVIRONMENT"],
        "profile": os.environ["ASVP_PROFILE"],
        "mode": os.environ.get("ASVP_MODE", "safe"),
        "scope_endpoints": changed,
        "commit_sha": os.environ.get("ASVP_COMMIT_SHA"),
    }
    if os.environ.get("ASVP_TARGET_OVERRIDE"):
        request["target_url_override"] = os.environ["ASVP_TARGET_OVERRIDE"]

    submitted = _api("POST", "/api/v1/scans", request)
    scan_id = submitted["scan_id"]
    _set_output("scan_id", scan_id)
    print(f"ASVP scan requested: {scan_id}")

    deadline = time.time() + int(os.environ.get("ASVP_TIMEOUT", "600"))
    status = {}
    while time.time() < deadline:
        status = _api("GET", f"/api/v1/scans/{scan_id}")
        if status["state"] in ("complete", "failed"):
            break
        time.sleep(3)
    else:
        sys.stderr.write("ASVP scan did not complete within the timeout budget.\n")
        return 1

    if status["state"] == "failed":
        sys.stderr.write(f"ASVP scan failed: {status.get('error')}\n")
        return 1

    comment = _api("GET", f"/api/v1/scans/{scan_id}/pr-comment").get("markdown", "")
    _write_pr_comment(comment)
    print(comment)

    verdict = (status.get("gate_verdict") or {}).get("verdict", "pass")
    _set_output("verdict", verdict)
    if verdict == "block":
        sys.stderr.write("ASVP gate verdict: BLOCK — failing the pipeline.\n")
        return 1
    print(f"ASVP gate verdict: {verdict.upper()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
