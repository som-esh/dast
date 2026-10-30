"""Nuclei adapter (AR-3).

Runs ProjectDiscovery's Nuclei against the target and parses its JSONL
output into normalized findings. Configure with ASVP_NUCLEI_PATH.

    nuclei -u <target> -jsonl -silent [-H "Authorization: Bearer ..."]

`parse_jsonl` is pure and unit-tested against captured Nuclei output.
"""

from __future__ import annotations

import json
import os
import shutil
from typing import Optional

from asvp.config import get_config
from asvp.engine.adapters.base import (
    ExternalEngine,
    RawFinding,
    Runner,
    normalize_severity,
)


class NucleiAdapter(ExternalEngine):
    name = "nuclei"
    destructiveness = "aggressive"

    def __init__(self, path: Optional[str] = None, runner: Optional[Runner] = None):
        super().__init__(runner)
        self._path = path or get_config().nuclei_path or ""

    def is_available(self) -> bool:
        if not self._path:
            return False
        return os.path.exists(self._path) or shutil.which(self._path) is not None

    def build_command(
        self, target_url: str, headers: Optional[dict[str, str]] = None
    ) -> list[str]:
        cmd = [self._path, "-u", target_url, "-jsonl", "-silent"]
        for key, value in (headers or {}).items():
            cmd += ["-H", f"{key}: {value}"]
        return cmd

    @staticmethod
    def parse_jsonl(text: str) -> list[RawFinding]:
        findings: list[RawFinding] = []
        for line in (text or "").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except ValueError:
                continue
            info = row.get("info", {})
            matched = row.get("matched-at") or row.get("host") or ""
            method = "GET"  # nuclei http matches are surfaced at the matched URL
            findings.append(
                RawFinding(
                    engine="nuclei",
                    rule_id=row.get("template-id", "unknown"),
                    title=info.get("name", row.get("template-id", "Nuclei match")),
                    severity=normalize_severity(info.get("severity", "info")),
                    endpoint_id=f"{method} {_path(matched)}" if matched else "unknown",
                    parameter="",
                    description=info.get("description", ""),
                    remediation=info.get("remediation", ""),
                    evidence={
                        "matched_at": matched,
                        "matcher_name": row.get("matcher-name", ""),
                        "extracted": row.get("extracted-results", []),
                        "tags": info.get("tags", []),
                    },
                    compliance_mappings=_classification_to_mappings(info.get("classification", {})),
                )
            )
        return findings

    async def scan(
        self, target_url: str, headers: Optional[dict[str, str]] = None
    ) -> list[RawFinding]:
        if not self.is_available():
            return []
        cmd = self.build_command(target_url, headers)
        _, stdout, _ = await self._runner(
            cmd, timeout=get_config().external_engine_timeout_seconds
        )
        return self.parse_jsonl(stdout)


def _path(matched: str) -> str:
    from urllib.parse import urlparse

    parsed = urlparse(matched)
    return parsed.path or "/"


def _classification_to_mappings(classification: dict) -> list[str]:
    out = []
    for cve in classification.get("cve-id", []) or []:
        out.append(str(cve).upper())
    for cwe in classification.get("cwe-id", []) or []:
        out.append(str(cwe).upper())
    return out
