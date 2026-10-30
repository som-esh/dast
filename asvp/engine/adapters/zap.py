"""OWASP ZAP adapter (AR-3).

Runs ZAP's baseline/quick scan in headless command mode and parses the JSON
report into normalized findings. Configure with ASVP_ZAP_PATH pointing at
zap.sh / zap.bat / the ZAP binary.

    zap.sh -cmd -quickurl <target> -quickout report.json -quickprogress

The report parser (`parse_report`) is pure and unit-tested against captured
ZAP output, so the normalization is verified without ZAP installed.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from typing import Optional

from asvp.config import get_config
from asvp.engine.adapters.base import (
    ExternalEngine,
    RawFinding,
    Runner,
    normalize_severity,
)


class ZapAdapter(ExternalEngine):
    name = "zap"
    destructiveness = "aggressive"

    def __init__(self, path: Optional[str] = None, runner: Optional[Runner] = None):
        super().__init__(runner)
        self._path = path or get_config().zap_path or ""

    def is_available(self) -> bool:
        if not self._path:
            return False
        return os.path.exists(self._path) or shutil.which(self._path) is not None

    def build_command(self, target_url: str, outfile: str) -> list[str]:
        return [
            self._path,
            "-cmd",
            "-quickurl", target_url,
            "-quickout", outfile,
            "-quickprogress",
        ]

    @staticmethod
    def parse_report(text: str) -> list[RawFinding]:
        try:
            data = json.loads(text)
        except (ValueError, TypeError):
            return []
        findings: list[RawFinding] = []
        for site in data.get("site", []):
            for alert in site.get("alerts", []):
                rule_id = str(alert.get("pluginid", alert.get("alertRef", "0")))
                severity = normalize_severity(alert.get("riskdesc", alert.get("riskcode", "")))
                title = alert.get("alert", alert.get("name", "ZAP alert"))
                desc = alert.get("desc", "")
                solution = alert.get("solution", "")
                instances = alert.get("instances") or [{}]
                for inst in instances:
                    method = (inst.get("method") or "GET").upper()
                    uri = inst.get("uri") or site.get("@name", "")
                    path = _uri_path(uri)
                    findings.append(
                        RawFinding(
                            engine="zap",
                            rule_id=rule_id,
                            title=title,
                            severity=severity,
                            endpoint_id=f"{method} {path}" if path else uri,
                            parameter=inst.get("param", ""),
                            description=_strip_html(desc),
                            remediation=_strip_html(solution),
                            evidence={
                                "uri": uri,
                                "attack": inst.get("attack", ""),
                                "evidence": inst.get("evidence", ""),
                                "cweid": alert.get("cweid"),
                                "wascid": alert.get("wascid"),
                            },
                        )
                    )
        return findings

    async def scan(
        self, target_url: str, headers: Optional[dict[str, str]] = None
    ) -> list[RawFinding]:
        if not self.is_available():
            return []
        with tempfile.TemporaryDirectory(prefix="asvp-zap-") as tmp:
            outfile = os.path.join(tmp, "zap-report.json")
            cmd = self.build_command(target_url, outfile)
            _, stdout, _ = await self._runner(
                cmd, cwd=tmp, timeout=get_config().external_engine_timeout_seconds
            )
            if os.path.exists(outfile):
                with open(outfile, "r", encoding="utf-8", errors="replace") as fh:
                    report = fh.read()
            else:
                report = stdout  # injected/streamed report path (tests)
            return self.parse_report(report)


def _uri_path(uri: str) -> str:
    from urllib.parse import urlparse

    parsed = urlparse(uri)
    return parsed.path or "/"


def _strip_html(text: str) -> str:
    import re

    return re.sub(r"<[^>]+>", "", text or "").strip()
