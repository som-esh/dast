"""Burp Suite adapter (AR-3) — jar-based.

Burp Suite ships as a runnable jar. Drop the jar in and point ASVP_BURP_JAR
at it (and ASVP_JAVA_PATH at a JRE if `java` is not on PATH):

    ASVP_BURP_JAR=/opt/burp/burpsuite_pro.jar
    ASVP_JAVA_PATH=/usr/bin/java

The adapter launches Burp headlessly to scan the target and export issues as
Burp's standard XML issue report, then parses that into normalized findings:

    java -jar burpsuite_pro.jar --headless \
         --target=<url> --report-file=issues.xml --report-format=xml

Headless scan orchestration varies by Burp edition (Professional driver vs
Enterprise REST API); the launch flags above are config-driven via
`extra_args` so the same adapter covers a custom wrapper. The XML parser
(`parse_report`) is pure and unit-tested against Burp's documented export
format, so normalization is verified without Burp installed.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from typing import Optional

from defusedxml import ElementTree as ET

from asvp.config import get_config
from asvp.engine.adapters.base import (
    ExternalEngine,
    RawFinding,
    Runner,
    normalize_severity,
)


class BurpAdapter(ExternalEngine):
    name = "burp"
    destructiveness = "aggressive"

    def __init__(
        self,
        jar_path: Optional[str] = None,
        java_path: Optional[str] = None,
        runner: Optional[Runner] = None,
        extra_args: Optional[list[str]] = None,
    ):
        super().__init__(runner)
        cfg = get_config()
        self._jar = jar_path or cfg.burp_jar_path or ""
        self._java = java_path or cfg.java_path or "java"
        self._extra_args = extra_args or []

    def is_available(self) -> bool:
        if not self._jar or not os.path.exists(self._jar):
            return False
        # Java must be resolvable to launch the jar.
        return os.path.exists(self._java) or shutil.which(self._java) is not None

    def build_command(self, target_url: str, outfile: str) -> list[str]:
        return [
            self._java,
            "-jar", self._jar,
            "--headless",
            f"--target={target_url}",
            f"--report-file={outfile}",
            "--report-format=xml",
            *self._extra_args,
        ]

    @staticmethod
    def parse_report(text: str) -> list[RawFinding]:
        if not text or not text.strip():
            return []
        try:
            root = ET.fromstring(text)
        except ET.ParseError:
            return []
        findings: list[RawFinding] = []
        for issue in root.iter("issue"):
            name = _t(issue, "name", "Burp issue")
            severity = normalize_severity(_t(issue, "severity", "Information"))
            host = _t(issue, "host")
            path = _t(issue, "path") or "/"
            location = _t(issue, "location")
            param = _param_from_location(location)
            rule_id = _t(issue, "type") or _t(issue, "serialNumber") or "0"
            findings.append(
                RawFinding(
                    engine="burp",
                    rule_id=rule_id,
                    title=name,
                    severity=severity,
                    endpoint_id=f"GET {path}",
                    parameter=param,
                    description=_strip_html(_t(issue, "issueBackground") or _t(issue, "issueDetail")),
                    remediation=_strip_html(
                        _t(issue, "remediationBackground") or _t(issue, "remediationDetail")
                    ),
                    evidence={
                        "host": host,
                        "location": location,
                        "confidence": _t(issue, "confidence"),
                    },
                )
            )
        return findings

    async def scan(
        self, target_url: str, headers: Optional[dict[str, str]] = None
    ) -> list[RawFinding]:
        if not self.is_available():
            return []
        with tempfile.TemporaryDirectory(prefix="asvp-burp-") as tmp:
            outfile = os.path.join(tmp, "issues.xml")
            cmd = self.build_command(target_url, outfile)
            _, stdout, _ = await self._runner(
                cmd, cwd=tmp, timeout=get_config().external_engine_timeout_seconds
            )
            if os.path.exists(outfile):
                with open(outfile, "r", encoding="utf-8", errors="replace") as fh:
                    report = fh.read()
            else:
                report = stdout  # injected report path (tests)
            return self.parse_report(report)


def _t(element, tag: str, default: str = "") -> str:
    child = element.find(tag)
    if child is None or child.text is None:
        return default
    return child.text.strip()


def _param_from_location(location: str) -> str:
    # Burp locations look like "/search [q parameter]".
    if "[" in location and "parameter" in location:
        inner = location[location.find("[") + 1 : location.find("]")]
        return inner.replace("parameter", "").strip()
    return ""


def _strip_html(text: str) -> str:
    import re

    return re.sub(r"<[^>]+>", "", text or "").strip()
