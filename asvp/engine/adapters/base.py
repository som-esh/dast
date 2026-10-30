"""External-engine interface, normalized finding, and subprocess runner."""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Optional

# A runner executes a command and returns (returncode, stdout, stderr).
# Injectable so adapter parsing is testable without the real tool.
Runner = Callable[..., Awaitable["tuple[int, str, str]"]]


async def default_runner(
    cmd: list[str], cwd: Optional[str] = None, timeout: float = 1800.0
) -> tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        cwd=cwd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        return 124, "", f"engine timed out after {timeout}s"
    return proc.returncode or 0, out.decode("utf-8", "replace"), err.decode("utf-8", "replace")


_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "informational": "info",
    "information": "info",
    "info": "info",
    "unknown": "info",
    "": "info",
}


def normalize_severity(raw: str) -> str:
    """Map any engine's severity vocabulary to the platform's scale."""
    token = (raw or "").strip().lower()
    # ZAP riskdesc looks like "High (Medium)" — take the leading word.
    token = token.split("(")[0].strip()
    return _SEVERITY_MAP.get(token, "info")


@dataclass
class RawFinding:
    """Engine output normalized prior to finding creation (FR-FND-1)."""

    engine: str
    rule_id: str
    title: str
    severity: str  # already normalized to the platform scale
    endpoint_id: str  # "METHOD /path" or a URL
    parameter: str = ""
    description: str = ""
    remediation: str = ""
    domain: str = "security"
    evidence: dict = field(default_factory=dict)
    compliance_mappings: list[str] = field(default_factory=list)

    @property
    def check_id(self) -> str:
        # Namespaced so external findings dedupe/regress independently of
        # the built-in check ids, while sharing the same fingerprint scheme.
        return f"{self.engine}:{self.rule_id}"


class ExternalEngine(ABC):
    name: str = "external"
    destructiveness: str = "aggressive"  # gates where the engine may run

    def __init__(self, runner: Optional[Runner] = None):
        self._runner = runner or default_runner

    @abstractmethod
    def is_available(self) -> bool:
        """True when the underlying tool is installed/configured."""

    @abstractmethod
    async def scan(
        self, target_url: str, headers: Optional[dict[str, str]] = None
    ) -> list[RawFinding]:
        """Run the engine against the target and return normalized findings."""
