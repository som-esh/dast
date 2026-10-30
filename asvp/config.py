"""Platform configuration.

Values mirror the PRD's binding requirements (AR-7 concurrency caps,
FR-FND-5 SLA defaults, NFR-5 retention). Everything is overridable via
environment variables prefixed ASVP_.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


@dataclass
class SlaDefaults:
    """FR-FND-5: SLA clocks start at confirmation."""

    critical_days: int = 7
    high_days: int = 30
    medium_days: int = 90
    low_days: int = 180

    def days_for(self, severity: str) -> int:
        return {
            "critical": self.critical_days,
            "high": self.high_days,
            "medium": self.medium_days,
            "low": self.low_days,
        }.get(severity.lower(), self.low_days)


@dataclass
class Config:
    # Storage
    db_path: str = field(
        default_factory=lambda: os.environ.get("ASVP_DB_PATH", "asvp.db")
    )

    # Orchestration (AR-2, AR-7, FR-EXE-2)
    max_concurrent_scans_platform: int = field(
        default_factory=lambda: _env_int("ASVP_MAX_CONCURRENT_SCANS", 50)
    )
    default_env_concurrency_cap: int = field(
        default_factory=lambda: _env_int("ASVP_ENV_CONCURRENCY_CAP", 4)
    )
    default_target_rps: float = 10.0  # per-target requests/sec throttle

    # Engine
    request_timeout_seconds: float = 10.0
    rate_limit_probe_requests: int = 15
    burst_probe_requests: int = 20

    # External engine binaries/jars (AR-3 swappable engines). Paths are
    # resolved from the environment so operators can drop in the tools
    # without code changes. Absent paths → the engine reports unavailable
    # and is skipped, never failing the scan.
    zap_path: str = field(
        default_factory=lambda: os.environ.get("ASVP_ZAP_PATH", "")
    )  # path to zap.sh / zap.bat / zap binary
    nuclei_path: str = field(
        default_factory=lambda: os.environ.get("ASVP_NUCLEI_PATH", "")
    )  # path to the nuclei binary
    burp_jar_path: str = field(
        default_factory=lambda: os.environ.get("ASVP_BURP_JAR", "")
    )  # path to burpsuite_pro.jar / burpsuite_community.jar
    java_path: str = field(
        default_factory=lambda: os.environ.get("ASVP_JAVA_PATH", "java")
    )  # JRE used to launch the Burp jar
    external_engine_timeout_seconds: float = field(
        default_factory=lambda: float(os.environ.get("ASVP_ENGINE_TIMEOUT", "1800"))
    )

    # API web crawler / spider (endpoint discovery for coverage + inventory)
    crawler_max_urls: int = field(
        default_factory=lambda: _env_int("ASVP_CRAWLER_MAX_URLS", 200)
    )
    crawler_max_depth: int = field(
        default_factory=lambda: _env_int("ASVP_CRAWLER_MAX_DEPTH", 3)
    )

    # Findings (FR-FND-5)
    sla: SlaDefaults = field(default_factory=SlaDefaults)

    # Retention (NFR-5)
    findings_retention_days: int = 7 * 365
    raw_artifact_retention_days: int = 90

    # Gate (FR-GTE-5)
    pr_verdict_budget_seconds: int = 600
    preprod_verdict_budget_seconds: int = 1800

    # Production protection (AR-4): CIDRs scans must never target.
    production_cidr_blocklist: tuple[str, ...] = ("10.100.", "10.200.")


_config: Config | None = None


def get_config() -> Config:
    global _config
    if _config is None:
        _config = Config()
    return _config


def reset_config() -> None:
    global _config
    _config = None
