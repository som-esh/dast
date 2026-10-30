"""External security-engine adapters (AR-3).

ZAP, Nuclei and Burp Suite are full scanners (not per-endpoint executors):
each takes a target URL and produces findings, which are normalized to the
platform's single finding schema (FR-FND-1). All three implement the
`ExternalEngine` interface, so the engine set is swappable and extensible.

Each adapter shells out to the real tool when its binary/jar is configured
(absent → reports unavailable and is skipped, never failing the scan). The
subprocess runner is injectable so the parsing path is unit-tested against
captured tool output without the tool installed.
"""

from asvp.engine.adapters.base import (
    ExternalEngine,
    RawFinding,
    default_runner,
    normalize_severity,
)
from asvp.engine.adapters.zap import ZapAdapter
from asvp.engine.adapters.nuclei import NucleiAdapter
from asvp.engine.adapters.burp import BurpAdapter

__all__ = [
    "ExternalEngine",
    "RawFinding",
    "default_runner",
    "normalize_severity",
    "ZapAdapter",
    "NucleiAdapter",
    "BurpAdapter",
    "build_default_registry",
]


def build_default_registry(config=None) -> dict[str, ExternalEngine]:
    """Construct the standard engine registry from configuration."""
    from asvp.config import get_config

    cfg = config or get_config()
    return {
        ZapAdapter.name: ZapAdapter(path=cfg.zap_path or None),
        NucleiAdapter.name: NucleiAdapter(path=cfg.nuclei_path or None),
        BurpAdapter.name: BurpAdapter(
            jar_path=cfg.burp_jar_path or None, java_path=cfg.java_path
        ),
    }
