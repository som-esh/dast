"""Secret scanning for ingested specs (FR-ING-3).

Detected secrets are quarantined: only a redacted preview and a hash
fingerprint leave this module — the raw value is never stored or logged.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("aws_access_key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("aws_secret_key", re.compile(r"(?i)aws.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----")),
    (
        "generic_api_key",
        re.compile(
            r"(?i)\b(api[_-]?key|api[_-]?secret|client[_-]?secret|access[_-]?token|auth[_-]?token|password)\b"
            r"\s*[:=]\s*['\"]?(?P<val>[A-Za-z0-9_\-./+]{12,})['\"]?"
        ),
    ),
]

# Placeholder values that are not secrets ({{var}}, ${VAR}, <token>, etc.)
_PLACEHOLDER = re.compile(r"^\s*(\{\{.*\}\}|\$\{.*\}|<.*>|\*+|x{4,}|YOUR_.*|CHANGE.*|REDACTED.*)\s*$", re.I)


@dataclass
class SecretHit:
    kind: str
    location: str  # JSON-path-ish locator inside the spec
    fingerprint: str  # sha256 of the raw value — safe to store
    redacted_preview: str  # first 4 chars + ellipsis


def _redact(value: str) -> str:
    return value[:4] + "…" if len(value) > 4 else "…"


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def _walk(node: Any, path: str, hits: list[SecretHit], redact: bool) -> Any:
    if isinstance(node, dict):
        return {k: _walk(v, f"{path}.{k}", hits, redact) for k, v in node.items()}
    if isinstance(node, list):
        return [_walk(v, f"{path}[{i}]", hits, redact) for i, v in enumerate(node)]
    if isinstance(node, str):
        return _scan_string(node, path, hits, redact)
    return node


def _scan_string(text: str, path: str, hits: list[SecretHit], redact: bool) -> str:
    if _PLACEHOLDER.match(text):
        return text
    out = text
    for kind, pattern in _PATTERNS:
        for m in pattern.finditer(text):
            raw = m.groupdict().get("val") or m.group(0)
            if _PLACEHOLDER.match(raw):
                continue
            hits.append(
                SecretHit(
                    kind=kind,
                    location=path,
                    fingerprint=_fingerprint(raw),
                    redacted_preview=_redact(raw),
                )
            )
            if redact:
                out = out.replace(raw, f"[QUARANTINED:{kind}]")
    return out


def scan_for_secrets(document: dict, redact: bool = True) -> tuple[dict, list[SecretHit]]:
    """Scan a spec document. Returns (possibly-redacted copy, hits)."""
    hits: list[SecretHit] = []
    cleaned = _walk(json.loads(json.dumps(document)), "$", hits, redact)
    return cleaned, hits
