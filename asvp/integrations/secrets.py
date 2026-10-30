"""Runtime scan-credential injection (AR-5).

Specs, jobs, and logs only ever carry credential *references* (handles).
The resolved value exists in worker memory for the duration of a scan and
is never persisted. Production deployment backs this with Vault/ASM; the
interface is identical.
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod


class SecretResolutionError(Exception):
    pass


class SecretsManager(ABC):
    @abstractmethod
    def resolve(self, ref: str) -> str:
        """Resolve a credential handle (e.g. 'secret:payments/qa/alice')."""


class EnvSecretsManager(SecretsManager):
    """Resolves 'secret:NAME' from environment variable ASVP_SECRET_NAME."""

    def resolve(self, ref: str) -> str:
        key = ref.removeprefix("secret:").replace("/", "_").replace("-", "_").upper()
        value = os.environ.get(f"ASVP_SECRET_{key}")
        if value is None:
            raise SecretResolutionError(f"secret not found for ref '{ref}'")
        return value


class InMemorySecretsManager(SecretsManager):
    """For tests and the demo environment."""

    def __init__(self, secrets: dict[str, str] | None = None):
        self._secrets = dict(secrets or {})

    def put(self, ref: str, value: str) -> None:
        self._secrets[ref] = value

    def resolve(self, ref: str) -> str:
        if ref not in self._secrets:
            raise SecretResolutionError(f"secret not found for ref '{ref}'")
        return self._secrets[ref]
