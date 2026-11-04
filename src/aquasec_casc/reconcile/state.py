"""Where reconcile status would go -- deliberately nowhere, in phase 1.

The tool is stateless: no state file, no in-cluster backend, nothing to persist
or commit back. Ownership lives on the Aqua object itself (``marker``), so a
run behaves identically on a laptop, in CI and in an Argo CD hook. See
docs/architecture.md for why this departs from the original brief.

``StateBackend`` stays as the seam for phase 2, where an operator would report
observed state on the custom resource's ``.status``. Phase 1 uses the no-op
backend.

The credential guard lives here too: it is about what the tool may *own*, which
used to be recorded in state and is now simply what the YAML asks for.
"""

from __future__ import annotations

from typing import Protocol

# Fields that carry a credential. Enforcer group objects hold their registration
# token in ``token`` and again inside ``install_command`` / ``command``.
FORBIDDEN_KEYS = ("token", "install_command", "command", "pas_deployment_link",
                  "password", "secret", "user_password", "api_key", "api_secret", "secret_key",
                  "access_key")


class StateError(Exception):
    """Raised when a resource would take ownership of a credential."""


def assert_not_ownable(paths: list[str], where: str = "") -> None:
    """Refuse to manage a credential-bearing API field.

    Matching is on whole path segments: ``token`` is refused, a policy's
    ``user_password_policy`` is not.
    """
    offenders = sorted(
        p for p in paths
        if any(f == p.split(".")[-1].lower() or f == p.lower() for f in FORBIDDEN_KEYS)
    )
    if offenders:
        raise StateError(
            f"refusing to manage{f' {where}' if where else ''}: "
            f"{', '.join(offenders)} carries a credential and must never be "
            "managed as configuration."
        )


class StateBackend(Protocol):
    """The seam for phase 2. Told about every successful write."""

    def record(self, kind: str, name: str, *, aqua_name: str,
               aqua_id: int | None = None) -> None: ...


class NoopStateBackend:
    """Phase 1: remembers nothing, on purpose."""

    def record(self, kind: str, name: str, *, aqua_name: str,
               aqua_id: int | None = None) -> None:
        return None
