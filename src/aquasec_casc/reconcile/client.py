"""The interface the reconciler talks to.

The reconciler must never import ``aquasec`` or ``requests`` directly. It talks
to this Protocol, and ``aquasec_casc.client`` provides the real implementation on
top of aquasec-lib. Three reasons that boundary is worth the indirection:

* SaaS and on-prem differ (auth, console URL resolution, TLS trust). Keeping
  those differences on one side of this line stops a SaaS-only assumption
  leaking into the core, which matters because production deployments are
  often on-prem while development happens against SaaS.
* The reconciler stays testable with a fake, so every rule below is exercised
  without a tenant.
* If this is rewritten in Go against controller-runtime, this module is the
  port surface -- one file, not an archaeology project.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from ..schema.registry import KindDef


class ClientError(Exception):
    """An Aqua API call failed. Carries no credentials in its message."""

    def __init__(self, message: str, status: int | None = None) -> None:
        self.status = status
        super().__init__(message)


@runtime_checkable
class AquaClient(Protocol):
    """Everything the reconciler needs from Aqua.

    Objects are addressed by name, not by numeric ID, because that is how Aqua's
    policy and enforcer-group endpoints work.
    """

    def get(self, kind: KindDef, name: str) -> dict[str, Any] | None:
        """The complete server object, or None if it does not exist.

        Must return the object *unmodified*. The three-way diff needs the whole
        thing, including fields we do not manage: that is how it tells an Aqua
        default apart from drift.
        """
        ...

    def list(self, kind: KindDef) -> list[dict[str, Any]]:
        """Every object of this kind, in whatever form the list endpoint gives.

        Used for orphan discovery, so each item must carry the object's name
        (``kind.name_field``), its ``description`` (the ownership marker) and
        the built-in flag if the kind has one. For runtime policies the list
        response carries all three (verified), so this is one call.
        """
        ...

    def create(self, kind: KindDef, body: dict[str, Any]) -> dict[str, Any]:
        ...

    def update(self, kind: KindDef, name: str, body: dict[str, Any]) -> dict[str, Any]:
        ...

    def delete(self, kind: KindDef, name: str) -> None:
        ...
