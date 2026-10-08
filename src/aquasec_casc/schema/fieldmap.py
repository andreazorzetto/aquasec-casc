"""Translation between canonical CasC field paths and Aqua API field paths.

This module is deliberately pure data plus a handful of path helpers. It carries
no behaviour that depends on Python, because it is the piece most likely to be
ported to Go later -- the mappings below should survive that port as a table,
not as code to be reinterpreted.

Why a mapping layer exists at all:

* Aqua's API nests several controls that read naturally as flat in YAML. The
  control a human calls "block container exec" lives at
  ``container_exec.block_container_exec``, and its exception list lives beside
  it rather than under it.
* Aqua has renamed fields across versions. ``block_unregistered_images`` became
  ``only_registered_images``; ``enable_port_scan_detection`` became
  ``enable_port_scan_protection``. Our YAML must not churn every time it does.
* On-prem deployments often run an older version than SaaS, so there will be version drift
  between what we develop against and what we deploy against. Isolating every
  name here means that drift is absorbed in one table.

Field names were mined from terraform-provider-aquasec v0.15.1 (commit 49182c7),
``client/runtime_policy.go`` and ``aquasec/resource_container_runtime_policy.go``,
rather than reverse-engineered from the API.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Sentinel distinguishing "key absent" from "key present and set to None".
MISSING = object()


@dataclass(frozen=True)
class FieldMapping:
    """One canonical field path and the Aqua API path it corresponds to."""

    canonical: str
    """Dotted path in our schema, e.g. ``spec.controls.blockContainerExec``."""

    api: str
    """Dotted path in the Aqua API object, e.g. ``container_exec.block_container_exec``."""

    api_aliases: tuple[str, ...] = ()
    """Older or alternate API paths to accept when *reading* a server object.

    Write always uses ``api``. Reads fall back through the aliases in order,
    which is how we tolerate an on-prem version that predates a rename without
    needing a separate mapping table per Aqua version.
    """

    also_set: tuple[str, ...] = ()
    """Additional API paths that receive the same value on write.

    Aqua wraps several controls in an object with its own ``enabled`` gate, and
    the gate moves in lockstep with the control: across all 47 policies on the
    lab tenant, ``container_exec.enabled`` and
    ``container_exec.block_container_exec`` are never observed to differ.
    Writing the inner flag while leaving the gate false would produce a policy
    that looks correct in the diff and does nothing in the cluster.

    These paths are written and owned, but never read back -- ``from_api``
    ignores them, since the primary path already carries the value.
    """

    unverified: bool = False
    """True when the API path has not yet been confirmed against a live tenant.

    An unverified mapping is a silent-failure risk: Aqua ignores unknown fields
    on write, so a wrong path here means the tool reports success and changes
    nothing. ``FieldMap.unverified()`` lists these so the CLI can warn.
    """

    note: str = ""
    """Why this mapping is non-obvious, for whoever reads the table next."""


def get_path(obj: Any, dotted: str, default: Any = MISSING) -> Any:
    """Read a dotted path out of nested dicts, returning ``default`` if absent."""
    current = obj
    for part in dotted.split("."):
        if not isinstance(current, dict) or part not in current:
            return default
        current = current[part]
    return current


def set_path(obj: dict, dotted: str, value: Any) -> None:
    """Write a dotted path into nested dicts, creating intermediate dicts."""
    parts = dotted.split(".")
    current = obj
    for part in parts[:-1]:
        existing = current.get(part)
        if not isinstance(existing, dict):
            existing = {}
            current[part] = existing
        current = existing
    current[parts[-1]] = value


def has_path(obj: Any, dotted: str) -> bool:
    return get_path(obj, dotted) is not MISSING


@dataclass
class FieldMap:
    """A bidirectional table of mappings for one kind."""

    kind: str
    mappings: list[FieldMapping] = field(default_factory=list)

    def __post_init__(self) -> None:
        self._by_canonical = {m.canonical: m for m in self.mappings}
        duplicates = len(self.mappings) - len(self._by_canonical)
        if duplicates:
            raise ValueError(
                f"{self.kind} field map has {duplicates} duplicate canonical path(s)"
            )

    def unverified(self) -> list[FieldMapping]:
        """Mappings not yet confirmed against a live tenant."""
        return [m for m in self.mappings if m.unverified]

    def to_api(self, canonical: dict) -> dict:
        """Project a canonical resource dict onto an Aqua API object.

        Only paths actually present in ``canonical`` are emitted. Callers should
        pass a dict built with ``exclude_unset=True`` so that "the user did not
        mention this field" stays distinguishable from "the user set it to its
        default" -- that distinction is what makes the three-way diff able to
        leave console-managed fields alone.
        """
        api: dict = {}
        for mapping in self.mappings:
            value = get_path(canonical, mapping.canonical)
            if value is not MISSING:
                set_path(api, mapping.api, value)
                for gate in mapping.also_set:
                    set_path(api, gate, value)
        return api

    def from_api(self, api: dict) -> dict:
        """Project an Aqua API object back onto canonical paths.

        Used by ``export`` to turn an existing tenant's configuration into
        schema-valid YAML. Falls back through ``api_aliases`` so an older
        on-prem object still maps onto current canonical names.
        """
        canonical: dict = {}
        for mapping in self.mappings:
            for path in (mapping.api, *mapping.api_aliases):
                value = get_path(api, path)
                if value is not MISSING:
                    set_path(canonical, mapping.canonical, value)
                    break
        return canonical

    def owned_api_paths(self, canonical: dict) -> list[str]:
        """The API paths this document claims ownership of.

        These are the fields the reconciler manages: the ones the YAML mentions.
        Anything outside this set that appears on the server is Aqua's default
        or a console edit, and is left alone.
        """
        owned: list[str] = []
        for m in self.mappings:
            if get_path(canonical, m.canonical) is not MISSING:
                owned.append(m.api)
                owned.extend(m.also_set)
        return owned

    def for_api_path(self, api_path: str) -> tuple[FieldMapping | None, bool]:
        """The mapping an API path belongs to, and whether it is that mapping's
        ``also_set`` gate rather than its primary path."""
        for m in self.mappings:
            if m.api == api_path:
                return m, False
        for m in self.mappings:
            if api_path in m.also_set:
                return m, True
        return None, False

    def resolve_api_path(self, api_object: dict, canonical_path: str) -> str | None:
        """Which API path this tenant actually uses for a canonical field.

        Returns the first of ``api`` or ``api_aliases`` present on the supplied
        server object, or None when the field is absent entirely. This is how an
        ambiguous mapping gets settled at runtime against the tenant in front of
        us rather than guessed at build time.
        """
        mapping = self._by_canonical.get(canonical_path)
        if mapping is None:
            return None
        for path in (mapping.api, *mapping.api_aliases):
            if has_path(api_object, path):
                return path
        return None
