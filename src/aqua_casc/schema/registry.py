"""The set of kinds this build understands.

Adding a kind means adding one entry here plus its module. Nothing else in the
codebase needs to enumerate kinds -- the reconciler, the CLI and the JSON Schema
generator all read this table.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Type

from .base import Resource
from .fieldmap import FieldMap
from . import runtime_policy


@dataclass(frozen=True)
class KindDef:
    """Everything the rest of the tool needs to know about one kind."""

    kind: str
    model: Type[Resource]
    field_map: FieldMap

    # API paths deliberately do not live here: aquasec-lib owns them, and the
    # client adapter maps each kind onto the library's functions. Keeping one
    # copy means a path changing in Aqua is fixed in exactly one place.


REGISTRY: dict[str, KindDef] = {
    runtime_policy.KIND: KindDef(
        kind=runtime_policy.KIND,
        model=runtime_policy.RuntimePolicy,
        field_map=runtime_policy.FIELD_MAP,
    ),
}


def get(kind: str) -> KindDef:
    try:
        return REGISTRY[kind]
    except KeyError:
        known = ", ".join(sorted(REGISTRY))
        raise KeyError(f"unknown kind {kind!r}; this build understands: {known}")


def kinds() -> list[str]:
    return sorted(REGISTRY)
