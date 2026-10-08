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

    name_field: str = "name"
    """The field holding the object's Aqua name in API objects (enforcer groups
    use ``id``)."""

    collection: bool = True
    """A collection kind (policies, scopes, enforcer groups) has many named
    instances. Each one we manage carries the ownership marker in its
    description, takes part in orphan detection, and is deleted when its file
    goes. A singleton (a settings object) carries no marker and is simply
    configured as Git says."""

    builtin_field: str | None = None
    """The server field that flags an Aqua system object, if this kind has one.

    System objects are adopt-only: the tool never creates or deletes them (Aqua
    refuses to delete them anyway). For runtime policies this is
    ``is_ootb_policy``, which survives edits; ``author`` does not."""

    predefined: frozenset[str] = frozenset()
    """Names of system objects with fields that cannot change -- listed by name
    because no API field identifies them, and matched only together with
    ``builtin_field``, so a custom policy reusing the name is not affected."""

    predefined_immutable: tuple[str, ...] = ()
    """API paths that cannot change on a predefined object. A desired change is
    reported as not allowed instead of being sent."""

    # API paths deliberately do not live here: aquasec-lib owns them, and the
    # client adapter maps each kind onto the library's functions. Keeping one
    # copy means a path changing in Aqua is fixed in exactly one place.


REGISTRY: dict[str, KindDef] = {
    runtime_policy.KIND: KindDef(
        kind=runtime_policy.KIND,
        model=runtime_policy.RuntimePolicy,
        field_map=runtime_policy.FIELD_MAP,
        collection=True,
        # Verified on the lab: present on every policy in the list response,
        # set on exactly the Aqua-shipped policies, and unchanged by an edit.
        # `author` is NOT usable: an API edit rewrites it to the editor.
        builtin_field="is_ootb_policy",
        # Verified on the lab (8 Oct 2026): Aqua refuses to delete any system
        # policy ("Action forbidden: runtime policy is a system policy"), and
        # refuses a scope change on the three defaults ("can't change
        # application scope for default policies"). Other system policies'
        # scope can change.
        predefined=frozenset({
            "Aqua default runtime policy",
            "Aqua default host runtime policy",
            "Aqua default function runtime policy",
        }),
        predefined_immutable=("application_scopes",),
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
