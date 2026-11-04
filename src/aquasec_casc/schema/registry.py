"""The set of kinds this build understands.

Adding a kind means adding one entry here plus its module. Nothing else in the
codebase needs to enumerate kinds -- the reconciler, the CLI and the JSON Schema
generator all read this table.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Type

from .base import Resource
from .fieldmap import FieldMap
from . import assurance_policy, runtime_policy


@dataclass(frozen=True)
class KindDef:
    """Everything the rest of the tool needs to know about one kind."""

    kind: str
    model: Type[Resource]
    field_map: FieldMap

    name_field: str = "name"
    """The field holding the object's Aqua name in API objects (enforcer groups
    use ``id``)."""

    qualifier_field: str | None = None
    """The API field that, with the name, identifies an object, for kinds whose
    names are unique only within a type. Every assurance policy type has its own
    "Default", so what addresses one is ``image/Default``: see ``key``."""

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

    builtin_value: Any = True
    """The value of ``builtin_field`` that marks a system object."""

    builtin_names: frozenset[str] = frozenset()
    """Keys of system objects, for kinds with no reliable flag: an object with one
    of these keys is treated as a system object whatever its fields say. The safe
    direction: the worst case is an object the tool will not delete."""

    predefined: frozenset[str] = frozenset()
    """Keys of system objects with fields that cannot change -- listed because no
    API field identifies them."""

    only_on: dict[str, frozenset[str]] = field(default_factory=dict)
    """API paths that exist only on particular system objects, by name. Setting
    one anywhere else is reported as not allowed and not sent -- matching what
    the console offers."""

    predefined_immutable: tuple[str, ...] = ()
    """API paths that cannot change on a predefined object. A desired change is
    reported as not allowed instead of being sent."""

    off_when_unset: tuple[str, ...] = ()
    """Canonical prefixes under which a field the YAML leaves out is switched
    off rather than left as the server has it. For runtime policies this is the
    controls: the file is the whole policy, so a control removed from it -- or
    switched on only in the console -- goes off, as on a new policy."""

    always_sent: tuple[str, ...] = ()
    """Canonical paths held to the schema's default when the YAML leaves them out,
    since Aqua's own default differs and says something the file did not: left to
    itself, Aqua creates a runtime policy disabled."""

    kept_when_unset: tuple[str, ...] = ()
    """Canonical prefixes under ``off_when_unset`` exempt from it: left as the
    server has them when the YAML leaves them out."""

    drop_on_export: Callable[[dict], list[str]] | None = None
    """Takes out of an exported spec what the schema refuses and that does nothing
    in Aqua anyway, so that the policy can still be adopted. Returns what it took."""

    # API paths deliberately do not live here: aquasec-lib owns them, and the
    # client adapter maps each kind onto the library's functions. Keeping one
    # copy means a path changing in Aqua is fixed in exactly one place.

    def key(self, resource: Resource) -> str:
        """What addresses this resource's object in Aqua."""
        if not self.qualifier_field:
            return resource.aqua_name
        canonical = resource.model_dump(mode="json")
        qualifier = self.field_map.from_api_path(self.qualifier_field, canonical)
        return f"{qualifier}/{resource.aqua_name}"

    def key_of(self, obj: dict) -> str:
        """What addresses a server object."""
        name = obj.get(self.name_field)
        return f"{obj.get(self.qualifier_field)}/{name}" if self.qualifier_field else name

    def name_of(self, key: str) -> str:
        """The bare Aqua name in a key."""
        return key.split("/", 1)[1] if self.qualifier_field else key

    def matches(self, key: str, patterns: Iterable[str]) -> bool:
        """Whether a ``--name`` glob selects this key. A glob matches the name, or
        with a "/" in it the whole key: ``h*`` is not every host policy."""
        return any(fnmatch.fnmatchcase(key if "/" in p else self.name_of(key), p) for p in patterns)


#: What Aqua ships. The flag alone will not do: is_ootb_policy is false on every
#: one of these in a 2022.4 export, so the names are what is certain.
SHIPPED_RUNTIME_POLICIES = (
    "Aqua default runtime policy", "Aqua default host runtime policy",
    "Aqua default function runtime policy",
    "Block Non-compliant Images", "Block Non-compliant Resources", "Block Unregistered Images",
    "CIS", "HIPAA", "NIST", "PCI DSS",
    "FIM for Linux", "FIM for Windows", "Registry monitoring for Windows",
    "Malware Protection for Linux hosts", "Malware Protection for Windows hosts",
    "Malware Protection for containers",
    "Manage Noncompliant Images in Kubernetes", "Manage Noncompliant Kubernetes Resources",
    "Manage Unregistered Images in Kubernetes",
)

#: Every type's predefined assurance policies. "You can customize all components
#: of these policies, with exception of their name and scope"; no flag marks them,
#: and an API edit may rewrite the author.
SHIPPED_ASSURANCE_POLICIES = (
    "image/Default", "image/DTA", "image/Malware-Default-Policy",
    "image/Sensitive-Data-Default-Policy",
    "host/Default", "host/Malware-Default-Policy", "host/Sensitive-Data-Default-Policy",
    "function/Default", "cf_application/Default",
    "kubernetes/Default", "kubernetes/Non-workload-resources",
)

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
        builtin_names=frozenset(SHIPPED_RUNTIME_POLICIES),
        always_sent=("spec.enabled", "spec.enforce", "spec.runtimeType"),
        off_when_unset=("spec.controls", "spec.excludeApplicationScopes"),
        # Bypass Scope is scope, not a control, and the default container policy
        # ships with it on, exempting Aqua's own components and kube-system.
        # Switching it off because a file leaves it out would put them in scope.
        kept_when_unset=("spec.controls.bypassScope",),
        # The console offers Bypass Scope only on these two. Every policy carries
        # bypass_scope in the API (disabled), so it is exported only for them.
        only_on={"bypass_scope": frozenset({
            "Aqua default runtime policy",
            "Aqua default host runtime policy",
        })},
    ),
    assurance_policy.KIND: KindDef(
        kind=assurance_policy.KIND,
        model=assurance_policy.AssurancePolicy,
        field_map=assurance_policy.FIELD_MAP,
        collection=True,
        qualifier_field="assurance_type",
        builtin_field="author",
        builtin_value="system",
        builtin_names=frozenset(SHIPPED_ASSURANCE_POLICIES),
        predefined=frozenset(SHIPPED_ASSURANCE_POLICIES),
        predefined_immutable=("application_scopes",),
        off_when_unset=("spec.actions", "spec.exceptions", "spec.controls",
                        "spec.excludeApplicationScopes"),
        drop_on_export=assurance_policy.not_offered_on_this_type,
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
