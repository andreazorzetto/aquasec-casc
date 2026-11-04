"""The three-way diff -- the core of the product.

A two-way diff (file vs server) breaks immediately. Aqua returns dozens of
fields we never set: defaults, server-assigned IDs, timestamps, computed values.
A two-way diff reads every one of those as drift and tries to null them.

The third input is what *we* set last time, recorded in state as a list of API
field paths. It is what makes these four cases distinguishable:

    desired != actual, we own it        -> drift, revert to desired
    in actual, not desired, never ours  -> Aqua default or console edit, leave alone
    we owned it, now absent from desired-> released, we stop managing it
    in desired, absent from actual      -> add it

Same mechanism as ``kubectl apply``. The difference from kubectl is what happens
to a released field: see ReleasePolicy.

This module imports nothing from the CLI, prints nothing, and never calls
``sys.exit``. It returns plan objects; rendering them is somebody else's job.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterator

from ..schema.fieldmap import MISSING, get_path, set_path


class ChangeType(str, Enum):
    ADD = "add"
    """Present in desired, absent on the server."""

    UPDATE = "update"
    """Present in both, and different. This is drift."""

    RELEASE = "release"
    """We owned it last run; the file no longer mentions it."""


class ReleasePolicy(str, Enum):
    """What to do with a field we used to manage and no longer declare.

    ``kubectl apply`` deletes released fields, because the Kubernetes API server
    will re-apply its own default afterwards. Aqua offers no such guarantee: we
    cannot know what value it would choose, and for a PUT of a whole object a
    missing boolean unmarshals as false. Silently turning a security control off
    because someone tidied a YAML file is not acceptable here.

    So RETAIN is the default: the value stays as-is on the server and we simply
    stop tracking it. RESET is available for people who want kubectl semantics
    and have thought about it.
    """

    RETAIN = "Retain"
    RESET = "Reset"


def _is_empty(value: Any) -> bool:
    return value is None or value == [] or value == {}


def is_off_value(value: Any) -> bool:
    """False, an empty list, 0 or "": what a control holds when it is off."""
    return value is False or value == "" or _is_empty(value) or (type(value) is int and value == 0)


def equivalent(a: Any, b: Any) -> bool:
    """Whether two API values mean the same thing.

    Aqua is inconsistent about empty collections: on the same policy object,
    ``drift_prevention.exec_lockdown_white_list`` comes back as ``[]`` while
    ``block_fileless_exec_proc_white_list`` comes back as ``null``. Treating
    those as different would report drift on a policy nobody has touched, and
    "apply straight after export changes nothing" would be false -- which is the
    single most important property this tool has to demonstrate.

    Note this deliberately does NOT treat ``False`` as equivalent to absent. A
    security control that is off is a meaningful, deliberate state.

    In a list of objects, only the fields of ``b``, the wanted item, count: Aqua
    adds fields of its own to items (a package's ``display``), and stores a
    field it was not given as "". The tool writes every field it maps, so a
    field removed from the YAML is still seen.
    """
    if _is_empty(a) and _is_empty(b):
        return True
    if (isinstance(a, list) and isinstance(b, list) and len(a) == len(b)
            and any(isinstance(item, dict) for item in b)):
        return all(_same_item(have, want) for have, want in zip(a, b))
    return a == b


def _same_item(have: Any, want: Any) -> bool:
    if not (isinstance(have, dict) and isinstance(want, dict)):
        return have == want
    return all(have.get(k) == v or (v == "" and have.get(k) is None) for k, v in want.items())


def flatten(obj: Any, prefix: str = "") -> dict[str, Any]:
    """Flatten nested dicts to dotted leaf paths.

    Lists are leaves, not containers to recurse into: Aqua's list-valued fields
    (allow-lists, scopes) are set wholesale, and diffing them element-by-element
    would produce changes that cannot be applied independently.
    """
    flat: dict[str, Any] = {}
    if not isinstance(obj, dict):
        return {prefix: obj} if prefix else {}

    for key, value in obj.items():
        path = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict) and value:
            flat.update(flatten(value, path))
        else:
            flat[path] = value
    return flat


@dataclass(frozen=True)
class FieldChange:
    """One field that would change, with enough context to explain why."""

    path: str
    change: ChangeType
    before: Any = None
    after: Any = None

    def render(self) -> str:
        if self.change is ChangeType.ADD:
            return f"+ {self.path}: {self.after!r}"
        if self.change is ChangeType.RELEASE:
            return f"~ {self.path}: releasing ownership (value left as {self.before!r})"
        return f"! {self.path}: {self.before!r} -> {self.after!r}"


@dataclass
class Plan:
    """The set of changes that would bring one resource into line."""

    changes: list[FieldChange] = field(default_factory=list)
    release_policy: ReleasePolicy = ReleasePolicy.RETAIN

    def __bool__(self) -> bool:
        return bool(self.effective_changes)

    def __iter__(self) -> Iterator[FieldChange]:
        return iter(self.changes)

    def __len__(self) -> int:
        return len(self.changes)

    def is_empty(self) -> bool:
        """True when applying this plan would not alter the server.

        Under RETAIN, releases change nothing on Aqua -- they only shrink what
        we record as ours -- so a plan of nothing but releases is still a no-op
        as far as the tenant is concerned. The state file is still updated.
        """
        return not self.effective_changes

    @property
    def effective_changes(self) -> list[FieldChange]:
        """Changes that actually alter the server object."""
        if self.release_policy is ReleasePolicy.RESET:
            return list(self.changes)
        return [c for c in self.changes if c.change is not ChangeType.RELEASE]

    def of_type(self, change: ChangeType) -> list[FieldChange]:
        return [c for c in self.changes if c.change is change]

    @property
    def paths(self) -> list[str]:
        return [c.path for c in self.changes]

    def apply_to(self, actual: dict) -> dict:
        """Produce the object to send back to Aqua.

        This is a read-modify-write against the *whole* server object rather
        than a PUT of just our fields. That is deliberate: Aqua's update
        endpoints replace the object, so sending only our fields would blank
        every setting the console owns. Starting from ``actual`` and overlaying
        only the paths we own is what keeps console-managed configuration
        intact.
        """
        merged = copy.deepcopy(actual)

        for change in self.changes:
            if change.change in (ChangeType.ADD, ChangeType.UPDATE):
                set_path(merged, change.path, change.after)
            elif change.change is ChangeType.RELEASE:
                if self.release_policy is ReleasePolicy.RESET:
                    _delete_path(merged, change.path)

        return merged


def _delete_path(obj: dict, dotted: str) -> None:
    """Remove a dotted path, pruning containers left empty behind it."""
    parts = dotted.split(".")
    stack: list[tuple[dict, str]] = []
    current: Any = obj

    for part in parts[:-1]:
        if not isinstance(current, dict) or part not in current:
            return
        stack.append((current, part))
        current = current[part]

    if isinstance(current, dict):
        current.pop(parts[-1], None)

    for parent, key in reversed(stack):
        if isinstance(parent.get(key), dict) and not parent[key]:
            del parent[key]


def three_way_diff(
    desired: dict,
    actual: dict,
    last_applied: list[str] | None = None,
    release_policy: ReleasePolicy = ReleasePolicy.RETAIN,
) -> Plan:
    """Compare desired, actual and last-applied into a plan.

    Args:
        desired: API-shaped projection of the YAML, containing only the fields
            the author actually wrote. Fields absent here are not ours.
        actual: The complete object as Aqua returned it.
        last_applied: API field paths we set on the previous successful apply.
        release_policy: What to do with fields we owned and no longer declare.

    Returns:
        A Plan. Fields outside both ``desired`` and ``last_applied`` are never
        examined, which is what stops the tool fighting Aqua's own defaults.
    """
    plan = Plan(release_policy=release_policy)

    desired_leaves = flatten(desired)
    previously_owned = set(last_applied or ())

    for path, wanted in desired_leaves.items():
        current = get_path(actual, path)

        if current is MISSING:
            plan.changes.append(
                FieldChange(path=path, change=ChangeType.ADD, after=wanted)
            )
        elif not equivalent(current, wanted):
            plan.changes.append(
                FieldChange(
                    path=path,
                    change=ChangeType.UPDATE,
                    before=current,
                    after=wanted,
                )
            )

    for path in sorted(previously_owned - set(desired_leaves)):
        current = get_path(actual, path)
        if current is MISSING:
            # Already gone from the server; nothing to release.
            continue
        plan.changes.append(
            FieldChange(path=path, change=ChangeType.RELEASE, before=current)
        )

    return plan
