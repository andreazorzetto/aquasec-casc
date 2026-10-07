"""Reconcile desired state against a live Aqua tenant. Stateless.

There is no state file. Each run compares what Git says with what Aqua has:

* every field the YAML mentions is ours, and is corrected when it drifts;
* every field the YAML does not mention belongs to Aqua or the console, and is
  left alone;
* ownership of the object itself is the marker in its description
  (``marker``), which also tells this instance's objects apart from another's.

The same function serves ``diff`` (dry run), ``apply``, and -- in phase 2 -- an
operator's reconcile loop. It prints nothing and exits nothing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from ..schema.base import Enforcement, Resource
from ..schema.registry import REGISTRY, KindDef
from . import marker
from .client import AquaClient, ClientError
from .diff import Plan, flatten, three_way_diff
from .result import Outcome, Result, RunSummary
from .state import NoopStateBackend, StateBackend, StateError, assert_not_ownable


@dataclass(frozen=True)
class Options:
    instance: str
    """Which deployment of the tool this is. Written into the ownership marker."""

    dry_run: bool = False

    no_delete: bool = False
    """Report orphans instead of deleting them (``--no-delete``)."""

    allow_empty: bool = False
    """Allow deletions when no resources were loaded at all (``--allow-empty``).

    Off by default, like Argo CD's ``allowEmpty``: an empty config directory --
    a wrongly mounted ConfigMap, a bad path -- is far more likely a mistake than
    an instruction to delete everything this instance owns."""

    kinds: tuple[KindDef, ...] = field(default_factory=lambda: tuple(REGISTRY.values()))
    """Kinds scanned for orphans. Defaults to every registered kind."""


# --------------------------------------------------------------------------- #
# Built-ins
# --------------------------------------------------------------------------- #

def is_shipped(kind: KindDef, obj: dict | None) -> bool:
    """Aqua-shipped: never created or deleted by the tool."""
    return bool(kind.builtin_field and obj and obj.get(kind.builtin_field) is True)


def is_predefined(kind: KindDef, obj: dict | None, name: str) -> bool:
    """Predefined: shipped *and* on the named list, so certain fields are locked.

    Both are required. The flag stops a customer's own policy that happens to
    reuse a predefined name from being treated as predefined; the name picks
    the locked ones out of everything Aqua ships.
    """
    return is_shipped(kind, obj) and name in kind.predefined


def _touches(path: str, prefixes: Iterable[str]) -> bool:
    return any(path == p or path.startswith(p + ".") for p in prefixes)


# --------------------------------------------------------------------------- #
# One resource
# --------------------------------------------------------------------------- #

def _desired(resource: Resource, kind: KindDef, actual: dict | None, instance: str) -> dict:
    """The API object the YAML asks for, with the ownership marker in place.

    ``exclude_unset`` is load-bearing: a schema default is not a statement of
    intent, so only fields the author wrote are owned.

    The marker goes into the description. If the YAML sets a description, that
    text plus the marker is what we want. If it does not, the console's text is
    kept and the marker appended -- the tool must not wipe a description nobody
    asked it to manage.
    """
    canonical = resource.model_dump(exclude_unset=True, mode="json")
    desired = kind.field_map.to_api(canonical)

    if kind.collection:
        spec = canonical.get("spec") or {}
        text = spec["description"] if "description" in spec else (actual or {}).get("description")
        desired["description"] = marker.compose(text, instance)

    assert_not_ownable(list(flatten(desired)), where=resource.ref)
    return desired


def reconcile(
    resource: Resource,
    kind: KindDef,
    client: AquaClient,
    options: Options,
    state: StateBackend | None = None,
) -> Result:
    """Bring one resource into line, or describe what it would take."""
    state = state or NoopStateBackend()
    name = resource.aqua_name
    common = dict(kind=resource.kind, name=resource.metadata.name, aqua_name=name)
    report_only = getattr(resource.spec, "enforcement", None) is Enforcement.REPORT_ONLY

    try:
        actual = client.get(kind, name)
    except ClientError as exc:
        return Result(**common, outcome=Outcome.FAILED, message=str(exc), reason="LookupFailed")

    try:
        desired = _desired(resource, kind, actual, options.instance)
    except StateError as exc:
        return Result(**common, outcome=Outcome.FAILED, message=str(exc), reason="Refused")

    # ---- missing: create it (this is also how a console deletion is undone) --
    if actual is None:
        body = dict(desired)
        body[kind.name_field] = name
        plan = three_way_diff(desired=body, actual={})
        if options.dry_run:
            return Result(**common, outcome=Outcome.PLANNED, action="create", plan=plan,
                          reason="CreateRequired")
        if report_only:
            return Result(**common, outcome=Outcome.DRIFT_DETECTED, plan=plan, reason="Missing",
                          message="does not exist in Aqua; ReportOnly, so not created")
        try:
            created = client.create(kind, body)
        except ClientError as exc:
            return Result(**common, outcome=Outcome.FAILED, message=str(exc), reason="CreateFailed")
        state.record(resource.kind, resource.metadata.name, aqua_name=name,
                     aqua_id=_aqua_id(created))
        return Result(**common, outcome=Outcome.CREATED, plan=plan)

    # ---- exists: whose is it? ----------------------------------------------
    adopting = False
    if kind.collection:
        found = marker.owner(actual.get("description"))
        if found and found != options.instance:
            return Result(
                **common, outcome=Outcome.BLOCKED, reason="OwnedByOtherInstance",
                message=(f"managed by another instance ({marker.PREFIX}{found}); this "
                         f"instance is {options.instance!r}. Two instances must not "
                         "manage the same object -- remove it from one of them."),
            )
        adopting = found is None

    plan = three_way_diff(desired=desired, actual=actual)

    # ---- predefined objects: some fields cannot change -----------------------
    not_allowed: list[str] = []
    if is_predefined(kind, actual, name):
        kept = []
        for change in plan.changes:
            if _touches(change.path, kind.predefined_immutable):
                not_allowed.append(
                    f"{change.path}: {change.before!r} -> {change.after!r} "
                    "(cannot change on a predefined policy; not sent)"
                )
            else:
                kept.append(change)
        plan = Plan(changes=kept, release_policy=plan.release_policy)

    if plan.is_empty():
        return Result(**common, outcome=Outcome.IN_SYNC, plan=plan, not_allowed=not_allowed)

    action = "adopt" if adopting else "update"
    if options.dry_run:
        return Result(**common, outcome=Outcome.PLANNED, action=action, plan=plan,
                      not_allowed=not_allowed,
                      reason="AdoptRequired" if adopting else "UpdateRequired")
    if report_only:
        return Result(**common, outcome=Outcome.DRIFT_DETECTED, plan=plan, not_allowed=not_allowed,
                      reason="ReportOnly",
                      message="drift detected; spec.enforcement is ReportOnly so nothing was changed")

    try:
        client.update(kind, name, plan.apply_to(actual))
    except ClientError as exc:
        return Result(**common, outcome=Outcome.FAILED, plan=plan, message=str(exc),
                      reason="UpdateFailed")

    state.record(resource.kind, resource.metadata.name, aqua_name=name, aqua_id=_aqua_id(actual))
    return Result(**common, outcome=Outcome.ADOPTED if adopting else Outcome.UPDATED,
                  plan=plan, not_allowed=not_allowed)


def _aqua_id(obj: dict | None) -> int | None:
    value = (obj or {}).get("id")
    return value if isinstance(value, int) else None


# --------------------------------------------------------------------------- #
# Orphans
# --------------------------------------------------------------------------- #

def _orphans(resources: list[Resource], client: AquaClient, options: Options) -> list[Result]:
    """Objects carrying this instance's marker that no file describes.

    Deleted by default -- removing a file from Git removes the object, as with
    Argo CD pruning. Never deleted: another instance's objects, unmarked
    objects, and anything Aqua ships.
    """
    results: list[Result] = []

    for kind in options.kinds:
        if not kind.collection:
            continue

        wanted = {r.aqua_name for r in resources if r.kind == kind.kind}
        try:
            objects = client.list(kind)
        except ClientError as exc:
            results.append(Result(kind=kind.kind, name="*", outcome=Outcome.FAILED,
                                  reason="OrphanScanFailed",
                                  message=f"could not list {kind.kind} objects: {exc}"))
            continue

        for obj in objects:
            name = obj.get(kind.name_field)
            if not name or name in wanted:
                continue
            if marker.owner(obj.get("description")) != options.instance:
                continue

            common = dict(kind=kind.kind, name=name, aqua_name=name)

            if is_shipped(kind, obj):
                results.append(Result(
                    **common, outcome=Outcome.ORPHANED, reason="ShippedNeverDeleted",
                    informational=True,
                    message=("no file describes it, but it is shipped by Aqua and the "
                             "tool never deletes those. It keeps its settings and the "
                             "ownership marker; remove the marker in the console to "
                             "release it."),
                ))
            elif options.no_delete:
                results.append(Result(**common, outcome=Outcome.ORPHANED, reason="DeletionDisabled",
                                      message="orphaned, not deleted (--no-delete)"))
            elif not resources and not options.allow_empty:
                results.append(Result(
                    **common, outcome=Outcome.ORPHANED, reason="NoResourcesLoaded",
                    message=("not deleted: no resources were loaded at all, which is more "
                             "likely a wrong path or an empty mount than an instruction to "
                             "delete everything. Pass --allow-empty if it is intended."),
                ))
            elif options.dry_run:
                results.append(Result(**common, outcome=Outcome.PLANNED, action="delete",
                                      reason="DeleteRequired",
                                      message="no file describes it; will be deleted"))
            else:
                try:
                    client.delete(kind, name)
                except ClientError as exc:
                    results.append(Result(**common, outcome=Outcome.FAILED, message=str(exc),
                                          reason="DeleteFailed"))
                    continue
                results.append(Result(**common, outcome=Outcome.DELETED,
                                      message="no file describes it any more"))
    return results


# --------------------------------------------------------------------------- #
# A whole run
# --------------------------------------------------------------------------- #

def reconcile_all(
    resources: list[Resource],
    client: AquaClient,
    options: Options,
    state: StateBackend | None = None,
) -> RunSummary:
    """Reconcile every resource, then deal with orphans.

    All creates and updates happen before any delete, so a Git-side rename --
    which is a new object plus an orphan -- never leaves a moment with neither
    policy in place. One failure does not stop the rest.
    """
    marker.validate_instance(options.instance)
    kinds = {k.kind: k for k in options.kinds}
    summary = RunSummary()

    for resource in resources:
        kind = kinds.get(resource.kind)
        if kind is None:
            summary.add(Result(kind=resource.kind, name=resource.metadata.name,
                               outcome=Outcome.FAILED, reason="UnknownKind",
                               message=f"no registered kind {resource.kind!r}"))
            continue
        summary.add(reconcile(resource, kind, client, options, state))

    summary.results.extend(_orphans(resources, client, options))
    return summary
