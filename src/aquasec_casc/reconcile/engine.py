"""Reconcile desired state against a live Aqua tenant. Stateless.

There is no state file. Each run compares what Git says with what Aqua has:

* every field the YAML mentions is ours, and is corrected when it drifts;
* a control the YAML does not mention is off, and is switched off if it is on
  (``KindDef.off_when_unset``) -- the file is the whole policy;
* any other field the YAML does not mention belongs to Aqua or the console, and
  is left alone (and named, if it changes what the policy covers:
  ``KindDef.held_by_aqua``);
* ownership of the object itself is the marker in its description
  (``marker``), which also tells this instance's objects apart from another's.

The same function serves ``diff`` (dry run), ``apply``, and -- in phase 2 -- an
operator's reconcile loop. It prints nothing and exits nothing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from ..schema.base import Enforcement, Resource
from ..schema.fieldmap import MISSING, get_path, set_path
from ..schema.registry import REGISTRY, KindDef
from . import marker
from .client import AquaClient, ClientError
from .diff import ChangeType, Plan, equivalent, flatten, is_off_value, three_way_diff
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

    scan_orphans: bool = True
    """Off when the run was given part of the configuration, one file: everything
    else this instance owns has no file in the run, and that says nothing."""


# --------------------------------------------------------------------------- #
# Built-ins
# --------------------------------------------------------------------------- #

def is_shipped(kind: KindDef, obj: dict | None) -> bool:
    """Aqua-shipped: never created or deleted by the tool."""
    if not obj:
        return False
    if kind.builtin_field and obj.get(kind.builtin_field) == kind.builtin_value:
        return True
    return kind.key_of(obj) in kind.builtin_names


def is_predefined(kind: KindDef, obj: dict | None, key: str) -> bool:
    """Predefined: shipped *and* on the named list, so certain fields are locked.

    Both are required. The flag stops a customer's own policy that happens to
    reuse a predefined name from being treated as predefined; the name picks
    the locked ones out of everything Aqua ships.
    """
    return is_shipped(kind, obj) and key in kind.predefined


def _touches(path: str, prefixes: Iterable[str]) -> bool:
    return any(path == p or path.startswith(p + ".") for p in prefixes)


def _withheld(kind: KindDef, obj: dict | None, key: str, path: str) -> str | None:
    """Why Aqua would refuse a change to ``path`` on this object, or None.

    Two rules, both matching what the console allows:
    * a predefined object's locked fields (the defaults' scope);
    * fields that exist only on particular system objects (Bypass Scope).
    """
    if is_predefined(kind, obj, key) and _touches(path, kind.predefined_immutable):
        return "cannot change on a default policy"
    for prefix, names in kind.only_on.items():
        if _touches(path, (prefix,)) and not (is_shipped(kind, obj) and key in names):
            return "only available on " + " and ".join(repr(n) for n in sorted(names))
    return None


def _split(kind: KindDef, obj: dict | None, key: str, plan: Plan) -> tuple[Plan, list[str]]:
    """The plan minus changes Aqua would refuse, and a note for each one."""
    kept, refused = [], []
    for change in plan.changes:
        why = _withheld(kind, obj, key, change.path)
        if why:
            refused.append(f"{change.path}: {change.before!r} -> {change.after!r} ({why}; not sent)")
        else:
            kept.append(change)
    return Plan(changes=kept, release_policy=plan.release_policy), refused


# --------------------------------------------------------------------------- #
# One resource
# --------------------------------------------------------------------------- #

def _desired(resource: Resource, kind: KindDef, actual: dict | None, instance: str) -> dict:
    """The API object the YAML asks for, with the ownership marker in place.

    ``exclude_unset`` is load-bearing: a schema default is not a statement of
    intent, so only fields the author wrote are owned -- except under the kind's
    ``off_when_unset`` prefixes, where a field left out means off, and, on a create,
    its ``always_sent`` fields. Those off values are taken against the server
    object, so a create sends none: a new object starts with every control off
    already.

    The marker goes into the description. If the YAML sets a description, that
    text plus the marker is what we want. If it does not, the console's text is
    kept and the marker appended -- the tool must not wipe a description nobody
    asked it to manage.
    """
    # exclude_none: a key with nothing after it, "limitNewPrivileges:", says the
    # same as leaving it out.
    canonical = resource.model_dump(exclude_unset=True, exclude_none=True, mode="json")
    if kind.always_sent and not actual:
        everything = resource.model_dump(mode="json")
        for path in kind.always_sent:
            if get_path(canonical, path) is MISSING:
                set_path(canonical, path, get_path(everything, path))
    desired = kind.field_map.to_api(canonical)
    for under in kind.off_when_unset if actual else ():
        off = kind.field_map.switched_off(canonical, actual, under, keep=kind.kept_when_unset)
        for path, value in flatten(off).items():
            set_path(desired, path, value)

    if kind.collection:
        spec = canonical.get("spec") or {}
        text = spec["description"] if "description" in spec else (actual or {}).get("description")
        desired["description"] = marker.compose(text, instance)

    assert_not_ownable(list(flatten(desired)), where=resource.ref)
    return desired


def _unstated(resource: Resource, kind: KindDef, actual: dict) -> list[str]:
    """Fields the file leaves out and whose default is not what Aqua holds.

    Applying the default could disable a policy, stop it enforcing, or convert a host
    policy into a container one; ignoring it would report in sync with a policy that
    is not what the file reads as. Only the file's author can say which is meant.
    """
    canonical = resource.model_dump(exclude_unset=True, mode="json")
    everything = resource.model_dump(mode="json")
    found = []
    for path in kind.always_sent:
        held = get_path(actual, kind.field_map.for_canonical(path).api)
        if (get_path(canonical, path) is MISSING and held is not MISSING
                and held != get_path(everything, path)):
            found.append(f"{path.removeprefix('spec.')} (Aqua holds {held!r})")
    return found


def _not_kept(kind: KindDef, key: str, plan: Plan, client: AquaClient) -> list[str]:
    """What was sent and is not what Aqua holds now, read back.

    Aqua accepts fields it does not know and drops them, and some versions drop
    fields others keep. Without this the write reports success, and the only sign
    is a plan that never settles.
    """
    try:
        stored = client.get(kind, key)
    except ClientError as exc:
        return [f"could not read the object back to check it: {exc}"]
    missing = []
    for change in plan.changes:
        have = get_path(stored or {}, change.path)
        if have is MISSING and is_off_value(change.after):
            continue                    # off, on a field this version does not have
        if have is MISSING or not equivalent(have, change.after):
            shown = "nothing" if have is MISSING else repr(have)
            missing.append(f"{change.path}: sent {change.after!r}, Aqua holds {shown}")
    return missing


def _held(kind: KindDef, obj: dict | None, then: str) -> list[str]:
    """A note for each setting Aqua holds that the tool does not offer."""
    return [f"{name}: Aqua holds {value!r}, a setting this tool does not offer. {then}"
            for name, value in kind.held_in_aqua(obj).items()]


def _held_when_deleted(kind: KindDef, client: AquaClient, name: str, listed: dict) -> list[str]:
    """What goes with a deleted object. A rename is a delete and a create, and the new
    policy will not hold it, so this is the one place it can be lost."""
    if not kind.held_by_aqua:
        return []
    try:
        full = client.get(kind, name) or listed
    except ClientError:
        full = listed                   # the delete will say so, if Aqua is gone
    return _held(kind, full, "It goes with this policy, and a new one will not hold it.")


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
    key = kind.key(resource)
    common = dict(kind=resource.kind, name=resource.metadata.name, aqua_name=key)
    report_only = getattr(resource.spec, "enforcement", None) is Enforcement.REPORT_ONLY

    try:
        actual = client.get(kind, key)
    except ClientError as exc:
        return Result(**common, outcome=Outcome.FAILED, message=str(exc), reason="LookupFailed")

    common["held"] = _held(kind, actual, "It is not in the file, and stays as it is.")

    try:
        desired = _desired(resource, kind, actual, options.instance)
    except StateError as exc:
        return Result(**common, outcome=Outcome.FAILED, message=str(exc), reason="Refused")

    # ---- missing: create it (this is also how a console deletion is undone) --
    if actual is None:
        body = dict(desired)
        body[kind.name_field] = name
        plan, not_allowed = _split(kind, None, key, three_way_diff(desired=body, actual={}))
        body = plan.apply_to({})
        # ReportOnly first: a dry run must say what apply would do, and apply
        # would not create it.
        if report_only:
            return Result(**common, outcome=Outcome.DRIFT_DETECTED, plan=plan, reason="Missing",
                          not_allowed=not_allowed,
                          message="does not exist in Aqua; ReportOnly, so not created")
        if options.dry_run:
            return Result(**common, outcome=Outcome.PLANNED, action="create", plan=plan,
                          not_allowed=not_allowed, reason="CreateRequired")
        try:
            created = client.create(kind, body)
        except ClientError as exc:
            return Result(**common, outcome=Outcome.FAILED, message=str(exc), reason="CreateFailed")
        state.record(resource.kind, resource.metadata.name, aqua_name=name,
                     aqua_id=_aqua_id(created))
        return Result(**common, outcome=Outcome.CREATED, plan=plan, not_allowed=not_allowed,
                      not_kept=_not_kept(kind, key, plan, client))

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

    # Not "the rest still applies": a host policy's controls written onto a container
    # policy would switch off what that policy does, and it would still be a container
    # policy. The file describes some other policy.
    for path in kind.immutable:
        wanted, held = get_path(desired, path), get_path(actual, path)
        if wanted is not MISSING and held is not MISSING and wanted != held:
            return Result(**common, outcome=Outcome.FAILED, reason="Immutable",
                          message=(f"{path}: the file says {wanted!r}, Aqua holds {held!r}, and it "
                                   "cannot change. Name a new policy, or correct the file; nothing "
                                   "was changed."))

    unstated = _unstated(resource, kind, actual)
    if unstated:
        return Result(**common, outcome=Outcome.FAILED, reason="Unstated",
                      message=("the file does not say, and Aqua differs from the default: "
                               f"{', '.join(unstated)}. Write it in the file; nothing was changed."))

    # Changes Aqua would refuse are reported, not sent; the rest still applies.
    wanted = three_way_diff(desired=desired, actual=actual)
    # Off on a field this Aqua version does not have is off already.
    wanted.changes = [c for c in wanted.changes
                      if not (c.change is ChangeType.ADD and is_off_value(c.after))]
    plan, not_allowed = _split(kind, actual, key, wanted)

    if plan.is_empty():
        return Result(**common, outcome=Outcome.IN_SYNC, plan=plan, not_allowed=not_allowed)

    action = "adopt" if adopting else "update"
    if report_only:
        return Result(**common, outcome=Outcome.DRIFT_DETECTED, plan=plan, not_allowed=not_allowed,
                      reason="ReportOnly",
                      message="drift detected; spec.enforcement is ReportOnly, so apply changes nothing")
    if options.dry_run:
        return Result(**common, outcome=Outcome.PLANNED, action=action, plan=plan,
                      not_allowed=not_allowed,
                      reason="AdoptRequired" if adopting else "UpdateRequired")

    try:
        client.update(kind, key, plan.apply_to(actual))
    except ClientError as exc:
        return Result(**common, outcome=Outcome.FAILED, plan=plan, message=str(exc),
                      reason="UpdateFailed")

    state.record(resource.kind, resource.metadata.name, aqua_name=name, aqua_id=_aqua_id(actual))
    return Result(**common, outcome=Outcome.ADOPTED if adopting else Outcome.UPDATED,
                  plan=plan, not_allowed=not_allowed,
                  not_kept=_not_kept(kind, key, plan, client))


def _aqua_id(obj: dict | None) -> int | None:
    value = (obj or {}).get("id")
    return value if isinstance(value, int) else None


# --------------------------------------------------------------------------- #
# Orphans
# --------------------------------------------------------------------------- #

def _missed(results: list[Result]) -> set[str]:
    """Kinds where a file's object did not end up in Aqua.

    The orphan might be what that file replaces: a rename is a new object and an
    orphan. Deleting it would leave neither.
    """
    return {r.kind for r in results
            if r.failed or r.outcome is Outcome.BLOCKED
            or (r.outcome is Outcome.DRIFT_DETECTED and r.reason == "Missing")}


def _orphans(resources: list[Resource], client: AquaClient, options: Options,
             missed: set[str]) -> list[Result]:
    """Objects carrying this instance's marker that no file describes.

    Deleted by default -- removing a file from Git removes the object, as with
    Argo CD pruning. Never deleted: another instance's objects, unmarked
    objects, and anything Aqua ships. Held back: everything of a kind with no file
    in this run (more likely a wrong path than an instruction to delete them all),
    and of a kind where something failed.
    """
    results: list[Result] = []

    for kind in options.kinds:
        if not kind.collection:
            continue

        loaded = [r for r in resources if r.kind == kind.kind]
        wanted = {kind.key(r) for r in loaded}
        try:
            objects = client.list(kind)
        except ClientError as exc:
            results.append(Result(kind=kind.kind, name="*", outcome=Outcome.FAILED,
                                  reason="OrphanScanFailed",
                                  message=f"could not list {kind.kind} objects: {exc}"))
            continue

        for obj in objects:
            if not obj.get(kind.name_field):
                continue
            name = kind.key_of(obj)
            if name in wanted:
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
                             f"ownership marker; run 'release --name \"{name}\"' to "
                             "stop managing it."),
                ))
            elif options.no_delete:
                results.append(Result(**common, outcome=Outcome.ORPHANED, reason="DeletionDisabled",
                                      message="orphaned, not deleted (--no-delete)"))
            elif not loaded and not options.allow_empty:
                results.append(Result(
                    **common, outcome=Outcome.ORPHANED, reason="NoResourcesLoaded",
                    message=("not deleted: no resources of this kind were loaded, which is "
                             "more likely a wrong path or an empty mount than an instruction "
                             "to delete them all. Pass --allow-empty if it is intended."),
                ))
            elif kind.kind in missed:
                results.append(Result(
                    **common, outcome=Outcome.ORPHANED, reason="HeldBack",
                    message=("not deleted: another file of this kind is not in Aqua as written "
                             "(it failed, is blocked, or is ReportOnly and new), and it may be "
                             "what replaces this one. It goes on the first run where they land."),
                ))
            elif options.dry_run:
                results.append(Result(**common, outcome=Outcome.PLANNED, action="delete",
                                      reason="DeleteRequired",
                                      held=_held_when_deleted(kind, client, name, obj),
                                      message="no file describes it; will be deleted"))
            else:
                held = _held_when_deleted(kind, client, name, obj)
                try:
                    client.delete(kind, name)
                except ClientError as exc:
                    results.append(Result(**common, outcome=Outcome.FAILED, message=str(exc),
                                          reason="DeleteFailed"))
                    continue
                results.append(Result(**common, outcome=Outcome.DELETED, held=held,
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

    if options.scan_orphans:
        summary.results.extend(_orphans(resources, client, options, _missed(summary.results)))
    return summary
