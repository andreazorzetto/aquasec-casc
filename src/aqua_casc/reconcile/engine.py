"""Reconcile desired state against a live Aqua tenant.

Prints nothing, exits nothing, imports nothing from the CLI. The same function
serves ``diff`` (dry_run=True), ``apply`` (dry_run=False), and -- in phase 2 --
an operator's reconcile loop, unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..schema.base import Enforcement, Resource
from ..schema.registry import KindDef
from .client import AquaClient, ClientError
from .diff import ReleasePolicy, three_way_diff
from .result import Outcome, Result, RunSummary
from .state import RenameDetected, StateBackend, StateError


@dataclass(frozen=True)
class Options:
    """Safety switches. Every default is the cautious one."""

    dry_run: bool = False

    release_policy: ReleasePolicy = ReleasePolicy.RETAIN

    allow_rename: bool = False
    """Required to rename an object in an enforce-mode scope.

    A rename is create-new-then-delete-old, because Aqua has no rename
    primitive. In audit mode that is safe enough to do automatically. In
    enforce mode there is a window where both policies exist and both apply,
    and two policies covering the same images is the shape of the incident this
    tool was built to prevent -- so that case asks first.
    """

    allow_delete: bool = False
    """Required, in addition to ``spec.deletionPolicy: Delete``, before
    anything is removed. Two independent opt-ins, per resource and per run."""

    allow_recreate_missing: bool = False
    """Required to recreate an object that state says we manage but Aqua no
    longer has. Silently recreating it could resurrect a policy somebody
    deliberately removed, so by default this stops and asks."""


def _canonical(resource: Resource) -> dict:
    """Only the fields the author actually wrote.

    ``exclude_unset`` is load-bearing: a schema default is not a statement of
    intent, and treating one as owned would make the first apply write our
    defaults over the console's configuration.
    """
    return resource.model_dump(exclude_unset=True, mode="json")


def reconcile(
    resource: Resource,
    kind: KindDef,
    state: StateBackend,
    client: AquaClient,
    options: Options | None = None,
) -> Result:
    """Bring one resource into line, or describe what it would take."""
    options = options or Options()

    canonical = _canonical(resource)
    desired = kind.field_map.to_api(canonical)
    owned = kind.field_map.owned_api_paths(canonical)

    recorded = state.get(resource.kind, resource.metadata.name)
    desired_aqua_name = resource.aqua_name

    # Look the object up under the name we last saw it as. Falling back to the
    # desired name is what makes adoption work on a tenant we have never
    # touched: no state, so look for what the file calls it.
    lookup_name = recorded.aquaName if (recorded and recorded.aquaName) else desired_aqua_name

    rename = state.detect_rename(
        resource.kind, resource.metadata.name, desired_aqua_name
    )

    try:
        actual = client.get(kind, lookup_name)
    except ClientError as exc:
        return Result(
            kind=resource.kind, name=resource.metadata.name, outcome=Outcome.FAILED,
            aqua_name=lookup_name, message=str(exc), reason="LookupFailed",
        )

    if rename is not None:
        return _handle_rename(
            resource, kind, state, client, options, rename, actual, desired, owned
        )

    if actual is None:
        return _handle_absent(
            resource, kind, state, client, options, recorded, desired_aqua_name,
            desired, owned,
        )

    plan = three_way_diff(
        desired=desired,
        actual=actual,
        last_applied=recorded.lastAppliedFields if recorded else None,
        release_policy=options.release_policy,
    )

    if plan.is_empty():
        # Still record: adoption of a previously unmanaged object is exactly
        # this case, and it is what makes the next run's diff three-way.
        if not options.dry_run:
            state.record(
                resource.kind, resource.metadata.name, lookup_name, owned,
                aqua_id=_aqua_id(actual),
            )
        return Result(
            kind=resource.kind, name=resource.metadata.name, outcome=Outcome.IN_SYNC,
            aqua_name=lookup_name, plan=plan,
        )

    if options.dry_run:
        return Result(
            kind=resource.kind, name=resource.metadata.name, outcome=Outcome.PLANNED,
            aqua_name=lookup_name, plan=plan, reason="UpdateRequired",
        )

    if resource.spec.enforcement is Enforcement.REPORT_ONLY:
        return Result(
            kind=resource.kind, name=resource.metadata.name,
            outcome=Outcome.DRIFT_DETECTED, aqua_name=lookup_name, plan=plan,
            reason="ReportOnly",
            message="drift detected; spec.enforcement is ReportOnly so nothing was changed",
        )

    try:
        client.update(kind, lookup_name, plan.apply_to(actual))
    except ClientError as exc:
        return Result(
            kind=resource.kind, name=resource.metadata.name, outcome=Outcome.FAILED,
            aqua_name=lookup_name, plan=plan, message=str(exc), reason="UpdateFailed",
        )

    _record(state, resource, lookup_name, owned, actual)
    return Result(
        kind=resource.kind, name=resource.metadata.name, outcome=Outcome.UPDATED,
        aqua_name=lookup_name, plan=plan,
    )


def _aqua_id(actual: dict) -> int | None:
    value = actual.get("id")
    return value if isinstance(value, int) else None


def _record(state, resource, aqua_name, owned, actual) -> None:
    state.record(
        resource.kind, resource.metadata.name, aqua_name, owned,
        aqua_id=_aqua_id(actual or {}),
    )


def _handle_absent(
    resource, kind, state, client, options, recorded, desired_aqua_name, desired, owned
) -> Result:
    """Nothing on the server under the name we looked for."""

    # We have state saying we manage this, but Aqua does not have it. Something
    # happened outside the tool. Recreating silently could resurrect a policy
    # somebody deliberately deleted, so stop and say so.
    if recorded is not None and recorded.aquaName and not options.allow_recreate_missing:
        return Result(
            kind=resource.kind, name=resource.metadata.name, outcome=Outcome.BLOCKED,
            aqua_name=recorded.aquaName, reason="ManagedObjectMissing",
            message=(
                f"state says we manage {recorded.aquaName!r} but Aqua has no such "
                f"{resource.kind}. It may have been deleted in the console. "
                "Re-create it with --allow-recreate-missing, or remove the entry "
                "from state if it is gone for good."
            ),
        )

    body = dict(desired)
    body["name"] = desired_aqua_name

    if options.dry_run:
        plan = three_way_diff(desired=body, actual={}, last_applied=None)
        return Result(
            kind=resource.kind, name=resource.metadata.name, outcome=Outcome.PLANNED,
            aqua_name=desired_aqua_name, plan=plan, reason="CreateRequired",
        )

    try:
        created = client.create(kind, body)
    except ClientError as exc:
        return Result(
            kind=resource.kind, name=resource.metadata.name, outcome=Outcome.FAILED,
            aqua_name=desired_aqua_name, message=str(exc), reason="CreateFailed",
        )

    _record(state, resource, desired_aqua_name, owned, created or {})
    return Result(
        kind=resource.kind, name=resource.metadata.name, outcome=Outcome.CREATED,
        aqua_name=desired_aqua_name,
    )


def _handle_rename(
    resource, kind, state, client, options, rename: RenameDetected, actual,
    desired, owned,
) -> Result:
    """The file wants a different Aqua name than the one we recorded.

    Aqua has no rename primitive -- the name is the key in the URL -- so this is
    create-new then delete-old, in that order. Never delete-first: a failure
    between the two steps must leave the policy in place, not absent.
    """
    enforcing = bool(getattr(resource.spec, "enforce", False))

    if enforcing and not options.allow_rename:
        return Result(
            kind=resource.kind, name=resource.metadata.name, outcome=Outcome.BLOCKED,
            aqua_name=rename.from_name, rename=rename, reason="RenameInEnforceMode",
            message=(
                f"{rename.render()}. Aqua cannot rename in place, so this is a "
                "create followed by a delete, and for a moment both policies "
                "exist and both apply. In an enforce-mode scope that is how "
                "workloads get blocked unexpectedly. Re-run with --allow-rename "
                "if that is acceptable."
            ),
        )

    if options.dry_run:
        return Result(
            kind=resource.kind, name=resource.metadata.name, outcome=Outcome.PLANNED,
            aqua_name=rename.to_name, rename=rename, reason="RenameRequired",
            message=f"{rename.render()} (create then delete; no in-place rename exists)",
        )

    body = dict(desired)
    body["name"] = rename.to_name

    try:
        created = client.create(kind, body)
    except ClientError as exc:
        return Result(
            kind=resource.kind, name=resource.metadata.name, outcome=Outcome.FAILED,
            aqua_name=rename.from_name, rename=rename, reason="RenameCreateFailed",
            message=(
                f"could not create {rename.to_name!r}: {exc}. The original "
                f"{rename.from_name!r} has been left untouched."
            ),
        )

    try:
        if actual is not None:
            client.delete(kind, rename.from_name)
    except ClientError as exc:
        # The new object exists; the old one could not be removed. Record the
        # new name so we do not create a third on the next run, and say plainly
        # that a duplicate is live -- this is precisely the orphan-and-duplicate
        # situation that must never pass silently.
        _record(state, resource, rename.to_name, owned, created or {})
        return Result(
            kind=resource.kind, name=resource.metadata.name, outcome=Outcome.FAILED,
            aqua_name=rename.to_name, rename=rename, reason="RenameDeleteFailed",
            message=(
                f"created {rename.to_name!r} but could not delete the old "
                f"{rename.from_name!r}: {exc}. BOTH now exist in Aqua and both "
                "apply. Remove the old one manually."
            ),
        )

    _record(state, resource, rename.to_name, owned, created or {})
    return Result(
        kind=resource.kind, name=resource.metadata.name, outcome=Outcome.RENAMED,
        aqua_name=rename.to_name, rename=rename,
        message=f"{rename.from_name!r} -> {rename.to_name!r} (created, then removed the old)",
    )


def reconcile_all(
    resources: list[Resource],
    registry_get,
    state: StateBackend,
    client: AquaClient,
    options: Options | None = None,
) -> RunSummary:
    """Reconcile every resource, then report orphans.

    One resource failing does not stop the others: a run that abandons half the
    tree on the first error leaves the tenant in a state nobody planned.
    """
    options = options or Options()
    summary = RunSummary()

    for resource in resources:
        try:
            kind = registry_get(resource.kind)
            summary.add(reconcile(resource, kind, state, client, options))
        except (ClientError, StateError, KeyError) as exc:
            summary.add(
                Result(
                    kind=resource.kind, name=resource.metadata.name,
                    outcome=Outcome.FAILED, message=str(exc), reason="ReconcileFailed",
                )
            )

    summary.results.extend(
        _report_orphans(resources, state, client, options)
    )

    if not options.dry_run:
        state.commit()

    return summary


def _report_orphans(resources, state, client, options) -> list[Result]:
    """Managed objects whose files have gone from Git.

    Default is Orphan: removing a file must not silently delete a production
    enforcement policy. Deletion needs ``spec.deletionPolicy: Delete`` on the
    resource *and* ``--allow-delete`` on the run -- and since the file is gone,
    the per-resource opt-in is no longer readable, so this can only ever report.
    """
    present = {(r.kind, r.metadata.name) for r in resources}
    results = []

    for orphan in state.orphans(present):
        results.append(
            Result(
                kind=orphan.kind, name=orphan.name, outcome=Outcome.BLOCKED,
                aqua_name=orphan.aquaName, reason="Orphaned",
                message=(
                    f"{orphan.aquaName!r} is managed in state but no file "
                    "describes it any more. It has been left in place. Delete it "
                    "in Aqua by hand if that is what you want, then remove its "
                    "state entry."
                ),
            )
        )
    return results
