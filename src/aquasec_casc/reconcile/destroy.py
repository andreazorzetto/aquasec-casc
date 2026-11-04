"""Destroy: delete what this instance manages, without touching Git.

Two scopes:

* **Given resources** (``destroy -f DIR``): the objects those files describe.
* **No resources** (plain ``destroy``): every object carrying this instance's
  marker -- found the same way as ``release``, so it works without the files.

Never deleted, whichever the scope: objects without this instance's marker
(unmarked console objects, another instance's objects) -- reported as blocked;
and objects Aqua ships, which Aqua refuses to delete -- those are released
instead, so nothing is left marked.

Like ``release``, the effect lasts only while nothing re-applies the files: if
they and the pipeline remain, the next apply recreates everything.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..schema.base import Resource
from ..schema.registry import REGISTRY, KindDef
from . import marker
from .client import AquaClient, ClientError
from .engine import is_shipped
from .result import Outcome, Result, RunSummary

SHIPPED = "shipped by Aqua and cannot be deleted; released instead (marker removed)"


@dataclass(frozen=True)
class DestroyOptions:
    instance: str

    resources: tuple[Resource, ...] | None = None
    """The objects to destroy, as files describe them. None: everything this
    instance marks."""

    names: tuple[str, ...] = ()
    """Only objects whose Aqua name matches one of these globs. Empty: all."""

    dry_run: bool = False

    kinds: tuple[KindDef, ...] = field(default_factory=lambda: tuple(REGISTRY.values()))


def _selected(kind: KindDef, key: str, names: tuple[str, ...]) -> bool:
    return not names or kind.matches(key, names)


def _targets(client: AquaClient, kind: KindDef, options: DestroyOptions,
             summary: RunSummary) -> list[tuple[str, str]]:
    """``(file name, key in Aqua)`` pairs to consider, in a stable order."""
    if options.resources is not None:
        return sorted((r.metadata.name, kind.key(r)) for r in options.resources
                      if r.kind == kind.kind and _selected(kind, kind.key(r), options.names))
    try:
        objects = client.list(kind)
    except ClientError as exc:
        summary.add(Result(kind=kind.kind, name="*", outcome=Outcome.FAILED, reason="ListFailed",
                           message=f"could not list {kind.kind} objects: {exc}"))
        return []
    return sorted((kind.key_of(o), kind.key_of(o)) for o in objects
                  if o.get(kind.name_field)
                  and marker.owner(o.get("description")) == options.instance
                  and _selected(kind, kind.key_of(o), options.names))


def destroy_all(client: AquaClient, options: DestroyOptions) -> RunSummary:
    """Delete (or, for shipped objects, release) everything selected.

    Each object is re-read and its marker checked just before acting on it.
    One failure does not stop the rest.
    """
    marker.validate_instance(options.instance)
    summary = RunSummary()

    for kind in options.kinds:
        if not kind.collection:
            continue
        for name, aqua_name in _targets(client, kind, options, summary):
            common = dict(kind=kind.kind, name=name, aqua_name=aqua_name)
            try:
                obj = client.get(kind, aqua_name)
            except ClientError as exc:
                summary.add(Result(**common, outcome=Outcome.FAILED, reason="LookupFailed",
                                   message=str(exc)))
                continue

            if obj is None:
                summary.add(Result(**common, outcome=Outcome.IN_SYNC, reason="Absent",
                                   message="not in Aqua; nothing to destroy"))
                continue

            found = marker.owner(obj.get("description"))
            if found != options.instance:
                why = (f"managed by another instance ({marker.PREFIX}{found})" if found
                       else "not managed by this tool (no ownership marker)")
                summary.add(Result(**common, outcome=Outcome.BLOCKED, reason="NotOwned",
                                   message=f"{why}; not deleted"))
                continue

            shipped = is_shipped(kind, obj)
            action = "release" if shipped else "delete"
            if options.dry_run:
                summary.add(Result(**common, outcome=Outcome.PLANNED, action=action,
                                   message=SHIPPED if shipped else ""))
                continue

            try:
                if shipped:
                    body = dict(obj)
                    body["description"] = marker.strip(obj.get("description"))
                    client.update(kind, aqua_name, body)
                else:
                    client.delete(kind, aqua_name)
            except ClientError as exc:
                summary.add(Result(**common, outcome=Outcome.FAILED,
                                   reason="ReleaseFailed" if shipped else "DeleteFailed",
                                   message=str(exc)))
                continue

            if shipped:
                summary.add(Result(**common, outcome=Outcome.RELEASED, action="release",
                                   message=SHIPPED))
            else:
                summary.add(Result(**common, outcome=Outcome.DELETED))

    return summary
