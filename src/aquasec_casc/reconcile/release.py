"""Release: hand objects back to the console, or over to another instance.

The way out of management that deletes nothing. Deleting the files would delete
the objects (that is what Git-driven deletion means), and ``--no-delete`` leaves
marked objects without files -- one run without the flag deletes them. Release
removes this instance's marker and changes nothing else, so the objects carry on
exactly as they are, simply unmanaged.

With ``to``, the marker is rewritten instead of removed: the objects move to
another instance (another team or repository, or a renamed instance) in one
step, never passing through an unmanaged moment.

It needs no YAML. Objects are found by this instance's marker, so it still works
after the repository is gone.

Order matters, and the caller should say so: release first, then remove the
files or stop the pipeline. While both remain, the next apply adopts the
objects again.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field

from ..schema.registry import REGISTRY, KindDef
from . import marker
from .client import AquaClient, ClientError
from .result import Outcome, Result, RunSummary


@dataclass(frozen=True)
class ReleaseOptions:
    instance: str
    """The instance whose objects are released."""

    to: str | None = None
    """Hand over to this instance instead of leaving the objects unmanaged."""

    names: tuple[str, ...] = ()
    """Only objects whose Aqua name matches one of these globs. Empty: all."""

    dry_run: bool = False

    kinds: tuple[KindDef, ...] = field(default_factory=lambda: tuple(REGISTRY.values()))


def released_description(description: str | None, to: str | None) -> str:
    """The description after release: the human text, re-marked only for ``to``."""
    return marker.compose(description, to) if to else marker.strip(description)


def release_all(client: AquaClient, options: ReleaseOptions) -> RunSummary:
    """Release every object this instance marks (and ``names`` selects).

    Only the description is written, and only its marker line changes. Objects
    of other instances and unmarked objects are never touched. One failure does
    not stop the rest.
    """
    marker.validate_instance(options.instance)
    if options.to is not None:
        marker.validate_instance(options.to)
        if options.to == options.instance:
            raise ValueError(f"--to {options.to!r} is this instance already")

    summary = RunSummary()
    action = "hand-over" if options.to else "release"
    target = f"'{marker.marker(options.to)}'" if options.to else ""
    done = (f"now carries {target}" if options.to
            else "marker removed; the object is no longer managed")

    for kind in options.kinds:
        if not kind.collection:
            continue
        try:
            objects = client.list(kind)
        except ClientError as exc:
            summary.add(Result(kind=kind.kind, name="*", outcome=Outcome.FAILED,
                               reason="ListFailed",
                               message=f"could not list {kind.kind} objects: {exc}"))
            continue

        for obj in sorted(objects, key=lambda o: str(kind.key_of(o) or "")):
            if not obj.get(kind.name_field):
                continue
            name = kind.key_of(obj)
            if marker.owner(obj.get("description")) != options.instance:
                continue
            if options.names and not any(fnmatch.fnmatchcase(n, p) for n in (name, kind.name_of(name))
                                         for p in options.names):
                continue

            common = dict(kind=kind.kind, name=name, aqua_name=name)
            if options.dry_run:
                summary.add(Result(**common, outcome=Outcome.PLANNED, action=action,
                                   message=f"would carry {target}" if options.to else ""))
                continue

            # Update is a full replace, so send the whole object as Aqua has it
            # now -- re-read, not the list summary -- with only the description
            # changed.
            try:
                full = client.get(kind, name)
                if full is None or marker.owner(full.get("description")) != options.instance:
                    summary.add(Result(**common, outcome=Outcome.FAILED, reason="Changed",
                                       message="changed or deleted while releasing; not touched"))
                    continue
                body = dict(full)
                body["description"] = released_description(full.get("description"), options.to)
                client.update(kind, name, body)
            except ClientError as exc:
                summary.add(Result(**common, outcome=Outcome.FAILED, reason="ReleaseFailed",
                                   message=str(exc)))
                continue
            summary.add(Result(**common, outcome=Outcome.RELEASED, action=action, message=done))

    return summary
