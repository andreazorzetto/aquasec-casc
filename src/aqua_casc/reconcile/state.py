"""Where ``status`` lives in push mode, and the identity mapping.

There is no Kubernetes API server here to hold status, so it goes in a file
committed alongside the config: visible, diffable, survives in Git, works
air-gapped, needs no infrastructure.

The backend is an interface so phase 2 can swap the file for the Kubernetes API
without the reconciler noticing. That is the whole point of keeping this
separate: ``StateBackend`` is the seam.

Identity
--------
Aqua keys its policy and enforcer-group endpoints by *name* in the URL, not by a
numeric ID. So the mapping we record is name-to-name:

    metadata.name (ours, stable, never changes)  ->  aquaName (what Aqua calls it)

That indirection is what makes a rename detectable. If the file's
``spec.aquaName`` differs from the ``aquaName`` in state under the same
``metadata.name``, that is unambiguously a rename and not a create -- which
matters, because Aqua has no rename primitive and the naive behaviour (what the
Terraform provider does) is to orphan the old object and create a duplicate. In
an enforce-mode production scope that is a live security incident.
"""

from __future__ import annotations

import os
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

import yaml

STATE_DIR = ".aqua-casc"
STATE_FILE = "state.yaml"
STATE_VERSION = 1

# Keys that must never reach the state file. Enforcer group objects carry a
# registration token, directly or embedded in a ready-to-run install command,
# and the state file is designed to be committed to Git.
FORBIDDEN_KEYS = ("token", "install_command", "command", "pas_deployment_link",
                  "password", "secret")


class StateError(Exception):
    """Raised when state is unreadable, malformed, or would leak a secret."""


def _utcnow() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


@dataclass
class ResourceState:
    """What we know about one managed object between runs.

    Mirrors ``schema.base.ResourceStatus`` field for field, so the phase 2
    operator can write the same structure to ``.status`` unchanged.
    """

    kind: str
    name: str
    """Our stable identity -- ``metadata.name``. Never changes."""

    aquaName: str | None = None
    """The name Aqua currently knows the object by. May change; see rename."""

    aquaId: int | None = None
    """Aqua's numeric ID where one exists. Recorded for traceability only --
    it is not a usable lookup key on any endpoint we manage."""

    observedGeneration: int = 0
    lastAppliedFields: list[str] = field(default_factory=list)
    """API field paths we set on the last successful apply. The third input to
    the three-way diff."""

    lastSyncTime: str | None = None

    @property
    def key(self) -> str:
        return f"{self.kind}/{self.name}"

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data.pop("kind")
        data.pop("name")
        return data

    @classmethod
    def from_dict(cls, kind: str, name: str, data: dict[str, Any]) -> "ResourceState":
        known = {f for f in cls.__dataclass_fields__ if f not in ("kind", "name")}
        unknown = set(data) - known
        if unknown:
            raise StateError(
                f"state entry {kind}/{name} has unrecognised keys: "
                f"{', '.join(sorted(unknown))}. This state file may have been "
                "written by a newer version of the tool."
            )
        return cls(kind=kind, name=name, **data)


@dataclass(frozen=True)
class RenameDetected:
    """The file wants a different Aqua name than the one we recorded."""

    kind: str
    name: str
    from_name: str
    to_name: str

    def render(self) -> str:
        return (
            f"{self.kind}/{self.name}: Aqua name would change "
            f"{self.from_name!r} -> {self.to_name!r}"
        )


class StateBackend(Protocol):
    """The seam phase 2 replaces with the Kubernetes API."""

    def get(self, kind: str, name: str) -> ResourceState | None: ...

    def put(self, state: ResourceState) -> None: ...

    def delete(self, kind: str, name: str) -> None: ...

    def all(self) -> list[ResourceState]: ...

    def commit(self) -> None:
        """Persist. A backend that writes through may make this a no-op."""
        ...


def assert_not_ownable(paths: list[str], where: str = "") -> None:
    """Refuse to claim ownership of a credential-bearing API field.

    This is the leak vector that can actually occur. An enforcer group object
    carries its registration token in ``token``, and the same value again inside
    ``install_command`` and ``pas_deployment_link``. If any of those ended up in
    ``lastAppliedFields`` then two bad things follow: the path is written to the
    state file, which is designed to be committed to Git, and the reconciler
    treats the field as ours and writes it back on every apply.

    Checked here rather than at the client boundary because state is the thing
    that persists: a token in a log line is bad, a token in Git history is not
    something you can meaningfully undo.
    """
    offenders = sorted(
        p for p in paths
        if any(f == p.split(".")[-1].lower() or f == p.lower() for f in FORBIDDEN_KEYS)
    )
    if offenders:
        raise StateError(
            f"refusing to write state{f' for {where}' if where else ''}: "
            f"{', '.join(offenders)} carries a credential and must never be "
            "managed as configuration. Enforcer tokens go to "
            "spec.tokenSecretRef, never into Git."
        )


def _assert_no_secret_values(payload: Any, path: str = "") -> None:
    """Defence in depth against a credential-shaped value anywhere in state.

    Currently no declared ``ResourceState`` field can hold one, so this guards
    against a future field or an alternative backend rather than against
    anything reachable today. It is cheap, and the failure it prevents is
    irreversible.
    """
    if isinstance(payload, dict):
        for key, value in payload.items():
            here = f"{path}.{key}" if path else key
            if any(f in key.lower() for f in FORBIDDEN_KEYS) and value not in (
                None, "", [], {}, False,
            ):
                raise StateError(
                    f"refusing to write state: {here} looks like a credential. "
                    "Tokens and secrets must never enter the state file."
                )
            _assert_no_secret_values(value, here)
    elif isinstance(payload, list):
        for i, item in enumerate(payload):
            _assert_no_secret_values(item, f"{path}[{i}]")


class FileStateBackend:
    """State in ``.aqua-casc/state.yaml``, next to the config it describes."""

    def __init__(self, root: Path | str, *, create: bool = True) -> None:
        self.root = Path(root)
        self.path = self.root / STATE_DIR / STATE_FILE
        self._create = create
        self._entries: dict[str, ResourceState] = {}
        self._loaded = False

    # -- loading ----------------------------------------------------------- #

    def load(self) -> "FileStateBackend":
        self._entries = {}
        self._loaded = True

        if not self.path.exists():
            return self

        try:
            raw = yaml.safe_load(self.path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise StateError(f"{self.path}: invalid YAML: {exc}") from exc

        if not isinstance(raw, dict):
            raise StateError(f"{self.path}: expected a mapping at the top level")

        version = raw.get("version")
        if version is not None and version != STATE_VERSION:
            raise StateError(
                f"{self.path}: state version {version} is not supported by this "
                f"build (expected {STATE_VERSION})"
            )

        for key, data in (raw.get("resources") or {}).items():
            if "/" not in key:
                raise StateError(f"{self.path}: malformed state key {key!r}")
            kind, _, name = key.partition("/")
            self._entries[key] = ResourceState.from_dict(kind, name, data or {})

        return self

    def _ensure_loaded(self) -> None:
        if not self._loaded:
            self.load()

    # -- StateBackend ------------------------------------------------------- #

    def get(self, kind: str, name: str) -> ResourceState | None:
        self._ensure_loaded()
        return self._entries.get(f"{kind}/{name}")

    def put(self, state: ResourceState) -> None:
        self._ensure_loaded()
        self._entries[state.key] = state

    def delete(self, kind: str, name: str) -> None:
        self._ensure_loaded()
        self._entries.pop(f"{kind}/{name}", None)

    def all(self) -> list[ResourceState]:
        self._ensure_loaded()
        return [self._entries[k] for k in sorted(self._entries)]

    def commit(self) -> None:
        """Write the state file atomically.

        Atomic because a half-written state file is worse than none: it would
        lose the identity mapping for everything after the truncation point, and
        the next apply would treat those objects as unmanaged and recreate them.
        """
        self._ensure_loaded()

        for key in sorted(self._entries):
            assert_not_ownable(self._entries[key].lastAppliedFields, where=key)

        payload = {
            "version": STATE_VERSION,
            "resources": {k: self._entries[k].to_dict() for k in sorted(self._entries)},
        }
        _assert_no_secret_values(payload)

        if not self._create and not self.path.parent.exists():
            raise StateError(f"{self.path.parent} does not exist")

        self.path.parent.mkdir(parents=True, exist_ok=True)

        fd, tmp = tempfile.mkstemp(dir=self.path.parent, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(
                    "# Written by aqua-casc. Commit this file: it is the mapping\n"
                    "# between names in Git and objects in Aqua, and the record of\n"
                    "# which fields this tool owns. Do not edit by hand.\n"
                )
                yaml.safe_dump(payload, fh, sort_keys=False, default_flow_style=False)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise

    # -- identity ----------------------------------------------------------- #

    def record(
        self,
        kind: str,
        name: str,
        aqua_name: str,
        owned_fields: list[str],
        aqua_id: int | None = None,
    ) -> ResourceState:
        """Record a successful create or update."""
        assert_not_ownable(owned_fields, where=f"{kind}/{name}")

        existing = self.get(kind, name)
        state = ResourceState(
            kind=kind,
            name=name,
            aquaName=aqua_name,
            aquaId=aqua_id if aqua_id is not None else (existing.aquaId if existing else None),
            observedGeneration=(existing.observedGeneration + 1) if existing else 1,
            lastAppliedFields=sorted(set(owned_fields)),
            lastSyncTime=_utcnow(),
        )
        self.put(state)
        return state

    def detect_rename(self, kind: str, name: str, desired_aqua_name: str) -> RenameDetected | None:
        """Whether this document renames an object we already manage.

        Returns None for anything unmanaged: if there is no state entry we have
        no basis to claim ownership, so it is a create (or an adoption), never a
        rename.
        """
        existing = self.get(kind, name)
        if existing is None or not existing.aquaName:
            return None
        if existing.aquaName == desired_aqua_name:
            return None
        return RenameDetected(
            kind=kind,
            name=name,
            from_name=existing.aquaName,
            to_name=desired_aqua_name,
        )

    def orphans(self, present: set[tuple[str, str]]) -> list[ResourceState]:
        """Managed objects whose files have disappeared from Git.

        Deleting these is opt-in twice over (``spec.deletionPolicy: Delete``
        plus ``--allow-delete``), so this only reports them.
        """
        self._ensure_loaded()
        return [s for s in self.all() if (s.kind, s.name) not in present]
