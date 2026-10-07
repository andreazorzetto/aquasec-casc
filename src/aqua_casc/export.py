"""Export: existing Aqua configuration as schema-valid YAML documents.

Read-only. This is the adoption path: export, commit, apply -- and the first
apply only adds the ownership marker ("adopted"), after which every apply is a
no-op until someone changes something.

Pure: returns documents, writes nothing. The CLI decides where they go.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError

from .reconcile import marker
from .reconcile.client import AquaClient
from .schema.base import API_VERSION
from .schema.registry import KindDef

_NON_NAME = re.compile(r"[^a-z0-9]+")
_CAMEL = re.compile(r"(?<!^)(?=[A-Z])")


def slugify(name: str) -> str:
    """A DNS-1123 name for ``metadata.name``: "Aqua default runtime policy" ->
    "aqua-default-runtime-policy". Falls back to "unnamed" if nothing is left."""
    slug = _NON_NAME.sub("-", name.lower()).strip("-")[:253].strip("-")
    return slug or "unnamed"


def kind_filename_prefix(kind: str) -> str:
    """RuntimePolicy -> runtime-policy."""
    return _CAMEL.sub("-", kind).lower()


def _prune(value: Any) -> Any:
    """Drop None leaves and the dicts left empty by doing so.

    Aqua returns null for unset lists and blocks; leaving them in would fail
    validation (a list field is not nullable) and write noise into Git.
    """
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            v = _prune(v)
            if v is None or v == {}:
                continue
            out[k] = v
        return out
    return value


@dataclass
class Exported:
    aqua_name: str
    filename: str
    document: dict
    shipped: bool = False


@dataclass
class Skipped:
    aqua_name: str
    reason: str


@dataclass
class ExportResult:
    exported: list[Exported] = field(default_factory=list)
    skipped: list[Skipped] = field(default_factory=list)


def export_kind(
    client: AquaClient,
    kind: KindDef,
    *,
    instance: str,
    scope: str | None = None,
    names: list[str] | None = None,
) -> ExportResult:
    """Export every object of ``kind`` in ``scope`` (and matching ``names``).

    Aqua-shipped objects are included: the default policy is usually the first
    one a customer changes. Objects marked by another instance are skipped --
    adopting them here would make two repositories fight over one object.
    """
    marker.validate_instance(instance)
    result = ExportResult()
    taken: set[str] = set()

    summaries = client.list(kind)
    for summary in sorted(summaries, key=lambda s: str(s.get(kind.name_field, ""))):
        name = summary.get(kind.name_field)
        if not name:
            continue
        if scope is not None and scope not in (summary.get("application_scopes") or []):
            continue
        if names and not any(fnmatch.fnmatchcase(name, pattern) for pattern in names):
            continue

        full = client.get(kind, name)
        if full is None:
            result.skipped.append(Skipped(name, "disappeared while exporting"))
            continue

        found = marker.owner(full.get("description"))
        if found and found != instance:
            result.skipped.append(Skipped(
                name, f"managed by another instance ({marker.PREFIX}{found})"))
            continue

        spec = _prune(kind.field_map.from_api(full).get("spec", {}))
        text = marker.strip(full.get("description"))
        if text:
            spec["description"] = text
        else:
            spec.pop("description", None)

        slug = slugify(name)
        base, n = slug, 2
        while slug in taken:
            slug = f"{base}-{n}"[:253]
            n += 1
        taken.add(slug)

        if slug != name:
            spec = {"aquaName": name, **spec}

        document = {
            "apiVersion": API_VERSION,
            "kind": kind.kind,
            "metadata": {"name": slug},
            "spec": spec,
        }
        try:
            kind.model.model_validate(document)
        except ValidationError as exc:
            first = exc.errors()[0]
            where = ".".join(str(p) for p in first["loc"])
            result.skipped.append(Skipped(name, f"does not fit the schema ({where}: {first['msg']})"))
            continue

        result.exported.append(Exported(
            aqua_name=name,
            filename=f"{kind_filename_prefix(kind.kind)}-{slug}.yaml",
            document=document,
            shipped=bool(kind.builtin_field and full.get(kind.builtin_field) is True),
        ))

    return result
