"""Export: existing Aqua configuration as schema-valid YAML documents.

Read-only. This is the adoption path: export, commit, apply -- and the first
apply only adds the ownership marker ("adopted"), after which every apply is a
no-op until someone changes something.

Pure: returns documents, writes nothing. The CLI decides where they go.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError

from .reconcile import marker
from .reconcile.client import AquaClient
from .reconcile.engine import is_shipped
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
    """Drop None and empty-string leaves, and the dicts left empty by doing so.

    Aqua returns null for unset lists and blocks, and "" for unset choices (an
    outdated-images unit, a malware action, while the control is off); leaving
    them in would fail validation and write noise into Git.
    """
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            v = _prune(v)
            if v is None or v == {} or v == "":
                continue
            out[k] = v
        return out
    return value


def _is_off(value: Any) -> bool:
    return (value is None or value is False or value == "" or value == [] or value == {}
            or (type(value) is int and value == 0))


def _only_what_is_on(value: Any) -> Any:
    """Drop what is off -- false, empty, 0 -- since a control the file leaves
    out is switched off anyway (``KindDef.off_when_unset``): the exported file
    lists what the policy does, not everything it does not do.

    A section that is off is dropped whole, settings included: a control left
    out only has its switch turned off, so its settings stay as they are and
    applying the export changes nothing. One that is on and holds settings
    drops ``enabled: true``: writing a setting switches the section on.
    """
    if not isinstance(value, dict):
        return value
    if value.get("enabled") is False:
        return {}
    out = {k: v for k, v in ((k, _only_what_is_on(v)) for k, v in value.items())
           if not _is_off(v)}
    if out.get("enabled") is True and len(out) > 1:
        del out["enabled"]
    return out


def _drop_off_controls(spec: dict, kind: KindDef) -> dict:
    for prefix in kind.off_when_unset:
        spec = _drop_off_under(spec, kind, prefix)
    return spec


def _drop_off_under(spec: dict, kind: KindDef, prefix: str) -> dict:
    *parents, leaf = prefix.split(".")[1:]     # below "spec"
    holder = spec
    for part in parents:
        holder = holder.get(part) or {}
    if not isinstance(holder.get(leaf), dict):
        return spec
    under = prefix + "."
    kept = {k[len(under):].split(".")[0] for k in kind.kept_when_unset if k.startswith(under)}
    section = holder[leaf]
    # A control with settings and no switch to say so reads as on when loaded, so
    # one whose switch this Aqua does not return is left out, as off.
    switches = {m.canonical[len(under):].split(".")[0] for m in kind.field_map.mappings
                if m.canonical.startswith(under) and m.canonical.endswith(".enabled")}
    section = {k: v for k, v in section.items()
               if not (k in switches and isinstance(v, dict) and "enabled" not in v)}
    trimmed = _only_what_is_on({k: v for k, v in section.items() if k not in kept})
    # A control that is on with no settings reads best as one line.
    trimmed = {k: True if v == {"enabled": True} else v for k, v in trimmed.items()}
    trimmed.update({k: v for k, v in section.items() if k in kept})
    if trimmed:
        holder[leaf] = trimmed
    else:
        del holder[leaf]
    return spec


NOT_THE_SCHEMA = "does not fit the schema"


@dataclass
class Exported:
    aqua_name: str
    filename: str
    document: dict
    shipped: bool = False
    left_out: list[str] = field(default_factory=list)
    """On in Aqua, but it does nothing on this type, so it is not in the file."""


@dataclass
class Skipped:
    aqua_name: str
    reason: str


@dataclass
class ExportResult:
    exported: list[Exported] = field(default_factory=list)
    skipped: list[Skipped] = field(default_factory=list)
    left_outside: list[str] = field(default_factory=list)
    """This instance's objects that --scope or --name left out. With no file, an
    apply of the folder deletes them."""

    def skipped_for_schema(self) -> list[Skipped]:
        return [s for s in self.skipped if s.reason.startswith(NOT_THE_SCHEMA)]


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
    for summary in sorted(summaries, key=lambda s: str(kind.key_of(s) or "")):
        name = summary.get(kind.name_field)
        if not name:
            continue
        key = kind.key_of(summary)
        if ((scope is not None and scope not in (summary.get("application_scopes") or []))
                or (names and not kind.matches(key, names))):
            if marker.owner(summary.get("description")) == instance:
                result.left_outside.append(key)
            continue

        full = client.get(kind, key)
        if full is None:
            result.skipped.append(Skipped(key, "disappeared while exporting"))
            continue

        found = marker.owner(full.get("description"))
        if found and found != instance:
            result.skipped.append(Skipped(
                key, f"managed by another instance ({marker.PREFIX}{found})"))
            continue

        api_view = dict(full)
        shipped = is_shipped(kind, full)
        for prefix, allowed in kind.only_on.items():
            # Every object may carry the field in the API (disabled); writing it
            # into YAML for an object that cannot have it would make the first
            # apply report it as not allowed.
            if not (shipped and name in allowed):
                api_view.pop(prefix.split(".")[0], None)
        spec = _drop_off_controls(_prune(kind.field_map.from_api(api_view).get("spec", {})), kind)
        # Aqua holds empty criteria and exclusions on a policy without any.
        if not (spec.get("additionalScopeCriteria") or {}).get("variables"):
            spec.pop("additionalScopeCriteria", None)
        if not spec.get("excludeApplicationScopes"):
            spec.pop("excludeApplicationScopes", None)
        text = marker.strip(full.get("description"))
        if text:
            spec["description"] = text
        else:
            spec.pop("description", None)

        # Names repeat across a kind's types ("Default"), so the type leads.
        left_out = kind.drop_on_export(spec) if kind.drop_on_export else []

        slug = slugify(key.replace("/", "-"))
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
            result.skipped.append(Skipped(key, f"{NOT_THE_SCHEMA} ({where}: {first['msg']})"))
            continue

        result.exported.append(Exported(
            aqua_name=key,
            filename=f"{kind_filename_prefix(kind.kind)}-{slug}.yaml",
            document=document,
            shipped=shipped,
            left_out=left_out,
        ))

    return result
