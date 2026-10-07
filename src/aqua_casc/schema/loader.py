"""Load YAML documents into validated resources.

No network, no side effects. This is what ``validate`` runs, which is why it is
fast enough for a pre-commit hook.
"""

from __future__ import annotations

import difflib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Type, get_args

import yaml
from pydantic import BaseModel, ValidationError

from . import registry
from .base import Resource
from .errors import SchemaError, SchemaErrorGroup, SchemaProblem

ALLOW_UNKNOWN_ANNOTATION = "config.aquasec.com/allow-unknown-fields"

YAML_SUFFIXES = (".yaml", ".yml")

#: The tool's own configuration file at the root of a config directory. It is
#: settings (the instance name), not a resource, so the loader skips it.
CONFIG_FILENAMES = ("aqua-casc.yaml", "aqua-casc.yml")


@dataclass
class LoadResult:
    """Everything a single load produced: resources, and any warnings."""

    resources: list[Resource] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def _model_field_names(model: Type[BaseModel], _seen: set | None = None) -> set[str]:
    """Every field name anywhere in a model tree, for did-you-mean suggestions."""
    seen = _seen if _seen is not None else set()
    if model in seen:
        return set()
    seen.add(model)

    names: set[str] = set()
    for name, info in model.model_fields.items():
        names.add(name)
        for candidate in (info.annotation, *get_args(info.annotation or ())):
            if isinstance(candidate, type) and issubclass(candidate, BaseModel):
                names |= _model_field_names(candidate, seen)
    return names


def _nested_model(info: Any) -> Type[BaseModel] | None:
    """The BaseModel a field holds, unwrapping Optional/list, or None."""
    for candidate in (info.annotation, *get_args(info.annotation or ())):
        if isinstance(candidate, type) and issubclass(candidate, BaseModel):
            return candidate
    return None


def _field_description(model: Type[BaseModel], loc: tuple[Any, ...]) -> str:
    """The schema description of the field at ``loc``, or "" if there is none."""
    current: Type[BaseModel] | None = model
    info = None
    for part in loc:
        if current is None or not isinstance(part, str):
            return ""
        info = current.model_fields.get(part)
        if info is None:
            return ""
        current = _nested_model(info)
    return (info.description or "") if info is not None else ""


def _dotted(loc: tuple[Any, ...]) -> str:
    return ".".join(str(p) for p in loc if p != "__root__")


def _split_problems(
    exc: ValidationError, model: Type[BaseModel]
) -> tuple[list[SchemaProblem], list[SchemaProblem]]:
    """Split pydantic errors into hard failures and unknown-field failures.

    Unknown fields come back separately so the per-document escape hatch can
    downgrade them without also suppressing genuine type errors.
    """
    known = _model_field_names(model)
    hard: list[SchemaProblem] = []
    unknown: list[SchemaProblem] = []

    for err in exc.errors():
        path = _dotted(err["loc"])
        if err["type"] == "extra_forbidden":
            bad = str(err["loc"][-1]) if err["loc"] else "?"
            matches = difflib.get_close_matches(bad, sorted(known), n=1, cutoff=0.7)
            hint = (
                f"did you mean {matches[0]!r}?"
                if matches
                else (
                    "remove it, or set the annotation "
                    f'{ALLOW_UNKNOWN_ANNOTATION}: "true" on this document to '
                    "downgrade this to a warning"
                )
            )
            unknown.append(SchemaProblem(path=path, message="unknown field", hint=hint))
        elif err["type"] == "missing":
            hard.append(SchemaProblem(
                path=path, message="required",
                hint=_field_description(model, tuple(err["loc"])),
            ))
        else:
            hard.append(SchemaProblem(path=path, message=err["msg"]))

    return hard, unknown


def _strip_unknown(data: Any, model: Type[BaseModel]) -> Any:
    """Drop fields the model does not declare, recursively.

    Used only under the escape-hatch annotation. Unknown fields are dropped
    rather than forwarded: a field with no entry in the kind's field map has no
    API path to be written to, so there is nowhere for it to go. Forwarding it
    would put it in the request body unmapped, where Aqua ignores it silently --
    exactly the failure the strict default exists to prevent.
    """
    if not isinstance(data, dict):
        return data

    out: dict[str, Any] = {}
    for key, value in data.items():
        info = model.model_fields.get(key)
        if info is None:
            continue
        nested = _nested_model(info)
        out[key] = _strip_unknown(value, nested) if nested else value
    return out


def _allows_unknown(doc: dict) -> bool:
    annotations = ((doc.get("metadata") or {}).get("annotations")) or {}
    return str(annotations.get(ALLOW_UNKNOWN_ANNOTATION, "")).lower() == "true"


def load_document(doc: Any, source: str, index: int = 0) -> tuple[Resource, list[str]]:
    """Validate one parsed YAML document into a resource.

    Raises:
        SchemaError: with every problem in the document, not just the first.
    """
    where = source if index == 0 else f"{source}[doc {index}]"

    if not isinstance(doc, dict):
        raise SchemaError(
            where,
            [SchemaProblem("", f"expected a mapping, found {type(doc).__name__}")],
        )

    kind = doc.get("kind")
    if not kind:
        raise SchemaError(
            where,
            [
                SchemaProblem(
                    "kind",
                    "missing",
                    hint=f"one of: {', '.join(registry.kinds())}",
                )
            ],
        )

    try:
        kind_def = registry.get(kind)
    except KeyError as exc:
        raise SchemaError(where, [SchemaProblem("kind", str(exc))]) from exc

    name = ((doc.get("metadata") or {}).get("name")) or None
    warnings: list[str] = []
    payload = doc

    try:
        resource = kind_def.model.model_validate(payload)
    except ValidationError as exc:
        hard, unknown = _split_problems(exc, kind_def.model)

        if unknown and _allows_unknown(doc):
            for problem in unknown:
                warnings.append(
                    f"{where}: dropped unknown field {problem.path} "
                    f"({ALLOW_UNKNOWN_ANNOTATION} is set)"
                )
            payload = _strip_unknown(doc, kind_def.model)
            try:
                resource = kind_def.model.model_validate(payload)
            except ValidationError as exc2:
                hard2, _ = _split_problems(exc2, kind_def.model)
                raise SchemaError(where, hard2, kind=kind, name=name) from exc2
            return resource, warnings

        raise SchemaError(where, hard + unknown, kind=kind, name=name) from exc

    return resource, warnings


def load_file(path: Path | str) -> LoadResult:
    """Load every document in one YAML file."""
    path = Path(path)
    result = LoadResult()

    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SchemaError(str(path), [SchemaProblem("", f"cannot read file: {exc}")])

    try:
        documents = list(yaml.safe_load_all(text))
    except yaml.YAMLError as exc:
        raise SchemaError(str(path), [SchemaProblem("", f"invalid YAML: {exc}")])

    real = [(i, d) for i, d in enumerate(documents) if d is not None]
    for index, doc in real:
        resource, warnings = load_document(doc, str(path), index if len(real) > 1 else 0)
        result.resources.append(resource)
        result.warnings.extend(warnings)

    return result


def load_dir(path: Path | str) -> LoadResult:
    """Load every YAML file under a directory, collecting all errors.

    Every file is attempted even after one fails, so a person fixing a tree sees
    the whole list in one run. Duplicate ``kind/name`` pairs are an error: two
    files claiming the same Aqua object would race each other on every apply.
    """
    path = Path(path)
    if path.is_file():
        return load_file(path)

    if not path.is_dir():
        raise SchemaError(str(path), [SchemaProblem("", "no such file or directory")])

    result = LoadResult()
    group = SchemaErrorGroup()

    for file in sorted(p for p in path.rglob("*") if p.suffix in YAML_SUFFIXES):
        if file.parent == path and file.name in CONFIG_FILENAMES:
            continue
        try:
            loaded = load_file(file)
        except SchemaError as exc:
            group.errors.append(exc)
            continue
        result.resources.extend(loaded.resources)
        result.warnings.extend(loaded.warnings)

    seen: dict[tuple[str, str], Resource] = {}
    for resource in result.resources:
        key = (resource.kind, resource.metadata.name)
        if key in seen:
            group.errors.append(
                SchemaError(
                    str(path),
                    [
                        SchemaProblem(
                            "metadata.name",
                            f"duplicate {resource.kind}/{resource.metadata.name}: "
                            "two documents describe the same object",
                        )
                    ],
                )
            )
        seen[key] = resource

    if group:
        raise group

    return result
