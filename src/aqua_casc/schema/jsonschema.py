"""Machine-readable schema output.

Two consumers:

* CI and editors, which want plain JSON Schema per kind so YAML can be validated
  without running this tool.
* Phase 2, which wants CustomResourceDefinitions. A CRD's ``openAPIV3Schema`` is
  JSON Schema with a few keywords disallowed, so the CRD generator here is a
  filter over the same output rather than a second schema definition. That is
  the whole reason the kinds are modelled in Kubernetes shape to begin with.
"""

from __future__ import annotations

from typing import Any

from . import registry
from .base import GROUP, VERSION

# Keywords the Kubernetes structural-schema rules reject inside openAPIV3Schema.
_CRD_FORBIDDEN = ("$ref", "$defs", "definitions", "allOf", "anyOf", "oneOf", "not")


def _pluralise(singular: str) -> str:
    """Lowercase plural for a CRD's ``names.plural``.

    Kubernetes does not derive this for you, and it is the name people type
    (``kubectl get runtimepolicies``), so a naive ``+ "s"`` would ship
    ``runtimepolicys`` into phase 2 and be awkward to change afterwards --
    ``names.plural`` is part of the resource's identity in the API server.
    """
    if singular.endswith("y") and not singular.endswith(("ay", "ey", "iy", "oy", "uy")):
        return singular[:-1] + "ies"
    if singular.endswith(("s", "x", "z", "ch", "sh")):
        return singular + "es"
    return singular + "s"


def for_kind(kind: str) -> dict[str, Any]:
    """JSON Schema for one kind, with $refs left intact."""
    kind_def = registry.get(kind)
    schema = kind_def.model.model_json_schema(mode="validation")
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["$id"] = f"https://{GROUP}/{VERSION}/{kind}.schema.json"
    schema["title"] = kind
    return schema


def all_kinds() -> dict[str, dict[str, Any]]:
    return {kind: for_kind(kind) for kind in registry.kinds()}


def _inline_refs(node: Any, defs: dict[str, Any], _depth: int = 0) -> Any:
    """Resolve $ref inline, as CRD structural schemas require.

    Recursion is bounded: a self-referential model would otherwise inline
    forever. None of the current kinds are recursive, and the guard is here so
    that adding one fails loudly rather than hanging a CI job.
    """
    if _depth > 32:
        raise ValueError(
            "schema nests deeper than 32 levels, or a model refers to itself; "
            "CRD structural schemas cannot express that"
        )

    if isinstance(node, list):
        return [_inline_refs(item, defs, _depth + 1) for item in node]
    if not isinstance(node, dict):
        return node

    if "$ref" in node:
        ref = node["$ref"]
        key = ref.rsplit("/", 1)[-1]
        target = defs.get(key)
        if target is None:
            raise ValueError(f"cannot resolve {ref!r} while flattening for CRD output")
        merged = {**target, **{k: v for k, v in node.items() if k != "$ref"}}
        return _inline_refs(merged, defs, _depth + 1)

    return {
        key: _inline_refs(value, defs, _depth + 1)
        for key, value in node.items()
        if key not in ("$defs", "definitions")
    }


def _is_null_branch(branch: Any) -> bool:
    return isinstance(branch, dict) and branch.get("type") == "null"


def _collapse_unions(node: Any, path: str = "spec") -> Any:
    """Flatten the unions pydantic emits for optional fields.

    ``Optional[DriftPrevention]`` becomes ``anyOf: [{$ref: ...}, {type: null}]``,
    which a structural schema cannot express. Where the union is just
    "this type, or absent" -- which is every union our models produce -- it
    collapses to the one real branch plus ``nullable: true``.

    A union of two genuinely different types cannot be expressed in a CRD at
    all, so it raises here rather than silently emitting a schema that
    Kubernetes would reject at install time or, worse, that would validate
    nothing.
    """
    if isinstance(node, list):
        return [_collapse_unions(item, f"{path}[]") for item in node]
    if not isinstance(node, dict):
        return node

    for keyword in ("anyOf", "oneOf", "allOf"):
        if keyword not in node:
            continue

        branches = node[keyword]
        real = [b for b in branches if not _is_null_branch(b)]
        nullable = len(real) != len(branches)

        if len(real) != 1:
            raise ValueError(
                f"{path}: cannot express {keyword} of {len(real)} non-null "
                "branches in a CRD structural schema. Give the field a single "
                "concrete type."
            )

        merged = {**real[0], **{k: v for k, v in node.items() if k != keyword}}
        if nullable:
            merged["nullable"] = True
        return _collapse_unions(merged, path)

    return {key: _collapse_unions(value, f"{path}.{key}") for key, value in node.items()}


def _strip_for_crd(node: Any) -> Any:
    """Remove leftover keywords a structural schema disallows, and add types."""
    if isinstance(node, list):
        return [_strip_for_crd(item) for item in node]
    if not isinstance(node, dict):
        return node

    out = {key: _strip_for_crd(value) for key, value in node.items() if key not in _CRD_FORBIDDEN}

    # Kubernetes requires a type on every node of a structural schema.
    if "properties" in out and "type" not in out:
        out["type"] = "object"
    return out


def crd_for_kind(kind: str, plural: str | None = None) -> dict[str, Any]:
    """A CustomResourceDefinition for one kind.

    Phase 2 ships these. They are generated rather than hand-written so the CRDs
    and the CLI's validation cannot drift apart.
    """
    schema = for_kind(kind)
    defs = schema.get("$defs", {})
    flat = _strip_for_crd(_collapse_unions(_inline_refs(schema, defs)))

    for key in ("$schema", "$id", "title"):
        flat.pop(key, None)

    plural = plural or _pluralise(kind.lower())
    return {
        "apiVersion": "apiextensions.k8s.io/v1",
        "kind": "CustomResourceDefinition",
        "metadata": {"name": f"{plural}.{GROUP}"},
        "spec": {
            "group": GROUP,
            "scope": "Namespaced",
            "names": {
                "kind": kind,
                "plural": plural,
                "singular": kind.lower(),
            },
            "versions": [
                {
                    "name": VERSION,
                    "served": True,
                    "storage": True,
                    "subresources": {"status": {}},
                    "schema": {"openAPIV3Schema": flat},
                }
            ],
        },
    }
