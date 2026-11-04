#!/usr/bin/env python3
"""Generate docs/schema-reference.md from the schema, so the two cannot disagree.

    python scripts/schema_reference.py > docs/schema-reference.md

tests/unit/test_schema_reference.py fails when the file is out of date.
"""

from __future__ import annotations

from typing import Any, get_args, get_origin

from pydantic import BaseModel

from aquasec_casc.schema import registry
from aquasec_casc.schema.assurance_policy import NOT_OFFERED as ASSURANCE_NOT_OFFERED
from aquasec_casc.schema.assurance_policy import ONLY_ON
from aquasec_casc.schema.runtime_policy import NOT_OFFERED as RUNTIME_NOT_OFFERED
from aquasec_casc.schema.sections import Section

HEAD = """# Schema reference

Generated from the schema by `scripts/schema_reference.py`; do not edit by hand.
[schema-examples.md](schema-examples.md) shows the same fields in use.

Names are the console's labels in camelCase. Under `actions`, `exceptions` and
`controls`, **what the file leaves out is off**. A control with settings can be
written `true`, and writing any of its settings switches it on. `aquasec-casc schema
KIND` prints the same as JSON Schema, for editors and CI.
"""


def _unwrap(annotation: Any) -> Any:
    """``X | None`` as ``X``."""
    args = [a for a in get_args(annotation) if a is not type(None)]
    return args[0] if get_origin(annotation) is not list and len(args) == 1 else annotation


def _type_name(annotation: Any) -> str:
    annotation = _unwrap(annotation)
    if get_origin(annotation) is list:
        item = _unwrap(get_args(annotation)[0])
        if isinstance(item, type) and issubclass(item, BaseModel):
            return "list of {" + ", ".join(item.model_fields) + "}"
        return f"list of {_type_name(item)}"
    if isinstance(annotation, type) and hasattr(annotation, "__members__"):
        return " \\| ".join(f"`{m.value}`" for m in annotation)
    if isinstance(annotation, type):
        return {"str": "text", "int": "number", "float": "number", "bool": "true/false"}.get(
            annotation.__name__, annotation.__name__)
    return str(annotation)


def _one_line(text: str | None) -> str:
    text = " ".join((text or "").split())
    return text.replace("|", "\\|")


def _rows(model: type[BaseModel], prefix: str, field_map, kind: str) -> list[str]:
    api_of = {m.canonical: m for m in field_map.mappings}
    rows = []
    for name, info in model.model_fields.items():
        if name == "enabled" and issubclass(model, Section):
            mapping = api_of.get(f"spec.{prefix}enabled")
            if mapping:
                rows.append(f"| `{prefix}enabled` | true/false | `{mapping.api}` | The control's switch. |")
            continue
        if name in ("enforcement", "aquaName"):
            continue
        path = f"{prefix}{name}"
        only = (" Only on " + ", ".join(sorted(t.value for t in ONLY_ON[path])) + "."
                if path in ONLY_ON and kind == "AssurancePolicy" else "")
        inner = _unwrap(info.annotation)
        if isinstance(inner, type) and issubclass(inner, BaseModel):
            text = _one_line(info.description or inner.__doc__) + only
            if text:
                rows.append(f"| `{path}` | object | | {text.strip()} |")
            rows.extend(_rows(inner, f"{path}.", field_map, kind))
            continue
        mapping = api_of.get(f"spec.{path}")
        api = f"`{mapping.api}`" if mapping else ""
        if mapping and mapping.also_set:
            api += " + " + ", ".join(f"`{g}`" for g in mapping.also_set)
        rows.append(f"| `{path}` | {_type_name(info.annotation)} | {api} | "
                    f"{(_one_line(info.description) + only).strip()} |")
    return rows


def _kind(kind: str) -> list[str]:
    kind_def = registry.get(kind)
    spec = kind_def.model.model_fields["spec"].annotation
    return [f"## {kind}", "", "All under `spec`.", "", "| Field | Type | API field | |", "|---|---|---|---|",
            *_rows(spec, "", kind_def.field_map, kind),
            "| `aquaName` | text | `name` | The name in Aqua, when it is not a valid `metadata.name`. Defaults to `metadata.name`. |",
            "| `enforcement` | `Reconcile` \\| `ReportOnly` | | `ReportOnly` reports drift and changes nothing. |",
            ""]


def _not_offered(title: str, table: dict[str, str]) -> list[str]:
    return [f"### {title}", "", "| API field | Why |", "|---|---|",
            *(f"| `{k}` | {_one_line(v)} |" for k, v in sorted(table.items())), ""]


TESTED = """## Tested against

`tests/integration/test_every_field.py` puts every field here through create, a re-save,
export, removal and update, on a live tenant, for each type that offers it.

| Aqua | |
|---|---|
| SaaS | All of it: 163 cases, and all 61 policies on the tenant export and plan only the marker. |
| Self-hosted 2022.4 | The API spec and a console export were compared. Not yet run live. |

Sign-in with a user name and password, as self-hosted Aqua uses, is covered by unit tests only.
"""


def main() -> None:
    lines = [HEAD, TESTED, *_kind("RuntimePolicy"), *_kind("AssurancePolicy"),
             "## Not offered", "",
             "In Aqua's API, and left as Aqua has them: `apply` never changes these. Each was",
             "checked against the API spec, the docs and a live tenant.", "",
             *_not_offered("RuntimePolicy", RUNTIME_NOT_OFFERED),
             *_not_offered("AssurancePolicy", ASSURANCE_NOT_OFFERED)]
    print("\n".join(lines).rstrip())


if __name__ == "__main__":
    main()
