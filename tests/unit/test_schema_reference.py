"""docs/schema-reference.md is generated: it may not fall behind the schema."""

from __future__ import annotations

import contextlib
import io
import runpy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_the_reference_is_up_to_date():
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        runpy.run_path(str(ROOT / "scripts" / "schema_reference.py"), run_name="__main__")
    assert (ROOT / "docs" / "schema-reference.md").read_text(encoding="utf-8").strip() == out.getvalue().strip(), (
        "run: python scripts/schema_reference.py > docs/schema-reference.md")


def test_it_covers_every_field():
    from aquasec_casc.schema import registry
    text = (ROOT / "docs" / "schema-reference.md").read_text(encoding="utf-8")
    for kind in registry.REGISTRY.values():
        for mapping in kind.field_map.mappings:
            path = mapping.canonical.removeprefix("spec.")
            assert f"`{path}`" in text, path
