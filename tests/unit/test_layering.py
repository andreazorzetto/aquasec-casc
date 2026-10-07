"""Architectural guards.

The reconciler must not import anything CLI-specific, must not print, and must
not call sys.exit. It returns result objects and the caller renders them.

This is the constraint that makes the phase 2 operator a wrapper around the same
reconciler rather than a rewrite of it, and it is the single easiest thing to
break by accident -- one debug print during a late night before a demo and the
property is gone. So it is a test, not a convention.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "src" / "aqua_casc"

RECONCILE = SRC / "reconcile"
SCHEMA = SRC / "schema"

FORBIDDEN_IN_CORE = {"sys.exit", "exit", "quit", "print", "input", "breakpoint"}


def python_files(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob("*.py"))


def parsed(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _called_names(tree: ast.Module):
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name):
            yield func.id, node.lineno
        elif isinstance(func, ast.Attribute):
            value = func.value
            if isinstance(value, ast.Name):
                yield f"{value.id}.{func.attr}", node.lineno


@pytest.mark.parametrize("layer", [RECONCILE, SCHEMA], ids=["reconcile", "schema"])
def test_core_layers_do_not_print_or_exit(layer):
    offences = []
    for path in python_files(layer):
        for name, line in _called_names(parsed(path)):
            if name in FORBIDDEN_IN_CORE:
                offences.append(f"{path.relative_to(SRC)}:{line} calls {name}()")
    assert offences == [], "\n".join(offences)


@pytest.mark.parametrize("layer", [RECONCILE, SCHEMA], ids=["reconcile", "schema"])
def test_core_layers_do_not_import_the_cli(layer):
    offences = []
    for path in python_files(layer):
        tree = parsed(path)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                if "cli" in node.module.split("."):
                    offences.append(f"{path.relative_to(SRC)}:{node.lineno} -> {node.module}")
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if "cli" in alias.name.split("."):
                        offences.append(
                            f"{path.relative_to(SRC)}:{node.lineno} -> {alias.name}"
                        )
    assert offences == [], "\n".join(offences)


def test_the_reconciler_does_not_import_the_http_stack_directly():
    """It talks to the AquaClient protocol, never to aquasec-lib or requests.

    Keeping SaaS/on-prem differences behind that interface is what stops a
    SaaS-only assumption reaching the core -- which matters because production often runs
    on-prem and every tenant we develop against is SaaS.
    """
    forbidden = {"requests", "aquasec", "urllib", "http"}
    offences = []

    for path in python_files(RECONCILE):
        tree = parsed(path)
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                names = [node.module]
            elif isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            for name in names:
                if name.split(".")[0] in forbidden:
                    offences.append(f"{path.relative_to(SRC)}:{node.lineno} -> {name}")

    assert offences == [], "\n".join(offences)


def test_the_schema_layer_has_no_behaviour_dependencies():
    """Layer 1 is pure data and validation: it must not reach the reconciler."""
    offences = []
    for path in python_files(SCHEMA):
        tree = parsed(path)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                if "reconcile" in node.module.split("."):
                    offences.append(f"{path.relative_to(SRC)}:{node.lineno}")
    assert offences == [], "\n".join(offences)


def test_the_guard_would_actually_catch_a_print(tmp_path):
    """A guard nobody has seen fail is not a guard."""
    offender = tmp_path / "bad.py"
    offender.write_text("def f():\n    print('debug')\n", encoding="utf-8")

    found = [n for n, _ in _called_names(parsed(offender)) if n in FORBIDDEN_IN_CORE]
    assert found == ["print"]
