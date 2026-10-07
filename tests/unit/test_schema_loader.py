"""Schema validation: what loads, what does not, and what the errors say."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from aqua_casc.schema import (
    ALLOW_UNKNOWN_ANNOTATION,
    DeletionPolicy,
    Enforcement,
    RuntimeType,
    SchemaError,
    SchemaErrorGroup,
    load_dir,
    load_file,
)

EXAMPLES = Path(__file__).resolve().parents[2] / "examples" / "two-scope"


def write(tmp_path: Path, name: str, body: str) -> Path:
    path = tmp_path / name
    path.write_text(textwrap.dedent(body).lstrip(), encoding="utf-8")
    return path


MINIMAL = """
    apiVersion: config.aquasec.com/v1alpha1
    kind: RuntimePolicy
    metadata:
      name: devtest-baseline
    spec:
      enforce: false
      controls:
        blockNonCompliantImages: false
"""


def test_minimal_document_loads(tmp_path):
    result = load_file(write(tmp_path, "p.yaml", MINIMAL))

    assert len(result.resources) == 1
    policy = result.resources[0]
    assert policy.metadata.name == "devtest-baseline"
    assert policy.spec.enforce is False
    assert policy.spec.controls.blockNonCompliantImages is False
    assert not result.warnings


def test_defaults_are_the_safe_ones(tmp_path):
    policy = load_file(write(tmp_path, "p.yaml", MINIMAL)).resources[0]

    # Removing a file must never silently delete a production policy, and a
    # policy must not start enforcing just because it was created.
    assert policy.spec.deletionPolicy is DeletionPolicy.ORPHAN
    assert policy.spec.enforcement is Enforcement.RECONCILE
    assert policy.spec.runtimeType is RuntimeType.CONTAINER


def test_aqua_name_defaults_to_metadata_name(tmp_path):
    policy = load_file(write(tmp_path, "p.yaml", MINIMAL)).resources[0]
    assert policy.aqua_name == "devtest-baseline"


def test_aqua_name_can_differ_for_adoption(tmp_path):
    """Aqua names allow spaces and capitals; metadata.name does not."""
    path = write(
        tmp_path,
        "p.yaml",
        """
        apiVersion: config.aquasec.com/v1alpha1
        kind: RuntimePolicy
        metadata:
          name: devtest-baseline
        spec:
          aquaName: "Dev Test Baseline"
        """,
    )
    policy = load_file(path).resources[0]
    assert policy.metadata.name == "devtest-baseline"
    assert policy.aqua_name == "Dev Test Baseline"


def test_unknown_field_is_rejected_with_a_suggestion(tmp_path):
    path = write(
        tmp_path,
        "p.yaml",
        """
        apiVersion: config.aquasec.com/v1alpha1
        kind: RuntimePolicy
        metadata:
          name: devtest-baseline
        spec:
          controls:
            blockContainerExecc: true
        """,
    )
    with pytest.raises(SchemaError) as exc:
        load_file(path)

    rendered = exc.value.render()
    assert "unknown field" in rendered
    assert "spec.controls.blockContainerExecc" in rendered
    assert "blockContainerExec" in rendered  # the did-you-mean
    assert "p.yaml" in rendered


def test_unknown_field_without_a_near_match_points_at_the_escape_hatch(tmp_path):
    path = write(
        tmp_path,
        "p.yaml",
        """
        apiVersion: config.aquasec.com/v1alpha1
        kind: RuntimePolicy
        metadata:
          name: devtest-baseline
        spec:
          somethingEntirelyMadeUp: true
        """,
    )
    with pytest.raises(SchemaError) as exc:
        load_file(path)
    assert ALLOW_UNKNOWN_ANNOTATION in exc.value.render()


def test_escape_hatch_downgrades_unknown_fields_to_warnings(tmp_path):
    path = write(
        tmp_path,
        "p.yaml",
        f"""
        apiVersion: config.aquasec.com/v1alpha1
        kind: RuntimePolicy
        metadata:
          name: devtest-baseline
          annotations:
            {ALLOW_UNKNOWN_ANNOTATION}: "true"
        spec:
          somethingEntirelyMadeUp: true
          enforce: false
        """,
    )
    result = load_file(path)

    assert len(result.resources) == 1
    assert result.resources[0].spec.enforce is False
    assert any("somethingEntirelyMadeUp" in w for w in result.warnings)
    assert any("dropped" in w for w in result.warnings)


def test_escape_hatch_does_not_suppress_real_type_errors(tmp_path):
    path = write(
        tmp_path,
        "p.yaml",
        f"""
        apiVersion: config.aquasec.com/v1alpha1
        kind: RuntimePolicy
        metadata:
          name: devtest-baseline
          annotations:
            {ALLOW_UNKNOWN_ANNOTATION}: "true"
        spec:
          enforce: "not-a-boolean-at-all"
        """,
    )
    with pytest.raises(SchemaError) as exc:
        load_file(path)
    assert "spec.enforce" in exc.value.render()


def test_every_problem_is_reported_not_just_the_first(tmp_path):
    path = write(
        tmp_path,
        "p.yaml",
        """
        apiVersion: config.aquasec.com/v1alpha1
        kind: RuntimePolicy
        metadata:
          name: devtest-baseline
        spec:
          enforce: "nope"
          enabled: "also-nope"
        """,
    )
    with pytest.raises(SchemaError) as exc:
        load_file(path)
    assert len(exc.value.problems) == 2


def test_wrong_api_version_is_rejected(tmp_path):
    path = write(
        tmp_path,
        "p.yaml",
        """
        apiVersion: config.aquasec.com/v1
        kind: RuntimePolicy
        metadata:
          name: devtest-baseline
        """,
    )
    with pytest.raises(SchemaError) as exc:
        load_file(path)
    assert "apiVersion" in exc.value.render()


def test_unknown_kind_lists_what_is_supported(tmp_path):
    path = write(
        tmp_path,
        "p.yaml",
        """
        apiVersion: config.aquasec.com/v1alpha1
        kind: NotAThing
        metadata:
          name: x
        """,
    )
    with pytest.raises(SchemaError) as exc:
        load_file(path)
    assert "RuntimePolicy" in exc.value.render()


def test_invalid_metadata_name_points_at_aqua_name(tmp_path):
    path = write(
        tmp_path,
        "p.yaml",
        """
        apiVersion: config.aquasec.com/v1alpha1
        kind: RuntimePolicy
        metadata:
          name: "Dev Test Baseline"
        """,
    )
    with pytest.raises(SchemaError) as exc:
        load_file(path)
    assert "spec.aquaName" in exc.value.render()


def test_invalid_yaml_names_the_file(tmp_path):
    path = tmp_path / "broken.yaml"
    path.write_text("kind: [unclosed\n", encoding="utf-8")
    with pytest.raises(SchemaError) as exc:
        load_file(path)
    assert "invalid YAML" in exc.value.render()
    assert "broken.yaml" in exc.value.render()


def test_multi_document_file(tmp_path):
    path = write(
        tmp_path,
        "both.yaml",
        """
        apiVersion: config.aquasec.com/v1alpha1
        kind: RuntimePolicy
        metadata:
          name: one
        ---
        apiVersion: config.aquasec.com/v1alpha1
        kind: RuntimePolicy
        metadata:
          name: two
        """,
    )
    result = load_file(path)
    assert [r.metadata.name for r in result.resources] == ["one", "two"]


def test_directory_load_collects_errors_from_every_file(tmp_path):
    write(tmp_path, "bad1.yaml", "kind: RuntimePolicy\napiVersion: wrong\nmetadata:\n  name: a\n")
    write(tmp_path, "bad2.yaml", "kind: Nope\napiVersion: config.aquasec.com/v1alpha1\nmetadata:\n  name: b\n")

    with pytest.raises(SchemaErrorGroup) as exc:
        load_dir(tmp_path)
    assert len(exc.value.errors) == 2


def test_duplicate_kind_and_name_is_an_error(tmp_path):
    write(tmp_path, "a.yaml", MINIMAL)
    write(tmp_path, "b.yaml", MINIMAL)

    with pytest.raises(SchemaErrorGroup) as exc:
        load_dir(tmp_path)
    assert "duplicate" in str(exc.value)


def test_state_directory_is_not_treated_as_config(tmp_path):
    write(tmp_path, "p.yaml", MINIMAL)
    state = tmp_path / ".aqua-casc"
    state.mkdir()
    (state / "state.yaml").write_text("this: is not a resource\n", encoding="utf-8")

    result = load_dir(tmp_path)
    assert len(result.resources) == 1


def test_shipped_examples_are_valid():
    """The examples shipped with the repo must actually parse."""
    result = load_dir(EXAMPLES)

    names = {r.metadata.name for r in result.resources}
    assert {"devtest-baseline", "accprod-baseline"} <= names
    assert not result.warnings

    devtest = next(r for r in result.resources if r.metadata.name == "devtest-baseline")
    assert devtest.spec.enforce is False
    assert devtest.spec.controls.blockNonCompliantImages is False
    assert devtest.spec.controls.driftPrevention.exceptions == ["redis-*"]
