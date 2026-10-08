"""Field map verified against a real recorded Aqua API response.

The fixture is the stock "Aqua default runtime policy" captured from the eu-1
lab tenant on 11 September 2026. It is Aqua's own out-of-the-box policy
(``author: System``) and contains no customer data.

These tests exist because the field map was mined from a third-party Terraform
provider, and a mapping that is merely plausible is worth nothing: Aqua ignores
unknown fields on write, so a wrong path means apply reports success and changes
nothing. Recording a real response is what turns "plausible" into "checked".
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aquasec_casc.schema.fieldmap import MISSING, get_path
from aquasec_casc.schema.runtime_policy import FIELD_MAP

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "runtime_policy_aqua_default.json"


@pytest.fixture(scope="module")
def policy() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


SECRET_KEY_HINTS = ("token", "password", "secret", "api_key", "credential")


def _secret_bearing_fields(node, path="") -> list[str]:
    """Paths whose key looks secret-ish AND which hold a non-empty value.

    Checking key names alone is useless here: a runtime policy legitimately has
    a ``user_password`` field in its user-access block, empty on every policy.
    What must never be committed is such a field carrying an actual value.
    """
    found = []
    if isinstance(node, dict):
        for key, value in node.items():
            here = f"{path}.{key}" if path else key
            looks_secret = any(h in key.lower() for h in SECRET_KEY_HINTS)
            if looks_secret and value not in (None, "", [], {}, False, 0):
                found.append(here)
            found.extend(_secret_bearing_fields(value, here))
    elif isinstance(node, list):
        for i, item in enumerate(node):
            found.extend(_secret_bearing_fields(item, f"{path}[{i}]"))
    return found


def test_fixture_carries_no_credentials(policy):
    """Guard rail: fixtures are committed, so they must never carry secrets."""
    assert _secret_bearing_fields(policy) == []


def test_every_verified_mapping_exists_on_a_real_object(policy):
    """A mapped API path that the server does not return is a mapping bug."""
    missing = [
        m.api
        for m in FIELD_MAP.mappings
        if not m.unverified and get_path(policy, m.api) is MISSING
    ]
    assert missing == [], f"mapped but absent from a real policy object: {missing}"


def test_no_mapping_is_unverified(policy):
    """Every mapped field has been seen on a real policy object."""
    assert list(FIELD_MAP.unverified()) == []


def test_prevent_privileged_is_not_mapped(policy):
    """Aqua accepts drift_prevention.prevent_privileged and drops it (write-tested
    live); mapping it would report drift on every run."""
    assert get_path(policy, "drift_prevention.prevent_privileged") is MISSING
    assert FIELD_MAP.for_api_path("drift_prevention.prevent_privileged") == (None, False)


def test_the_demo_field_is_present_and_the_retired_name_is_not(policy):
    assert policy["block_disallowed_images"] is True
    assert "block_non_compliant_images" not in policy


def test_top_level_block_container_exec_is_vestigial(policy):
    """The nested flag is on; the top-level one is not. Hence the mapping."""
    assert policy["container_exec"]["block_container_exec"] is True
    assert policy["block_container_exec"] is False


def test_gated_controls_are_enabled_alongside_their_flag(policy):
    assert policy["container_exec"]["enabled"] is True
    assert policy["reverse_shell"]["enabled"] is True


def test_import_of_a_real_policy_produces_canonical_fields(policy):
    """The export path: a real server object becomes schema-shaped config."""
    canonical = FIELD_MAP.from_api(policy)
    spec = canonical["spec"]
    controls = spec["controls"]

    assert spec["enforce"] is False
    assert spec["applicationScopes"] == ["Global"]
    assert controls["blockNonCompliantImages"] is True
    assert controls["blockContainerExec"] is True
    assert controls["driftPrevention"]["enabled"] is True
    assert controls["driftPrevention"]["execLockdown"] is True


def test_import_drops_server_owned_fields(policy):
    """Nothing Aqua assigns itself may leak into our spec."""
    canonical = FIELD_MAP.from_api(policy)
    blob = json.dumps(canonical)

    for server_owned in ("author", "digest", "lastupdate", "is_ootb_policy", "vpatch"):
        assert server_owned not in blob


def test_reapplying_an_imported_policy_is_a_no_op(policy):
    """The acceptance test for adoption, at the field-map level.

    export -> canonical -> back to API must reproduce exactly what the server
    already holds for every field we own. If this drifts, the first apply after
    an import would show spurious changes, and nobody would trust the tool
    again.
    """
    canonical = FIELD_MAP.from_api(policy)
    round_tripped = FIELD_MAP.to_api(canonical)

    differences = {}
    for path in FIELD_MAP.owned_api_paths(canonical):
        server = get_path(policy, path)
        ours = get_path(round_tripped, path)
        if server != ours:
            differences[path] = {"server": server, "ours": ours}

    assert differences == {}, f"round trip would produce spurious drift: {differences}"


def test_no_gate_collides_with_a_primary_mapping():
    """A gate writing over a field someone else owns would be silent corruption."""
    primary = {m.api for m in FIELD_MAP.mappings}
    for mapping in FIELD_MAP.mappings:
        for gate in mapping.also_set:
            assert gate not in primary, (
                f"{mapping.canonical}'s gate {gate} is also a primary mapping"
            )
