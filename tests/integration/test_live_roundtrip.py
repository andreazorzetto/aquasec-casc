"""Live round trip against a real Aqua tenant, through the real CLI. Opt-in.

Runs only with AQUASEC_CASC_LIVE=1, using AQUA_* environment variables or, if
AQUASEC_CASC_PROFILE is set, that saved aquasec-lib profile:

    AQUASEC_CASC_LIVE=1 AQUASEC_CASC_PROFILE=lab pytest tests/integration -v

Safety: it creates one throwaway runtime policy (disabled, so inert) and uses a
random instance name, so the orphan scan can only ever match that one policy --
nothing else on the tenant carries this run's marker. The policy is deleted at
the end even on failure.
"""

from __future__ import annotations

import copy
import io
import os
import secrets

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("AQUASEC_CASC_LIVE") != "1",
    reason="live test: set AQUASEC_CASC_LIVE=1 (and credentials) to run against a tenant",
)

PROFILE = os.environ.get("AQUASEC_CASC_PROFILE")


@pytest.fixture(scope="module")
def client():
    from aquasec_casc.client import connect, settings_from_env, settings_from_profile
    return connect(settings_from_profile(PROFILE) if PROFILE else settings_from_env())


@pytest.fixture
def throwaway(client):
    """A pre-existing, unmarked policy -- as if someone made it in the console."""
    from aquasec import runtime_policies as rp

    name = f"aquasec-casc-live-{secrets.token_hex(3)}"
    rp.create_runtime_policy(client.server, client.token, {
        "name": name, "runtime_type": "container", "enabled": False,
        "description": "Made in the console (aquasec-casc live test, safe to delete)",
        "application_scopes": ["Global"], "block_disallowed_images": False,
    })
    yield name
    rp.delete_runtime_policy(client.server, client.token, name, missing_ok=True)
    assert rp.get_runtime_policy(client.server, client.token, name) is None


def cli(client, *argv):
    from aquasec_casc.cli.main import main

    out, err = io.StringIO(), io.StringIO()
    code = main(list(argv), stdout=out, stderr=err, connect=lambda profile: client)
    return code, out.getvalue() + err.getvalue()


def test_export_adopt_noop_drift_revert_delete(client, throwaway, tmp_path):
    from aquasec import runtime_policies as rp

    from aquasec_casc.reconcile import marker

    instance = f"live-{secrets.token_hex(3)}"
    repo = tmp_path / "repo"

    def server():
        return rp.get_runtime_policy(client.server, client.token, throwaway)

    original = server()

    # 1. export just this policy
    code, out = cli(client, "export", "--scope", "Global", "--name", throwaway,
                    "-o", str(repo), "--instance", instance)
    assert code == 0, out
    assert "1 exported" in out
    assert server()["description"] == original["description"]      # export is read-only

    # 2. diff: only the ownership marker would change
    code, out = cli(client, "plan", "--detailed-exitcode", "-f", str(repo))
    assert code == 2, out
    assert "will be adopted" in out and "+ ownership marker" in out

    # 3. apply: adopted, and nothing but the description changed
    code, out = cli(client, "apply", "-f", str(repo))
    assert code == 0 and "1 adopted" in out, out
    after = server()
    assert marker.owner(after["description"]) == instance
    assert marker.strip(after["description"]) == original["description"]
    for key in ("enabled", "enforce", "application_scopes", "block_disallowed_images",
                "container_exec", "drift_prevention"):
        assert after.get(key) == original.get(key), key

    # 4. apply again: a true no-op
    code, out = cli(client, "plan", "--detailed-exitcode", "-f", str(repo))
    assert code == 0 and "1 unchanged" in out, out

    # 5. someone flips a control in the console; diff sees exactly that; apply reverts
    tampered = copy.deepcopy(server())
    tampered["block_disallowed_images"] = True
    rp.update_runtime_policy(client.server, client.token, throwaway, tampered)

    code, out = cli(client, "plan", "--detailed-exitcode", "-f", str(repo), "--output", "json")
    assert code == 2
    import json
    changes = json.loads(out)["results"][0]["changes"]
    assert [c["path"] for c in changes] == ["block_disallowed_images"]

    code, out = cli(client, "apply", "-f", str(repo))
    assert code == 0 and "1 updated" in out, out
    assert server()["block_disallowed_images"] is False

    # 6. the file is removed from Git. An empty repo is refused first...
    for f in repo.glob("runtime-policy-*.yaml"):
        f.unlink()
    code, out = cli(client, "apply", "-f", str(repo), "--detailed-exitcode")
    assert code == 2 and "no resources of this kind were loaded" in out, out
    assert server() is not None

    # ...and deleted when that is explicitly intended.
    code, out = cli(client, "apply", "-f", str(repo), "--allow-empty")
    assert code == 0 and "1 deleted" in out, out
    assert server() is None


def test_adopt_hand_over_release_then_nothing_is_deleted(client, throwaway, tmp_path):
    from aquasec import runtime_policies as rp

    from aquasec_casc.reconcile import marker

    first, second = f"live-{secrets.token_hex(3)}", f"live-{secrets.token_hex(3)}"
    repo = tmp_path / "repo"

    def server():
        return rp.get_runtime_policy(client.server, client.token, throwaway)

    original = server()
    unchanged = ("enabled", "enforce", "application_scopes", "block_disallowed_images",
                 "container_exec", "drift_prevention")

    code, out = cli(client, "export", "--scope", "Global", "--name", throwaway,
                    "-o", str(repo), "--instance", first)
    assert code == 0, out
    code, out = cli(client, "apply", "-f", str(repo))
    assert code == 0 and "1 adopted" in out, out

    # dry run: names the object, writes nothing
    code, out = cli(client, "release", "-f", str(repo), "--name", throwaway, "--dry-run")
    assert code == 0 and "1 to release" in out, out
    assert marker.owner(server()["description"]) == first

    # hand over: the old instance is now blocked, the new one owns it
    code, out = cli(client, "release", "-f", str(repo), "--name", throwaway, "--to", second)
    assert code == 0 and "1 handed over" in out, out
    assert marker.owner(server()["description"]) == second
    code, out = cli(client, "plan", "--detailed-exitcode", "-f", str(repo))
    assert code == 2 and "blocked" in out, out

    # release from the new owner: the description is back to the original text
    code, out = cli(client, "release", "--instance", second, "--name", throwaway)
    assert code == 0 and "1 released" in out, out
    after = server()
    assert after["description"] == original["description"]
    for key in unchanged:
        assert after.get(key) == original.get(key), key

    # neither instance deletes it when its file goes away
    for f in repo.glob("runtime-policy-*.yaml"):
        f.unlink()
    for instance in (first, second):
        code, out = cli(client, "apply", "-f", str(repo), "--allow-empty", "--instance", instance)
        assert code == 0 and "0 deleted" in out, out
    assert server() is not None


def test_destroy_refuses_unmanaged_then_deletes_managed(client, throwaway, tmp_path):
    from aquasec import runtime_policies as rp

    instance = f"live-{secrets.token_hex(3)}"
    repo = tmp_path / "repo"

    def server():
        return rp.get_runtime_policy(client.server, client.token, throwaway)

    code, out = cli(client, "export", "--scope", "Global", "--name", throwaway,
                    "-o", str(repo), "--instance", instance)
    assert code == 0, out

    # not adopted yet: the file names it, but the tool does not own it
    code, out = cli(client, "destroy", "-f", str(repo), "--yes")
    assert code == 0 and "1 blocked" in out and "no ownership marker" in out, out
    assert server() is not None

    code, out = cli(client, "apply", "-f", str(repo))
    assert code == 0 and "1 adopted" in out, out

    code, out = cli(client, "destroy", "-f", str(repo), "--dry-run")
    assert code == 0 and "1 to destroy" in out, out
    assert server() is not None

    code, out = cli(client, "destroy", "-f", str(repo), "--yes")
    assert code == 0 and "1 destroyed" in out, out
    assert server() is None


def test_the_all_controls_example_is_stored_as_written_and_survives_a_resave(client, tmp_path):
    """Every section, through create and a later update. Aqua validates the two
    differently: some settings are accepted on create, then dropped or refused
    on update -- this is the test that catches the next one."""
    from pathlib import Path

    from aquasec import runtime_policies as rp

    tag = secrets.token_hex(3)
    name = f"aquasec-casc-live-{tag}-all-controls"
    repo = tmp_path / "repo"
    repo.mkdir()
    example = Path(__file__).resolve().parents[2] / "examples/playground/runtime-policy-all-controls.yaml"
    (repo / "policy.yaml").write_text(
        example.read_text(encoding="utf-8").replace("name: casc-playground-all-controls", f"name: {name}"),
        encoding="utf-8")
    (repo / "aquasec-casc.yaml").write_text(f"instance: live-{tag}\n", encoding="utf-8")

    try:
        code, out = cli(client, "apply", "-f", str(repo))
        assert code == 0 and "1 created" in out, out
        code, out = cli(client, "plan", "-f", str(repo), "--detailed-exitcode")
        assert code == 0, out

        stored = rp.get_runtime_policy(client.server, client.token, name)
        rp.update_runtime_policy(client.server, client.token, name, stored)   # a console save
        code, out = cli(client, "plan", "-f", str(repo), "--detailed-exitcode")
        assert code == 0, out
    finally:
        rp.delete_runtime_policy(client.server, client.token, name, missing_ok=True)


def test_assurance_export_adopt_noop_drift_revert_delete(client, tmp_path):
    """The whole path on an assurance policy. Inert: scoped to match nothing."""
    import json

    from aquasec import assurance_policies as ap

    from aquasec_casc.reconcile import marker

    tag = secrets.token_hex(3)
    instance, name = f"live-{tag}", f"aquasec-casc-live-{tag}-assurance"
    repo = tmp_path / "repo"

    def server():
        return ap.get_assurance_policy(client.server, client.token, "image", name)

    ap.create_assurance_policy(client.server, client.token, "image", {
        "name": name, "assurance_type": "image", "application_scopes": ["Global"],
        "description": "Made in the console (aquasec-casc live test, safe to delete)",
        "cvss_severity_enabled": True, "cvss_severity": "high",
        "scope": {"expression": "v1", "variables": [{"attribute": "image.name",
                                                     "value": f"casc-no-such-{tag}"}]}})
    try:
        original = server()
        code, out = cli(client, "export", "--scope", "Global", "--name", name, "--kind",
                        "AssurancePolicy", "-o", str(repo), "--instance", instance)
        assert code == 0 and "1 exported" in out, out

        code, out = cli(client, "plan", "--detailed-exitcode", "-f", str(repo), "--output", "json")
        assert code == 2, out
        assert [c["path"] for c in json.loads(out)["results"][0]["changes"]] == ["description"]

        code, out = cli(client, "apply", "-f", str(repo))
        assert code == 0 and "1 adopted" in out, out
        after = server()
        assert marker.owner(after["description"]) == instance
        for key in ("cvss_severity", "cvss_severity_enabled", "scope", "application_scopes"):
            assert after[key] == original[key], key

        code, out = cli(client, "plan", "--detailed-exitcode", "-f", str(repo))
        assert code == 0 and "1 unchanged" in out, out

        tampered = {**server(), "fail_cicd": True}             # on in the console, not in the file
        ap.update_assurance_policy(client.server, client.token, "image", name, tampered)
        code, out = cli(client, "plan", "--detailed-exitcode", "-f", str(repo), "--output", "json")
        assert code == 2, out
        assert [c["path"] for c in json.loads(out)["results"][0]["changes"]] == ["fail_cicd"]
        code, out = cli(client, "apply", "-f", str(repo))
        assert code == 0 and "1 updated" in out, out
        assert server()["fail_cicd"] is False

        code, out = cli(client, "release", "-f", str(repo), "--name", name, "--dry-run")
        assert code == 0 and "1 to release" in out, out

        for f in repo.glob("assurance-policy-*.yaml"):
            f.unlink()
        code, out = cli(client, "apply", "-f", str(repo), "--allow-empty")
        assert code == 0 and "1 deleted" in out, out
        assert server() is None
    finally:
        ap.delete_assurance_policy(client.server, client.token, "image", name, missing_ok=True)
