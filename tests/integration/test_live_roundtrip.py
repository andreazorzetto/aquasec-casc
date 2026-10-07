"""Live round trip against a real Aqua tenant, through the real CLI. Opt-in.

Runs only with AQUA_CASC_LIVE=1, using AQUA_* environment variables or, if
AQUA_CASC_PROFILE is set, that saved aquasec-lib profile:

    AQUA_CASC_LIVE=1 AQUA_CASC_PROFILE=lab pytest tests/integration -v

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
    os.environ.get("AQUA_CASC_LIVE") != "1",
    reason="live test: set AQUA_CASC_LIVE=1 (and credentials) to run against a tenant",
)

PROFILE = os.environ.get("AQUA_CASC_PROFILE")


@pytest.fixture(scope="module")
def client():
    from aqua_casc.client import connect, settings_from_env, settings_from_profile
    return connect(settings_from_profile(PROFILE) if PROFILE else settings_from_env())


@pytest.fixture
def throwaway(client):
    """A pre-existing, unmarked policy -- as if someone made it in the console."""
    from aquasec import runtime_policies as rp

    name = f"aqua-casc-live-{secrets.token_hex(3)}"
    rp.create_runtime_policy(client.server, client.token, {
        "name": name, "runtime_type": "container", "enabled": False,
        "description": "Made in the console (aqua-casc live test, safe to delete)",
        "application_scopes": ["Global"], "block_disallowed_images": False,
    })
    yield name
    rp.delete_runtime_policy(client.server, client.token, name, missing_ok=True)
    assert rp.get_runtime_policy(client.server, client.token, name) is None


def cli(client, *argv):
    from aqua_casc.cli.main import main

    out, err = io.StringIO(), io.StringIO()
    code = main(list(argv), stdout=out, stderr=err, connect=lambda profile: client)
    return code, out.getvalue() + err.getvalue()


def test_export_adopt_noop_drift_revert_delete(client, throwaway, tmp_path):
    from aquasec import runtime_policies as rp

    from aqua_casc.reconcile import marker

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
    code, out = cli(client, "diff", "-f", str(repo))
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
    code, out = cli(client, "diff", "-f", str(repo))
    assert code == 0 and "1 unchanged" in out, out

    # 5. someone flips a control in the console; diff sees exactly that; apply reverts
    tampered = copy.deepcopy(server())
    tampered["block_disallowed_images"] = True
    rp.update_runtime_policy(client.server, client.token, throwaway, tampered)

    code, out = cli(client, "diff", "-f", str(repo), "--output", "json")
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
    assert code == 2 and "no resources were loaded" in out, out
    assert server() is not None

    # ...and deleted when that is explicitly intended.
    code, out = cli(client, "apply", "-f", str(repo), "--allow-empty")
    assert code == 0 and "1 deleted" in out, out
    assert server() is None
