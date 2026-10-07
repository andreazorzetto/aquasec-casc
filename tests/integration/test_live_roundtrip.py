"""Live round trip against a real Aqua tenant. Opt-in.

Runs only with AQUA_CASC_LIVE=1, using AQUA_* environment variables or, if
AQUA_CASC_PROFILE is set, that saved aquasec-lib profile. It creates one
throwaway runtime policy (disabled, so inert), exercises the demo sequence and
deletes it again, even on failure.

    AQUA_CASC_LIVE=1 AQUA_CASC_PROFILE=lab pytest tests/integration -v
"""

from __future__ import annotations

import copy
import os
import secrets
import textwrap

import pytest
import yaml

pytestmark = pytest.mark.skipif(
    os.environ.get("AQUA_CASC_LIVE") != "1",
    reason="live test: set AQUA_CASC_LIVE=1 (and credentials) to run against a tenant",
)


@pytest.fixture(scope="module")
def client():
    from aqua_casc.client import connect, settings_from_env, settings_from_profile

    profile = os.environ.get("AQUA_CASC_PROFILE")
    settings = settings_from_profile(profile) if profile else settings_from_env()
    return connect(settings)


@pytest.fixture
def throwaway(client):
    from aquasec import runtime_policies as rp

    name = f"aqua-casc-live-{secrets.token_hex(3)}"
    yield name
    rp.delete_runtime_policy(client.server, client.token, name, missing_ok=True)
    assert rp.get_runtime_policy(client.server, client.token, name) is None


def test_create_noop_drift_revert(client, throwaway, tmp_path):
    from aquasec import runtime_policies as rp

    from aqua_casc.reconcile import FileStateBackend, Options, Outcome, reconcile_all
    from aqua_casc.schema import load_document, registry

    doc = textwrap.dedent(f"""
        apiVersion: config.aquasec.com/v1alpha1
        kind: RuntimePolicy
        metadata:
          name: {throwaway}
        spec:
          description: aqua-casc live test - safe to delete
          enabled: false
          applicationScopes: ["Global"]
          controls:
            blockNonCompliantImages: false
            blockContainerExec: true
    """)
    resource = load_document(yaml.safe_load(doc), "live.yaml")[0]
    state = FileStateBackend(tmp_path).load()

    def run(**opts):
        return reconcile_all([resource], registry.get, state, client, Options(**opts))

    def server():
        return rp.get_runtime_policy(client.server, client.token, throwaway)

    assert run().results[0].outcome is Outcome.CREATED
    assert server()["enabled"] is False

    again = run()
    assert again.results[0].outcome is Outcome.IN_SYNC and again.exit_code() == 0

    tampered = copy.deepcopy(server())
    tampered["block_disallowed_images"] = True
    rp.update_runtime_policy(client.server, client.token, throwaway, tampered)

    planned = run(dry_run=True)
    plan = planned.results[0].plan
    assert planned.exit_code() == 2
    assert [c.path for c in plan.changes] == ["block_disallowed_images"]
    assert server()["block_disallowed_images"] is True          # dry run wrote nothing

    assert run().results[0].outcome is Outcome.UPDATED
    after = server()
    assert after["block_disallowed_images"] is False
    assert after["container_exec"]["block_container_exec"] is True

    assert run().results[0].outcome is Outcome.IN_SYNC
