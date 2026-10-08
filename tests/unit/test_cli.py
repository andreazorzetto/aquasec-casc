"""The CLI, run in-process against a fake Aqua."""

from __future__ import annotations

import io
import json
import textwrap
from pathlib import Path

import pytest
import yaml

from aquasec_casc.cli.main import main
from aquasec_casc.reconcile import marker

from .test_engine import FakeAqua

POLICY = textwrap.dedent("""
    apiVersion: config.aquasec.com/v1alpha1
    kind: RuntimePolicy
    metadata:
      name: devtest-baseline
    spec:
      applicationScopes: ["DevTest"]
      enforce: false
      controls:
        blockNonCompliantImages: false
""")


@pytest.fixture
def repo(tmp_path) -> Path:
    (tmp_path / "policy.yaml").write_text(POLICY, encoding="utf-8")
    (tmp_path / "aquasec-casc.yaml").write_text("instance: platform\n", encoding="utf-8")
    return tmp_path


def run(argv, aqua=None):
    out, err = io.StringIO(), io.StringIO()
    code = main(argv, stdout=out, stderr=err, connect=lambda profile: aqua)
    return code, out.getvalue(), err.getvalue()


def marked(name, **extra):
    return {"name": name, "description": f"x\n\n{marker.marker('platform')}",
            "application_scopes": ["DevTest"], "enforce": False,
            "block_disallowed_images": False, "is_ootb_policy": False, **extra}


# --------------------------------------------------------------------------- #
# validate
# --------------------------------------------------------------------------- #

def test_validate_ok(repo):
    code, out, _ = run(["validate", "-f", str(repo)])
    assert code == 0 and "1 resource(s) valid" in out


def test_validate_does_not_need_an_instance_or_a_network(tmp_path):
    (tmp_path / "p.yaml").write_text(POLICY, encoding="utf-8")
    assert run(["validate", "-f", str(tmp_path)])[0] == 0


def test_validate_reports_errors_with_exit_1(tmp_path):
    (tmp_path / "p.yaml").write_text(POLICY.replace("enforce: false", "enforcee: false"), encoding="utf-8")
    code, _, err = run(["validate", "-f", str(tmp_path)])
    assert code == 1 and "enforcee" in err and "did you mean" in err


def test_a_bad_config_file_is_reported(repo):
    (repo / "aquasec-casc.yaml").write_text("instance: platform\nprune: true\n", encoding="utf-8")
    code, _, err = run(["validate", "-f", str(repo)])
    assert code == 1 and "unknown setting" in err


# --------------------------------------------------------------------------- #
# diff and apply
# --------------------------------------------------------------------------- #

def test_diff_exits_2_with_changes_then_apply_then_diff_exits_0(repo):
    aqua = FakeAqua()
    code, out, _ = run(["diff", "-f", str(repo)], aqua)
    assert code == 2 and "will be created" in out
    assert aqua.writes() == []

    code, out, _ = run(["apply", "-f", str(repo)], aqua)
    assert code == 0 and "1 created" in out

    code, out, _ = run(["diff", "-f", str(repo)], aqua)
    assert code == 0 and "0 created" in out


def test_adoption_is_shown_as_a_marker_not_as_a_description_diff(repo):
    aqua = FakeAqua({"devtest-baseline": {**marked("devtest-baseline"), "description": "console text"}})
    code, out, _ = run(["diff", "-f", str(repo)], aqua)
    assert "will be adopted" in out
    assert "+ ownership marker (managed-by: aquasec-casc/platform)" in out


def test_apply_exit_2_only_with_detailed_exitcode(repo):
    aqua = FakeAqua({"devtest-baseline": marked("devtest-baseline"), "gone": marked("gone")})
    assert run(["apply", "-f", str(repo), "--no-delete"], aqua)[0] == 0
    code, out, _ = run(["apply", "-f", str(repo), "--no-delete", "--detailed-exitcode"], aqua)
    assert code == 2 and "orphaned, not deleted (--no-delete)" in out


def test_apply_deletes_orphans_by_default(repo):
    aqua = FakeAqua({"devtest-baseline": marked("devtest-baseline"), "gone": marked("gone")})
    code, out, _ = run(["apply", "-f", str(repo)], aqua)
    assert code == 0 and "gone" not in aqua.objects and "1 deleted" in out


def test_json_output_is_parseable_and_carries_the_exit_code(repo):
    code, out, _ = run(["diff", "-f", str(repo), "--output", "json"], FakeAqua())
    data = json.loads(out)
    assert data["exitCode"] == code == 2
    assert data["results"][0]["action"] == "create"


def test_instance_flag_beats_env_beats_file(repo, monkeypatch):
    aqua = FakeAqua()
    monkeypatch.setenv("AQUASEC_CASC_INSTANCE", "from-env")
    run(["apply", "-f", str(repo)], aqua)
    assert marker.owner(aqua.objects["devtest-baseline"]["description"]) == "from-env"

    aqua = FakeAqua()
    run(["apply", "-f", str(repo), "--instance", "from-flag"], aqua)
    assert marker.owner(aqua.objects["devtest-baseline"]["description"]) == "from-flag"


def test_no_instance_anywhere_is_an_error_that_explains_why(tmp_path, monkeypatch):
    monkeypatch.delenv("AQUASEC_CASC_INSTANCE", raising=False)
    (tmp_path / "p.yaml").write_text(POLICY, encoding="utf-8")
    code, _, err = run(["diff", "-f", str(tmp_path)], FakeAqua())
    assert code == 1 and "No instance name" in err and "aquasec-casc.yaml" in err


def test_an_invalid_instance_name_is_an_error(repo):
    code, _, err = run(["diff", "-f", str(repo), "--instance", "Not Valid"], FakeAqua())
    assert code == 1 and "not a valid instance name" in err


# --------------------------------------------------------------------------- #
# export
# --------------------------------------------------------------------------- #

def test_export_writes_documents_and_the_config_file(tmp_path):
    aqua = FakeAqua({"Dev Test": {**marked("Dev Test"), "description": "Hand made"}})
    target = tmp_path / "out"
    code, out, _ = run(["export", "--scope", "DevTest", "-o", str(target),
                        "--instance", "platform"], aqua)
    assert code == 0
    written = yaml.safe_load((target / "runtime-policy-dev-test.yaml").read_text())
    assert written["spec"]["aquaName"] == "Dev Test"
    assert written["spec"]["description"] == "Hand made"
    assert yaml.safe_load((target / "aquasec-casc.yaml").read_text()) == {"instance": "platform"}
    assert aqua.writes() == []                                   # export is read-only


def test_export_then_validate_then_apply_only_adopts(tmp_path):
    aqua = FakeAqua({"devtest": {**marked("devtest"), "description": "Hand made"}})
    target = tmp_path / "out"
    run(["export", "--scope", "DevTest", "-o", str(target), "--instance", "platform"], aqua)
    assert run(["validate", "-f", str(target)])[0] == 0

    code, out, _ = run(["apply", "-f", str(target)], aqua)
    assert code == 0
    assert "1 adopted" in out and "0 updated" in out and "0 created" in out
    code, out, _ = run(["diff", "-f", str(target)], aqua)
    assert code == 0 and "1 unchanged" in out


def test_export_refuses_to_overwrite_without_force(tmp_path):
    aqua = FakeAqua({"devtest": marked("devtest")})
    target = tmp_path / "out"
    args = ["export", "--scope", "DevTest", "-o", str(target), "--instance", "platform"]
    assert run(args, aqua)[0] == 0
    code, _, err = run(args, aqua)
    assert code == 1 and "--force" in err
    assert run(args + ["--force"], aqua)[0] == 0


# --------------------------------------------------------------------------- #
# Diff lines speak the YAML's vocabulary
# --------------------------------------------------------------------------- #

def test_a_change_is_named_as_in_the_yaml_with_the_api_name_alongside(repo):
    aqua = FakeAqua({"devtest-baseline": marked("devtest-baseline", block_disallowed_images=True)})
    code, out, _ = run(["diff", "-f", str(repo)], aqua)
    assert ("! controls.blockNonCompliantImages: true -> false   "
            "(API: block_disallowed_images)") in out


def test_a_controls_enabled_gate_joins_the_controls_line(tmp_path):
    (tmp_path / "aquasec-casc.yaml").write_text("instance: platform\n", encoding="utf-8")
    (tmp_path / "p.yaml").write_text(POLICY.replace(
        "blockNonCompliantImages: false", "blockContainerExec: true"), encoding="utf-8")
    aqua = FakeAqua({"devtest-baseline": marked(
        "devtest-baseline", container_exec={"enabled": False, "block_container_exec": False})})
    code, out, _ = run(["diff", "-f", str(tmp_path)], aqua)
    assert ("! controls.blockContainerExec: false -> true   "
            "(API: container_exec.block_container_exec + enabled)") in out
    assert "container_exec.enabled:" not in out          # not a separate line


def test_json_changes_carry_both_names(repo):
    aqua = FakeAqua({"devtest-baseline": marked("devtest-baseline", block_disallowed_images=True)})
    change = json.loads(run(["diff", "-f", str(repo), "--output", "json"], aqua)[1])["results"][0]["changes"][0]
    assert change["field"] == "controls.blockNonCompliantImages"
    assert change["path"] == "block_disallowed_images"


# --------------------------------------------------------------------------- #
# release
# --------------------------------------------------------------------------- #

def test_release_dry_run_then_release(repo):
    aqua = FakeAqua({"devtest-baseline": marked("devtest-baseline")})
    code, out, _ = run(["release", "-f", str(repo), "--dry-run"], aqua)
    assert code == 0 and "will be released" in out and "1 to release" in out
    assert aqua.writes() == []

    code, out, _ = run(["release", "-f", str(repo)], aqua)
    assert code == 0 and "1 released" in out and "adopts the objects again" in out
    assert marker.owner(aqua.objects["devtest-baseline"]["description"]) is None


def test_release_needs_no_yaml(tmp_path):
    aqua = FakeAqua({"p": marked("p")})
    code, out, _ = run(["release", "-f", str(tmp_path), "--instance", "platform"], aqua)
    assert code == 0 and "1 released" in out


def test_release_with_nothing_marked_says_so(repo):
    code, out, _ = run(["release", "-f", str(repo)], FakeAqua())
    assert code == 0 and "Nothing to release" in out


def test_hand_over(repo):
    aqua = FakeAqua({"p": marked("p")})
    code, out, _ = run(["release", "-f", str(repo), "--to", "team-b"], aqua)
    assert code == 0 and "handed over" in out and "1 handed over" in out and "blocked" in out
    assert marker.owner(aqua.objects["p"]["description"]) == "team-b"


@pytest.mark.parametrize("to,message", [("platform", "this instance already"),
                                        ("Team B", "not a valid instance")])
def test_hand_over_target_is_checked_before_connecting(repo, to, message):
    code, _, err = run(["release", "-f", str(repo), "--to", to], aqua=None)
    assert code == 1 and message in err


def test_release_json(repo):
    aqua = FakeAqua({"p": marked("p")})
    code, out, _ = run(["release", "-f", str(repo), "--output", "json"], aqua)
    data = json.loads(out)
    assert code == 0 and data["summary"] == "1 released"
    assert data["results"][0]["outcome"] == "released"


# --------------------------------------------------------------------------- #
# validate ignores connection flags; profile management
# --------------------------------------------------------------------------- #

def test_validate_accepts_and_ignores_profile_and_instance(repo):
    code, out, _ = run(["validate", "-f", str(repo), "--profile", "anything", "--instance", "x"])
    assert code == 0 and "1 resource(s) valid" in out


@pytest.fixture
def store(monkeypatch):
    """A fake profile store behind aquasec_casc.client.profiles."""
    from aquasec_casc.client import profiles

    state = {"default": "lab", "profiles": {
        "lab": {"auth_method": "api_keys", "csp_endpoint": "https://t.cloud.aquasec.com",
                "api_endpoint": "https://eu-1.api.cloudsploit.com", "credentials_ref": "1a2b3c4d"},
        "onprem": {"auth_method": "user_pass", "csp_endpoint": "https://aqua.local",
                   "credentials_ref": "5e6f7a8b"}}}

    def info(name=None):
        name = name or state["default"]
        p = state["profiles"].get(name)
        return None if p is None else {"name": name, "is_default": name == state["default"], **p}

    monkeypatch.setattr(profiles, "default_name", lambda: state["default"])
    monkeypatch.setattr(profiles, "info", info)
    monkeypatch.setattr(profiles, "all_info", lambda: [info(n) for n in state["profiles"]])
    monkeypatch.setattr(profiles, "delete", lambda n: {"success": state["profiles"].pop(n, None) is not None})
    monkeypatch.setattr(profiles, "set_default", lambda n: state.update(default=n) or {"success": True})
    return state


def test_profile_list_marks_the_default(store):
    code, out, _ = run(["profile", "list"])
    assert code == 0
    assert "* lab" in out and "  onprem" in out


def test_profile_show_defaults_to_the_default_and_never_shows_secrets(store):
    code, out, _ = run(["profile", "show"])
    assert code == 0 and "lab  (default)" in out and "ref 1a2b3c4d" in out


def test_profile_show_json(store):
    code, out, _ = run(["profile", "show", "onprem", "--output", "json"])
    assert code == 0 and json.loads(out)["name"] == "onprem"


def test_profile_set_default_and_delete(store):
    assert run(["profile", "set-default", "onprem"])[0] == 0 and store["default"] == "onprem"
    assert run(["profile", "delete", "lab"])[0] == 0 and "lab" not in store["profiles"]


@pytest.mark.parametrize("action", ["show", "delete", "set-default"])
def test_unknown_profiles_are_refused(store, action):
    code, _, err = run(["profile", action, "nope"])
    assert code == 1 and "No saved profile 'nope'" in err
    assert store["default"] == "lab"


def test_setup_runs_the_library_wizard(monkeypatch):
    from aquasec_casc.client import profiles
    seen = []
    monkeypatch.setattr(profiles, "setup", lambda name: seen.append(name) or True)
    assert run(["setup", "lab"])[0] == 0 and seen == ["lab"]
