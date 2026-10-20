"""Control sections: the console's sections, their switches, and Aqua's rules."""

from __future__ import annotations

import pytest

from aquasec_casc.schema import SchemaError, load_document, registry

FIELD_MAP = registry.get("RuntimePolicy").field_map


def doc(controls, runtime="container"):
    return {"apiVersion": "config.aquasec.com/v1alpha1", "kind": "RuntimePolicy",
            "metadata": {"name": "p"},
            "spec": {"runtimeType": runtime, "applicationScopes": ["Global"], "controls": controls}}


def api(controls, runtime="container"):
    resource = load_document(doc(controls, runtime), "t.yaml")[0]
    return FIELD_MAP.to_api(resource.model_dump(exclude_unset=True, mode="json"))


def test_writing_a_setting_turns_the_section_on():
    """The API's switch and settings are separate; settings under an off switch
    silently do nothing. Writing a setting means you want the control."""
    body = api({"portBlock": {"inbound": ["22"]}})
    assert body["port_block"] == {"enabled": True, "block_inbound_ports": ["22"]}


def test_an_explicit_off_is_kept():
    body = api({"portBlock": {"enabled": False, "inbound": ["22"]}})
    assert body["port_block"]["enabled"] is False


def test_drift_prevention_follows_the_same_rule():
    assert api({"driftPrevention": {"execLockdown": True}})["drift_prevention"]["enabled"] is True


def test_section_names_map_to_the_api():
    body = api({"limitContainerPrivileges": {"hostNetwork": True, "ownerUserContext": True},
                "blockOutdatedImages": {"olderThan": 2, "unit": "weeks"},
                "forensics": {"processCommandLine": True}})
    assert body["limit_container_privileges"] == {"enabled": True, "netmode": True,
                                                  "use_host_user": True}
    assert body["block_outdated_images"] == {"enabled": True, "threshold_value": 2,
                                             "threshold_unit": "weeks"}
    assert body["auditing"] == {"enabled": True, "audit_process_cmdline": True}


@pytest.mark.parametrize("controls,runtime,message", [
    ({"readonlyFiles": {"files": ["/etc/passwd"]}}, "container", "not available on container"),
    ({"blockOutdatedImages": {"olderThan": 2, "unit": "days"}}, "host", "only available on container"),
])
def test_sections_aqua_refuses_for_the_runtime_type_fail_validation(controls, runtime, message):
    with pytest.raises(SchemaError, match=message):
        load_document(doc(controls, runtime), "t.yaml")


def test_switched_off_they_are_fine_anywhere():
    """Aqua returns both sections, off, on every policy -- exports carry them."""
    api({"readonlyFiles": {"enabled": False}}, "container")
    api({"blockOutdatedImages": {"enabled": False, "olderThan": 0}}, "host")


def test_read_only_files_are_fine_on_hosts():
    assert api({"readonlyFiles": {"files": ["/etc/passwd"]}}, "host")["readonly_files"]["enabled"]


@pytest.mark.parametrize("controls", [
    {"fileIntegrityMonitoring": {"monitorRead": True}},
    {"fileIntegrityMonitoring": {"monitorAttributes": True}},
    {"malwareProtection": {"includeDirectories": ["/*"]}},
])
def test_settings_aqua_will_not_keep_are_not_offered(controls):
    """Write-tested: Aqua drops, refuses on update, or overwrites these."""
    with pytest.raises(SchemaError, match="unknown field"):
        load_document(doc(controls), "t.yaml")


def test_an_unset_choice_is_not_exported():
    """Aqua stores "" for a unit or action while the control is off."""
    import sys
    sys.path.insert(0, "tests")
    from aquasec_casc.export import export_kind
    from unit.test_engine import FakeAqua

    obj = {"name": "p", "description": "", "enabled": False, "runtime_type": "container",
           "application_scopes": ["Global"], "is_ootb_policy": False,
           "block_outdated_images": {"enabled": False, "threshold_value": 0, "threshold_unit": ""},
           "malware_scan_options": {"enabled": False, "action": ""}}
    (item,) = export_kind(FakeAqua({"p": obj}), registry.get("RuntimePolicy"),
                          instance="x", scope="Global").exported
    controls = item.document["spec"]["controls"]
    assert "unit" not in controls["blockOutdatedImages"] and "action" not in controls["malwareProtection"]


def test_secure_ai_sections_map_to_the_api():
    body = api({"secureAiDiscovery": {"ignore": ["OpenAI@gpt-4o"]},
                "secureAiUnauthorizedModels": {"models": ["DeepSeek@*", "Inference-Server@llama3"]}})
    assert body["secure_ai_discovery"] == {"enabled": True, "ignore_list": ["OpenAI@gpt-4o"]}
    assert body["secure_ai_unauthorized_models"] == {
        "enabled": True, "unauthorized_list": ["DeepSeek@*", "Inference-Server@llama3"]}


@pytest.mark.parametrize("entry", ["OpenAI", "@gpt-4o", "OpenAI@", " @x"])
def test_secure_ai_entries_must_be_service_at_model(entry):
    """Aqua refuses anything else with HTTP 400 (write-tested); say so offline."""
    with pytest.raises(SchemaError, match="not Service@model"):
        load_document(doc({"secureAiUnauthorizedModels": {"models": [entry]}}), "t.yaml")


def test_secure_ai_is_kept_in_enforce_mode_and_on_hosts():
    """The console switches Secure AI off in enforce mode; the API keeps it as
    written (write-tested), so the tool sends what the file says."""
    resource = load_document({**doc({"secureAiDiscovery": {"ignore": ["OpenAI@*"]}}, "host"),
                              }, "t.yaml")[0]
    resource.spec.enforce = True
    body = FIELD_MAP.to_api(resource.model_dump(exclude_unset=True, mode="json"))
    assert body["secure_ai_discovery"]["enabled"] is True
