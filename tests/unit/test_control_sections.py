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
    body = api({"portBlock": {"blockedInboundPorts": ["22"]}})
    assert body["port_block"] == {"enabled": True, "block_inbound_ports": ["22"]}


def test_an_explicit_off_is_kept():
    body = api({"portBlock": {"enabled": False, "blockedInboundPorts": ["22"]}})
    assert body["port_block"]["enabled"] is False


@pytest.mark.parametrize("value", [True, False])
def test_true_and_false_are_shorthand_for_a_section(value):
    assert api({"fileBlock": value})["file_block"] == {"enabled": value}


def test_exec_controls_carry_their_allowed_processes_and_gates():
    body = api({"blockContainerExec": {"allowedProcesses": ["/bin/sh"]},
                "blockReverseShell": {"whitelistedIps": ["10.0.0.0/8"]},
                "blockFilelessExec": {"allowedProcesses": ["python"]}})
    assert body["container_exec"] == {"enabled": True, "block_container_exec": True,
                                      "container_exec_proc_white_list": ["/bin/sh"]}
    assert body["reverse_shell"] == {"enabled": True, "block_reverse_shell": True,
                                     "reverse_shell_ip_white_list": ["10.0.0.0/8"]}
    assert body["block_fileless_exec"] is True
    assert body["block_fileless_exec_proc_white_list"] == ["python"]


def test_drift_prevention_switch_writes_exec_lockdown_too():
    """The console's one switch; enabled and exec_lockdown are equal on every
    console-made policy."""
    body = api({"driftPrevention": {"includeScriptFiles": True}})
    assert body["drift_prevention"] == {"enabled": True, "exec_lockdown": True,
                                        "exec_lockdown_scripts": True}


def test_section_names_map_to_the_api():
    body = api({"limitContainerPrivileges": {"hostNetwork": True},
                "blockOutdatedImages": {"ageThreshold": 2, "unit": "weeks"},
                "forensics": {"fullCommandArguments": True},
                "fileIntegrityMonitoring": {"create": True, "monitor": {"paths": ["/etc/*"]},
                                            "exclude": {"users": ["root"]}}})
    assert body["limit_container_privileges"] == {"enabled": True, "netmode": True}
    assert body["block_outdated_images"] == {"enabled": True, "threshold_value": 2,
                                             "threshold_unit": "weeks"}
    assert body["auditing"] == {"enabled": True, "audit_process_cmdline": True}
    assert body["file_integrity_monitoring"] == {
        "enabled": True, "monitored_files_create": True, "monitored_files": ["/etc/*"],
        "exceptional_monitored_files_users": ["root"]}


def test_capabilities_block_drops_the_listed_capabilities():
    body = api({"capabilitiesBlock": {"dropCapabilities": ["NET_RAW", "ALL"]}})
    assert body["linux_capabilities"] == {"enabled": True,
                                          "remove_linux_capabilities": ["NET_RAW", "ALL"]}


@pytest.mark.parametrize("controls,hint", [
    ({"containerExecAllowedProcesses": ["sh"]}, "now 'blockContainerExec.allowedProcesses'"),
    ({"fileIntegrityMonitoring": {"paths": ["/etc"]}}, "now 'monitor.paths'"),
    ({"onlyRegisteredImages": True}, "now 'blockUnregisteredImages'"),
    ({"driftPrevention": {"imageLockdown": True}}, "not in Aqua's console"),
    ({"portBlok": {"blockedInboundPorts": ["22"]}}, "did you mean 'portBlock'"),
])
def test_unknown_fields_get_a_hint_for_that_spot(controls, hint):
    """Old names say what they became; typos are matched only against the
    names valid where they appear, not anywhere in the schema."""
    with pytest.raises(SchemaError, match=hint):
        load_document(doc(controls), "t.yaml")


def test_a_hint_never_points_to_a_field_from_elsewhere():
    """'paths' exists, but under monitor/exclude -- not here."""
    with pytest.raises(SchemaError) as exc:
        load_document(doc({"fileBlock": {"path": ["/etc"]}}), "t.yaml")
    assert "did you mean" not in str(exc.value)


def test_blocking_outdated_images_on_a_host_fails_validation():
    with pytest.raises(SchemaError, match="only available on container"):
        load_document(doc({"blockOutdatedImages": {"ageThreshold": 2, "unit": "days"}}, "host"), "t.yaml")


def test_switched_off_it_is_fine_on_a_host():
    """Aqua returns it, off, on every policy -- exports carry it."""
    api({"blockOutdatedImages": {"enabled": False, "ageThreshold": 0}}, "host")


@pytest.mark.parametrize("controls", [
    {"fileIntegrityMonitoring": {"read": True}},
    {"fileIntegrityMonitoring": {"attributes": True}},
    {"realTimeMalwareProtection": {"includeDirectories": ["/*"]}},
])
def test_settings_aqua_will_not_keep_are_not_offered(controls):
    """Write-tested: Aqua drops, refuses on update, or overwrites these."""
    with pytest.raises(SchemaError, match="unknown field"):
        load_document(doc(controls), "t.yaml")


@pytest.mark.parametrize("controls", [
    {"readonlyFiles": {"files": ["/etc/passwd"]}},
    {"failedKubernetesChecks": {"checks": ["x"]}},
    {"driftPrevention": {"imageLockdown": True}},
    {"executablesAllowed": {"rootExecutables": ["sh"]}},
    {"fileBlock": {"users": ["root"]}},
    {"packageBlock": {"processes": ["sh"]}},
])
def test_settings_the_console_does_not_show_are_not_offered(controls):
    with pytest.raises(SchemaError, match="unknown field"):
        load_document(doc(controls), "t.yaml")


def _export_one(**fields):
    import sys
    sys.path.insert(0, "tests")
    from aquasec_casc.export import export_kind
    from unit.test_engine import FakeAqua

    obj = {"name": "p", "description": "", "enabled": False, "runtime_type": "container",
           "application_scopes": ["Global"], "is_ootb_policy": False, **fields}
    aqua = FakeAqua({"p": obj})
    (item,) = export_kind(aqua, registry.get("RuntimePolicy"), instance="x",
                          scope="Global").exported
    return item.document, aqua


def test_controls_that_are_off_are_not_exported():
    """Aqua stores false, 0, "" and [] for a control that is off; a control the
    file leaves out is off, so none of it is written."""
    doc, _ = _export_one(
        block_fileless_exec=False, fork_guard_process_limit=0,
        block_outdated_images={"enabled": False, "threshold_value": 0, "threshold_unit": ""},
        malware_scan_options={"enabled": False, "action": "", "exclude_directories": []},
        port_block={"enabled": True, "block_inbound_ports": ["22"], "block_outbound_ports": []})
    assert doc["spec"]["controls"] == {"portBlock": {"blockedInboundPorts": ["22"]}}


def test_a_control_on_with_no_settings_is_exported_as_true():
    doc, _ = _export_one(file_block={"enabled": True, "filename_block_list": []},
                         container_exec={"enabled": True, "block_container_exec": True,
                                         "container_exec_proc_white_list": None})
    assert doc["spec"]["controls"] == {"fileBlock": True, "blockContainerExec": True}


def test_a_section_off_is_not_exported_and_applying_changes_nothing():
    """Its settings stay on the server untouched: only the switch is managed."""
    from aquasec_casc.reconcile import Options, Outcome, reconcile
    from aquasec_casc.schema import load_document

    doc, aqua = _export_one(
        port_block={"enabled": False, "block_inbound_ports": ["22"], "block_outbound_ports": []},
        container_exec={"enabled": False, "block_container_exec": False,
                        "container_exec_proc_white_list": ["sh"]})
    assert "controls" not in doc["spec"]
    resource = load_document(doc, "p.yaml")[0]
    r = reconcile(resource, registry.get("RuntimePolicy"), aqua, Options(instance="x"))
    assert r.outcome is Outcome.ADOPTED and [c.path for c in r.plan.changes] == ["description"]


def test_secure_ai_sections_map_to_the_api():
    body = api({"secureAiDiscovery": {"ignoreList": ["OpenAI@gpt-4o"]},
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
    resource = load_document({**doc({"secureAiDiscovery": {"ignoreList": ["OpenAI@*"]}}, "host"),
                              }, "t.yaml")[0]
    resource.spec.enforce = True
    body = FIELD_MAP.to_api(resource.model_dump(exclude_unset=True, mode="json"))
    assert body["secure_ai_discovery"]["enabled"] is True


@pytest.mark.parametrize("kind,type_field,type_", [("RuntimePolicy", "runtimeType", "container"),
                                                   ("AssurancePolicy", "assuranceType", "image")])
def test_a_heading_with_everything_commented_out_is_empty(kind, type_field, type_):
    from aquasec_casc.schema import load_document, registry
    doc = {"apiVersion": "config.aquasec.com/v1alpha1", "kind": kind, "metadata": {"name": "x"},
           "spec": {type_field: type_, "applicationScopes": ["Global"], "controls": None}}
    canonical = load_document(doc, "test")[0].model_dump(exclude_unset=True, mode="json")
    assert not registry.get(kind).field_map.to_api(canonical).get("block_disallowed_images")
