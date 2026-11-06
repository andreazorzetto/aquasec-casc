# Schema reference

Generated from the schema by `scripts/schema_reference.py`; do not edit by hand.
[Writing policies](writing-policies.md) shows the same fields in use.

Names are the console's labels in camelCase. Under `actions`, `exceptions` and
`controls`, **what the file leaves out is off**. A control with settings can be
written `true`, and writing any of its settings switches it on. `aquasec-casc schema
KIND` prints the same as JSON Schema, for editors and CI. What this was tested against is
[at the end](#tested-against).

## RuntimePolicy

All under `spec`.

| Field | Type | API field | |
|---|---|---|---|
| `description` | text | `description` |  |
| `enabled` | true/false | `enabled` |  |
| `enforce` | true/false | `enforce` | False is audit mode, True is enforce mode. Defaults to audit: a policy that silently starts enforcing on creation is the wrong default for a tool whose first run may be against production. |
| `enforceAfterDays` | number | `enforce_after_days` | Enforce Mode after this many days. When Aqua makes the switch, write ``enforce: true`` too: a file still saying ``false`` puts the policy back in audit. |
| `runtimeType` | `container` \| `host` \| `function` | `runtime_type` |  |
| `applicationScopes` | list of text | `application_scopes` | The application scopes this policy applies to. Required: when Aqua is given none it applies the policy to Global, meaning every workload. Write ["Global"] if that is what you intend. |
| `additionalScopeCriteria` | object | | The console's Additional Scope Criteria: what, within the application scopes, a policy applies to. They can narrow a policy, never widen it. |
| `additionalScopeCriteria.expression` | text | `scope.expression` | How the variables combine, e.g. ``v1 \|\| v2``; ``v1`` is the first. |
| `additionalScopeCriteria.variables` | list of {attribute, value, name} | `scope.variables` |  |
| `controls` | object | | The security controls a runtime policy turns on or off, named as in the console's control list. A control left out is off. Not offered, because the console does not show them (and no console-made policy on the lab uses them): Read-Only Files, failed Kubernetes checks, drift prevention's image lockdown, root executables, and File and Package Block's users, processes and exceptions. Nor: Honeypot (``tripwire``: serverless; carries an AWS secret key, and the tool never manages credential fields) and the auditing ``*_config`` objects. All of these are left as Aqua has them. |
| `controls.blockNonCompliantImages` | true/false | `block_disallowed_images` | Block images an assurance policy has marked non-compliant. Worth understanding before relying on audit mode: the enforcer evaluates compliance by image *hash*, so a non-compliant verdict from one policy blocks that hash everywhere the enforcer sees it -- including scopes meant to be in audit mode. Leaving this control out of a dev/test policy entirely is the recommended fix, rather than relying on audit mode to soften it. The API field is ``block_disallowed_images`` -- see FIELD_MAP. |
| `controls.blockNonCompliantResources` | true/false | `block_non_compliant_workloads` | Block non-compliant Kubernetes resources (KubeEnforcer). |
| `controls.blockUnregisteredImages` | true/false | `only_registered_images` |  |
| `controls.blockNonKubernetesContainers` | true/false | `block_non_k8s_containers` |  |
| `controls.blockOutdatedImages` | object | | Block Outdated Images: images older than the threshold do not run. |
| `controls.blockOutdatedImages.enabled` | true/false | `block_outdated_images.enabled` | The control's switch. |
| `controls.blockOutdatedImages.ageThreshold` | number | `block_outdated_images.threshold_value` | Age Threshold: how old, in ``unit``. |
| `controls.blockOutdatedImages.unit` | `days` \| `weeks` \| `months` \| `years` | `block_outdated_images.threshold_unit` |  |
| `controls.registriesAllowed` | object | | Registries Allowed: images may only come from these. |
| `controls.registriesAllowed.enabled` | true/false | `allowed_registries.enabled` | The control's switch. |
| `controls.registriesAllowed.registries` | list of text | `allowed_registries.allowed_registries` |  |
| `controls.blockContainerExec` | object | | A blocking control with its Allowed Processes: Block Container Exec, Block Fileless Exec. |
| `controls.blockContainerExec.enabled` | true/false | `container_exec.block_container_exec` | The control's switch. |
| `controls.blockContainerExec.allowedProcesses` | list of text | `container_exec.container_exec_proc_white_list` |  |
| `controls.blockReverseShell.enabled` | true/false | `reverse_shell.block_reverse_shell` | The control's switch. |
| `controls.blockReverseShell.allowedProcesses` | list of text | `reverse_shell.reverse_shell_proc_white_list` |  |
| `controls.blockReverseShell.whitelistedIps` | list of text | `reverse_shell.reverse_shell_ip_white_list` | Whitelisted IPs / CIDRs. |
| `controls.blockFilelessExec` | object | | A blocking control with its Allowed Processes: Block Container Exec, Block Fileless Exec. |
| `controls.blockFilelessExec.enabled` | true/false | `block_fileless_exec` | The control's switch. |
| `controls.blockFilelessExec.allowedProcesses` | list of text | `block_fileless_exec_proc_white_list` |  |
| `controls.driftPrevention` | object | | Drift Prevention: executables not in the original image do not run. On a function policy the console calls this Block Malicious Executables. The console's switch writes two API fields, ``enabled`` and ``exec_lockdown``; they are equal on every console-made policy. The API's ``image_lockdown`` is not in the console and not offered. |
| `controls.driftPrevention.enabled` | true/false | `drift_prevention.enabled` | The control's switch. |
| `controls.driftPrevention.allowedProcesses` | list of text | `drift_prevention.exec_lockdown_white_list` |  |
| `controls.driftPrevention.includeScriptFiles` | true/false | `drift_prevention.exec_lockdown_scripts` |  |
| `controls.driftPrevention.applyToChildProcesses` | true/false | `drift_prevention.exec_lockdown_inherit_to_child` | Extend the Allowed Processes exemption to their child processes. |
| `controls.executablesAllowed` | object | | Executables Allowed: everything else is prevented from running. |
| `controls.executablesAllowed.enabled` | true/false | `allowed_executables.enabled` | The control's switch. |
| `controls.executablesAllowed.executables` | list of text | `allowed_executables.allow_executables` |  |
| `controls.executablesBlocked` | object | | Executables Blocked; Executables Blacklist on a function policy. |
| `controls.executablesBlocked.enabled` | true/false | `executable_blacklist.enabled` | The control's switch. |
| `controls.executablesBlocked.executables` | list of text | `executable_blacklist.executables` |  |
| `controls.limitNewPrivileges` | true/false | `no_new_privileges` |  |
| `controls.limitContainerPrivileges` | object | | Limit Container Privileges: each setting true prevents that privilege. The console's labels are sentences, so these are short forms. |
| `controls.limitContainerPrivileges.enabled` | true/false | `limit_container_privileges.enabled` | The control's switch. |
| `controls.limitContainerPrivileges.privileged` | true/false | `limit_container_privileges.privileged` | Privileged containers. |
| `controls.limitContainerPrivileges.hostNetwork` | true/false | `limit_container_privileges.netmode` | Access to host network. |
| `controls.limitContainerPrivileges.hostPid` | true/false | `limit_container_privileges.pidmode` | Use the host PID namespace. |
| `controls.limitContainerPrivileges.hostIpc` | true/false | `limit_container_privileges.ipcmode` | Use the host IPC namespace. |
| `controls.limitContainerPrivileges.hostUts` | true/false | `limit_container_privileges.utsmode` | Use the host UTS namespace. |
| `controls.limitContainerPrivileges.hostUserNamespace` | true/false | `limit_container_privileges.usermode` | Use the host user namespace. |
| `controls.limitContainerPrivileges.rootUser` | true/false | `limit_container_privileges.prevent_root_user` | Configured with 'root' user. |
| `controls.limitContainerPrivileges.lowPortBinding` | true/false | `limit_container_privileges.prevent_low_port_binding` | Port binding lower than 1024. The only privilege that also applies to Windows. |
| `controls.limitContainerPrivileges.addCapabilities` | true/false | `limit_container_privileges.block_add_capabilities` | Adding capabilities with --cap-add. |
| `controls.limitContainerPrivileges.ownerUserContext` | true/false | `limit_container_privileges.use_host_user` | Run in owner's user context (requires restart). In Aqua's docs; not shown by every console version. |
| `controls.capabilitiesBlock` | object | | Capabilities Block: Linux capabilities containers may not use, named as in the console's list (``NET_RAW``, ``SYS_ADMIN``; ``ALL``). The console offers it only in enforce mode; the API accepts it in audit mode too (seen live), so the tool stores what the file says, as for Secure AI. |
| `controls.capabilitiesBlock.enabled` | true/false | `linux_capabilities.enabled` | The control's switch. |
| `controls.capabilitiesBlock.dropCapabilities` | list of text | `linux_capabilities.remove_linux_capabilities` |  |
| `controls.forkGuard` | object | | Fork Guard (hosts; deprecated by Aqua). Aqua refuses it on a container policy. |
| `controls.forkGuard.enabled` | true/false | `enable_fork_guard` | The control's switch. |
| `controls.forkGuard.processLimit` | number | `fork_guard_process_limit` |  |
| `controls.blockCryptocurrencyMining` | true/false | `enable_crypto_mining_dns` |  |
| `controls.dnsIpReputation` | true/false | `enable_ip_reputation` |  |
| `controls.portScanningDetection` | true/false | `enable_port_scan_protection` |  |
| `controls.portBlock.enabled` | true/false | `port_block.enabled` | The control's switch. |
| `controls.portBlock.blockedInboundPorts` | list of text | `port_block.block_inbound_ports` |  |
| `controls.portBlock.blockedOutboundPorts` | list of text | `port_block.block_outbound_ports` |  |
| `controls.bruteForceLoginDetection` | true/false | `audit_brute_force_login` | Hosts. |
| `controls.fileBlock` | object | | File Block: no reading, writing or executing these files. |
| `controls.fileBlock.enabled` | true/false | `file_block.enabled` | The control's switch. |
| `controls.fileBlock.files` | list of text | `file_block.filename_block_list` |  |
| `controls.packageBlock` | object | | Package Block: no reading, writing or executing files of these packages. |
| `controls.packageBlock.enabled` | true/false | `package_block.enabled` | The control's switch. |
| `controls.packageBlock.packages` | list of text | `package_block.packages_black_list` |  |
| `controls.volumesBlocked` | object | | Volumes Blocked: host paths containers may not mount. |
| `controls.volumesBlocked.enabled` | true/false | `restricted_volumes.enabled` | The control's switch. |
| `controls.volumesBlocked.volumes` | list of text | `restricted_volumes.volumes` |  |
| `controls.fileIntegrityMonitoring` | object | | File Integrity Monitoring: audit events for the operations selected, never blocks. ``monitor`` and ``exclude`` are the console's Monitor and Exclude tabs; its presets are stored as the paths they expand to. The API also has read and attributes switches. Write-tested live: Aqua accepts them on create, then drops read and refuses attributes on every later update -- and the console does not show them -- so they are not offered here. |
| `controls.fileIntegrityMonitoring.enabled` | true/false | `file_integrity_monitoring.enabled` | The control's switch. |
| `controls.fileIntegrityMonitoring.create` | true/false | `file_integrity_monitoring.monitored_files_create` |  |
| `controls.fileIntegrityMonitoring.modify` | true/false | `file_integrity_monitoring.monitored_files_modify` |  |
| `controls.fileIntegrityMonitoring.delete` | true/false | `file_integrity_monitoring.monitored_files_delete` |  |
| `controls.fileIntegrityMonitoring.monitor` | object | | One tab of a monitoring control: the paths, processes and users it covers. |
| `controls.fileIntegrityMonitoring.monitor.paths` | list of text | `file_integrity_monitoring.monitored_files` |  |
| `controls.fileIntegrityMonitoring.monitor.processes` | list of text | `file_integrity_monitoring.monitored_files_processes` |  |
| `controls.fileIntegrityMonitoring.monitor.users` | list of text | `file_integrity_monitoring.monitored_files_users` |  |
| `controls.fileIntegrityMonitoring.exclude` | object | | One tab of a monitoring control: the paths, processes and users it covers. |
| `controls.fileIntegrityMonitoring.exclude.paths` | list of text | `file_integrity_monitoring.exceptional_monitored_files` |  |
| `controls.fileIntegrityMonitoring.exclude.processes` | list of text | `file_integrity_monitoring.exceptional_monitored_files_processes` |  |
| `controls.fileIntegrityMonitoring.exclude.users` | list of text | `file_integrity_monitoring.exceptional_monitored_files_users` |  |
| `controls.realTimeMalwareProtection` | object | | Real-time Malware Protection (needs the Advanced Malware Protection licence). The scanned directories are not configurable, as in the console: Aqua sets them itself and restores its own list on every save (write-tested). Only exclusions are yours. In audit mode, ``alert`` is the only action the console offers. |
| `controls.realTimeMalwareProtection.enabled` | true/false | `malware_scan_options.enabled` | The control's switch. |
| `controls.realTimeMalwareProtection.action` | `alert` \| `block` \| `delete` | `malware_scan_options.action` | Action for Malware Files. |
| `controls.realTimeMalwareProtection.excludedPaths` | list of text | `malware_scan_options.exclude_directories` |  |
| `controls.realTimeMalwareProtection.excludedProcesses` | list of text | `malware_scan_options.exclude_processes` |  |
| `controls.realTimeMalwareProtection.collectForensicFiles` | true/false | `malware_scan_options.file_forensic_collection` |  |
| `controls.realTimeMalwareProtection.collectSelectiveMemoryDumps` | true/false | `malware_scan_options.selective_memory_dump_collection` |  |
| `controls.forensics` | object | | Forensics: what goes into the audit log. The console's labels are sentences ("Audit all process activity of the container"), so these are short forms. |
| `controls.forensics.enabled` | true/false | `auditing.enabled` | The control's switch. |
| `controls.forensics.allProcesses` | true/false | `auditing.audit_all_processes` |  |
| `controls.forensics.fullCommandArguments` | true/false | `auditing.audit_process_cmdline` |  |
| `controls.forensics.allNetwork` | true/false | `auditing.audit_all_network` |  |
| `controls.forensics.osUserActivity` | true/false | `auditing.audit_os_user_activity` |  |
| `controls.forensics.successfulLogins` | true/false | `auditing.audit_success_login` |  |
| `controls.forensics.failedLogins` | true/false | `auditing.audit_failed_login` |  |
| `controls.forensics.userAccountManagement` | true/false | `auditing.audit_user_account_management` |  |
| `controls.systemIntegrityMonitoring` | object | | System Integrity Monitoring (hosts): audits, never blocks. |
| `controls.systemIntegrityMonitoring.enabled` | true/false | `system_integrity_protection.enabled` | The control's switch. |
| `controls.systemIntegrityMonitoring.systemTime` | true/false | `system_integrity_protection.audit_systemtime_change` |  |
| `controls.systemIntegrityMonitoring.windowsServicesMonitoring` | true/false | `system_integrity_protection.windows_services_monitoring` |  |
| `controls.systemIntegrityMonitoring.monitorSystemLogIntegrity` | true/false | `system_integrity_protection.monitor_audit_log_integrity` |  |
| `controls.osUsersAndGroupsAllowed.enabled` | true/false | `whitelisted_os_users.enabled` | The control's switch. |
| `controls.osUsersAndGroupsAllowed.usersAllowed` | list of text | `whitelisted_os_users.user_white_list` |  |
| `controls.osUsersAndGroupsAllowed.groupsAllowed` | list of text | `whitelisted_os_users.group_white_list` |  |
| `controls.osUsersAndGroupsBlocked.enabled` | true/false | `blacklisted_os_users.enabled` | The control's switch. |
| `controls.osUsersAndGroupsBlocked.usersBlocked` | list of text | `blacklisted_os_users.user_black_list` |  |
| `controls.osUsersAndGroupsBlocked.groupsBlocked` | list of text | `blacklisted_os_users.group_black_list` |  |
| `controls.windowsRegistryMonitoring` | object | | Windows Registry Monitoring (hosts): audits registry operations. |
| `controls.windowsRegistryMonitoring.enabled` | true/false | `registry_access_monitoring.enabled` | The control's switch. |
| `controls.windowsRegistryMonitoring.create` | true/false | `registry_access_monitoring.monitored_registry_create` |  |
| `controls.windowsRegistryMonitoring.modify` | true/false | `registry_access_monitoring.monitored_registry_modify` |  |
| `controls.windowsRegistryMonitoring.delete` | true/false | `registry_access_monitoring.monitored_registry_delete` |  |
| `controls.windowsRegistryMonitoring.attributes` | true/false | `registry_access_monitoring.monitored_registry_attributes` |  |
| `controls.windowsRegistryMonitoring.monitor` | object | | One tab of a monitoring control: the paths, processes and users it covers. |
| `controls.windowsRegistryMonitoring.monitor.paths` | list of text | `registry_access_monitoring.monitored_registry_paths` |  |
| `controls.windowsRegistryMonitoring.monitor.processes` | list of text | `registry_access_monitoring.monitored_registry_processes` |  |
| `controls.windowsRegistryMonitoring.monitor.users` | list of text | `registry_access_monitoring.monitored_registry_users` |  |
| `controls.windowsRegistryMonitoring.exclude` | object | | One tab of a monitoring control: the paths, processes and users it covers. |
| `controls.windowsRegistryMonitoring.exclude.paths` | list of text | `registry_access_monitoring.exceptional_monitored_registry_paths` |  |
| `controls.windowsRegistryMonitoring.exclude.processes` | list of text | `registry_access_monitoring.exceptional_monitored_registry_processes` |  |
| `controls.windowsRegistryMonitoring.exclude.users` | list of text | `registry_access_monitoring.exceptional_monitored_registry_users` |  |
| `controls.windowsRegistryProtection` | object | | Windows Registry Protection (hosts): blocks changes to the registry. |
| `controls.windowsRegistryProtection.enabled` | true/false | `readonly_registry.enabled` | The control's switch. |
| `controls.windowsRegistryProtection.protect` | object | | One tab of a monitoring control: the paths, processes and users it covers. |
| `controls.windowsRegistryProtection.protect.paths` | list of text | `readonly_registry.readonly_registry_paths` |  |
| `controls.windowsRegistryProtection.protect.processes` | list of text | `readonly_registry.readonly_registry_processes` |  |
| `controls.windowsRegistryProtection.protect.users` | list of text | `readonly_registry.readonly_registry_users` |  |
| `controls.windowsRegistryProtection.exclude` | object | | One tab of a monitoring control: the paths, processes and users it covers. |
| `controls.windowsRegistryProtection.exclude.paths` | list of text | `readonly_registry.exceptional_readonly_registry_paths` |  |
| `controls.windowsRegistryProtection.exclude.processes` | list of text | `readonly_registry.exceptional_readonly_registry_processes` |  |
| `controls.windowsRegistryProtection.exclude.users` | list of text | `readonly_registry.exceptional_readonly_registry_users` |  |
| `controls.secureAiDiscovery` | object | | Secure AI - Discovery: reports AI services and models in use. Audit only, Linux only. The console switches the Secure AI controls off when a policy is in enforce mode; the API keeps them as written (write-tested), so this tool stores what the file says in either mode. |
| `controls.secureAiDiscovery.enabled` | true/false | `secure_ai_discovery.enabled` | The control's switch. |
| `controls.secureAiDiscovery.ignoreList` | list of text | `secure_ai_discovery.ignore_list` | Models and services left out of discovery. |
| `controls.secureAiUnauthorizedModels` | object | | Secure AI - Unauthorized Models: flags the listed models as unauthorized (medium severity). Audit only, Linux only; same enforce-mode note as Discovery. |
| `controls.secureAiUnauthorizedModels.enabled` | true/false | `secure_ai_unauthorized_models.enabled` | The control's switch. |
| `controls.secureAiUnauthorizedModels.models` | list of text | `secure_ai_unauthorized_models.unauthorized_list` | Models and services flagged as unauthorized. |
| `controls.secureAiProtection` | true/false | `secure_ai_protection.enabled` | Secure AI - Protection. Needs the Prompt Protection toggle on the Integrations > Secure AI screen. Aqua's docs describe excluding services here; the API has only the switch. |
| `controls.bypassScope` | object | | Only on "Aqua default runtime policy" and "Aqua default host runtime policy"; anywhere else it is reported as not allowed and not sent. |
| `controls.bypassScope.enabled` | true/false | `bypass_scope.enabled` | The control's switch. |
| `controls.bypassScope.expression` | text | `bypass_scope.scope.expression` | How the variables combine, e.g. ``v1 \|\| v2 \|\| v3``. |
| `controls.bypassScope.variables` | list of {attribute, value, name} | `bypass_scope.scope.variables` |  |
| `aquaName` | text | `name` | The name in Aqua, when it is not a valid `metadata.name`. Defaults to `metadata.name`. |
| `enforcement` | `Reconcile` \| `ReportOnly` | | `ReportOnly` reports drift and changes nothing. |

## AssurancePolicy

All under `spec`.

| Field | Type | API field | |
|---|---|---|---|
| `assuranceType` | `image` \| `host` \| `function` \| `kubernetes` \| `cf_application` | `assurance_type` |  |
| `description` | text | `description` |  |
| `applicationScopes` | list of text | `application_scopes` | The application scopes this policy applies to. Required: when Aqua is given none it applies the policy to Global, meaning everything. Write ["Global"] if that is what you intend. |
| `additionalScopeCriteria` | object | | The console's Additional Scope Criteria: what, within the application scopes, a policy applies to. They can narrow a policy, never widen it. |
| `additionalScopeCriteria.expression` | text | `scope.expression` | How the variables combine, e.g. ``v1 \|\| v2``; ``v1`` is the first. |
| `additionalScopeCriteria.variables` | list of {attribute, value, name} | `scope.variables` |  |
| `actions` | object | | The console's Actions. Left out means not done. |
| `actions.createAuditMessage` | true/false | `audit_on_failure` | Create an audit message when the policy fails. |
| `actions.failCicd` | true/false | `fail_cicd` | Fail the Aqua step in CI/CD. Only on cf_application, function, image. |
| `actions.markNonCompliant` | true/false | `block_failed` | Mark failed images (hosts, resources) as non-compliant. On a function policy: Block function if non-compliant. |
| `actions.blockResources` | true/false | `policy_settings.enforce` | Block resources if policy fails (Kubernetes). Only on kubernetes. |
| `actions.displayWarningMessage` | object | | Display warning message in Linux shell (Kubernetes). Only on kubernetes. |
| `actions.displayWarningMessage.enabled` | true/false | `policy_settings.warn` | The control's switch. |
| `actions.displayWarningMessage.message` | text | `policy_settings.warning_message` |  |
| `exceptions` | object | | The console's Exceptions. Left out means nothing is ignored. |
| `exceptions.ignoreNoFix` | true/false | `control_exclude_no_fix` | Ignore vulnerabilities that have no available fix. Only on cf_application, function, host, image. |
| `exceptions.ignoreRecentlyPublished` | object | | Ignore vulnerabilities published in the last [days] days. Only on cf_application, function, host, image. |
| `exceptions.ignoreRecentlyPublished.enabled` | true/false | `ignore_recently_published_vln` | The control's switch. |
| `exceptions.ignoreRecentlyPublished.days` | number | `ignore_recently_published_vln_period` | How long the grace period is (1-999). |
| `exceptions.ignoreRecentlyPublishedRunning` | object | | The same for running workloads. In the API, not the docs; stored as written. Only on cf_application, function, host, image. |
| `exceptions.ignoreRecentlyPublishedRunning.enabled` | true/false | `ignore_recently_published_running_vln` | The control's switch. |
| `exceptions.ignoreRecentlyPublishedRunning.days` | number | `ignore_recently_published_running_vln_period` | How long the grace period is (1-999). |
| `exceptions.ignoreRecentlyFixed` | object | | Ignore vulnerabilities fixed in the last [days] days (Trivy Premium). Only on cf_application, image. |
| `exceptions.ignoreRecentlyFixed.enabled` | true/false | `ignore_recently_published_fix_vln` | The control's switch. |
| `exceptions.ignoreRecentlyFixed.days` | number | `ignore_recently_published_fix_vln_period` | How long the grace period is (1-999). |
| `exceptions.ignoreSpecificVulnerabilities` | object | | Only on cf_application, function, host, image. |
| `exceptions.ignoreSpecificVulnerabilities.enabled` | true/false | `cves_white_list_enabled` | The control's switch. |
| `exceptions.ignoreSpecificVulnerabilities.cves` | list of text | `cves_white_list` |  |
| `exceptions.ignorePaths` | object | | Ignore vulnerabilities, malware and sensitive data found in these paths (gitignore syntax). Only on cf_application, function, host, image. |
| `exceptions.ignorePaths.enabled` | true/false | `ignore_risk_resources_enabled` | The control's switch. |
| `exceptions.ignorePaths.paths` | list of text | `ignored_risk_resources` |  |
| `exceptions.ignoreBaseImage` | true/false | `ignore_base_image_vln` | Ignore vulnerabilities found in the base image. Only on cf_application, image. |
| `controls` | object | | The console's Controls. A control left out is off. Which type offers which is in ``ONLY_ON``. |
| `controls.vulnerabilitySeverity` | object | | Only on cf_application, function, host, image. |
| `controls.vulnerabilitySeverity.enabled` | true/false | `cvss_severity_enabled` | The control's switch. |
| `controls.vulnerabilitySeverity.severity` | `low` \| `medium` \| `high` \| `critical` | `cvss_severity` | Fails at this severity or higher. |
| `controls.vulnerabilitySeverity.useCustomSeverity` | true/false | `custom_severity_enabled` |  |
| `controls.vulnerabilityScore` | object | | Only on cf_application, function, host, image. |
| `controls.vulnerabilityScore.enabled` | true/false | `maximum_score_enabled` | The control's switch. |
| `controls.vulnerabilityScore.range` | list of number | `vulnerability_score_range` | ``[from, to]``: fails on vulnerabilities whose score is in the range. A threshold is ``[7, 10]``. |
| `controls.vulnerabilityScoreAndSeverity` | object | | Only on cf_application, image. |
| `controls.vulnerabilityScoreAndSeverity.enabled` | true/false | `aggregated_vulnerability.enabled` | The control's switch. |
| `controls.vulnerabilityScoreAndSeverity.range` | list of number | `aggregated_vulnerability.score_range` |  |
| `controls.vulnerabilityScoreAndSeverity.severity` | `low` \| `medium` \| `high` \| `critical` | `aggregated_vulnerability.severity` |  |
| `controls.vulnerabilityScoreAndSeverity.useCustomSeverity` | true/false | `aggregated_vulnerability.custom_severity_enabled` |  |
| `controls.vulnerabilityExploitability` | object | | Only on cf_application, function, host, image. |
| `controls.vulnerabilityExploitability.enabled` | true/false | `vulnerability_exploitability` | The control's switch. |
| `controls.vulnerabilityExploitability.exploitTypes` | list of `CISA` \| `dos` \| `local` \| `remote` \| `webapps` | `disallow_exploit_types` |  |
| `controls.vulnerabilityExploitabilityAndSeverity` | object | | Fails on a vulnerability with a known exploit of these types, at this severity or higher. Field names read from a policy saved in the console: Aqua's spec does not define them, and it stores whatever is sent. On self-hosted, ``CISA`` here needs 2022.4.818 or later. Only on image. |
| `controls.vulnerabilityExploitabilityAndSeverity.enabled` | true/false | `exploitability_and_severity.enabled` | The control's switch. |
| `controls.vulnerabilityExploitabilityAndSeverity.exploitTypes` | list of `CISA` \| `dos` \| `local` \| `remote` \| `webapps` | `exploitability_and_severity.disallow_exploit_types` |  |
| `controls.vulnerabilityExploitabilityAndSeverity.severity` | `low` \| `medium` \| `high` \| `critical` | `exploitability_and_severity.severity` |  |
| `controls.vulnerabilityExploitabilityAndSeverity.useCustomSeverity` | true/false | `exploitability_and_severity.custom_severity_enabled` |  |
| `controls.cvesBlocked` | object | | Only on cf_application, function, host, image. |
| `controls.cvesBlocked.enabled` | true/false | `cves_black_list_enabled` | The control's switch. |
| `controls.cvesBlocked.cves` | list of text | `cves_black_list` |  |
| `controls.malware` | object | | Malware. The settings are the host policy's. Only on cf_application, host, image. |
| `controls.malware.enabled` | true/false | `disallow_malware` | The control's switch. |
| `controls.malware.enableNfsShareScan` | true/false | `scan_nfs_mounts` |  |
| `controls.malware.scanWindowsRegistryHives` | true/false | `scan_windows_registry` |  |
| `controls.malware.enableInMemoryScan` | true/false | `scan_process_memory` |  |
| `controls.malware.scanArchives` | true/false | `scan_malware_in_archives` | ``scan_malware_in_archives``. In the API; no label in Aqua's docs. |
| `controls.malware.monitoredPaths` | list of text | `monitored_malware_paths` |  |
| `controls.malware.excludedPaths` | list of text | `exceptional_monitored_malware_paths` |  |
| `controls.malware.action` | text | `malware_action` | Action for Malware Files: ``alert`` or ``delete``. |
| `controls.malware.collectForensicFiles` | true/false | `file_forensic_collection` |  |
| `controls.sensitiveData` | object | | Only on cf_application, function, host, image. |
| `controls.sensitiveData.enabled` | true/false | `scan_sensitive_data` | The control's switch. |
| `controls.sensitiveData.excludedPaths` | list of text | `ignored_sensitive_resources` | Directories and file names ignored when scanning for sensitive data. |
| `controls.packagesBlocked` | object | | Only on cf_application, host, image. |
| `controls.packagesBlocked.enabled` | true/false | `packages_black_list_enabled` | The control's switch. |
| `controls.packagesBlocked.packages` | list of {name, version, versionRange} | `packages_black_list` |  |
| `controls.packagesRequired` | object | | Only on cf_application, host, image. |
| `controls.packagesRequired.enabled` | true/false | `packages_white_list_enabled` | The control's switch. |
| `controls.packagesRequired.packages` | list of {name, version, versionRange} | `packages_white_list` |  |
| `controls.ossLicensesAllowed` | object | | Only on cf_application, host, image. |
| `controls.ossLicensesAllowed.enabled` | true/false | `whitelisted_licenses_enabled` | The control's switch. |
| `controls.ossLicensesAllowed.licenses` | list of text | `whitelisted_licenses` |  |
| `controls.ossLicensesBlocked` | object | | Only on cf_application, host, image. |
| `controls.ossLicensesBlocked.enabled` | true/false | `blacklisted_licenses_enabled` | The control's switch. |
| `controls.ossLicensesBlocked.licenses` | list of text | `blacklisted_licenses` |  |
| `controls.customComplianceChecks` | object | | Only on cf_application, host, image. |
| `controls.customComplianceChecks.enabled` | true/false | `custom_checks_enabled` | The control's switch. |
| `controls.customComplianceChecks.scripts` | list of {name} | `custom_checks` |  |
| `controls.approvedBaseImage` | object | | Only on cf_application, image. |
| `controls.approvedBaseImage.enabled` | true/false | `trusted_base_images_enabled` | The control's switch. |
| `controls.approvedBaseImage.images` | list of {registry, image} | `trusted_base_images` |  |
| `controls.dynamicThreatAnalysis` | object | | Only on image. |
| `controls.dynamicThreatAnalysis.enabled` | true/false | `dta_enabled` | The control's switch. |
| `controls.dynamicThreatAnalysis.severity` | `low` \| `medium` \| `high` \| `critical` | `dta_severity` | Fails on issues of this severity or higher. |
| `controls.labelsForbidden` | object | | Only on cf_application, image. |
| `controls.labelsForbidden.enabled` | true/false | `forbidden_labels_enabled` | The control's switch. |
| `controls.labelsForbidden.labels` | list of {key, value} | `forbidden_labels` |  |
| `controls.labelsRequired` | object | | Only on cf_application, image. |
| `controls.labelsRequired.enabled` | true/false | `required_labels_enabled` | The control's switch. |
| `controls.labelsRequired.labels` | list of {key, value} | `required_labels` |  |
| `controls.microEnforcer` | true/false | `force_microenforcer` | Only on cf_application, image. |
| `controls.osPackageManager` | true/false | `partial_results_image_fail` | OS Package Manager (the API's ``partial_results_image_fail``). Only on cf_application, image. |
| `controls.superuser` | true/false | `only_none_root_users` | Only on cf_application, image. |
| `controls.cisBenchmarkForDocker` | true/false | `docker_cis_enabled` | Only on host. |
| `controls.cisBenchmarkForKubernetes` | true/false | `kube_cis_enabled` | Only on host. |
| `controls.cisBenchmarkForLinux` | true/false | `linux_cis_enabled` | Only on host. |
| `controls.cisBenchmarkForWindows` | true/false | `windows_cis_enabled` | Only on host. |
| `controls.openshiftHardening` | true/false | `openshift_hardening_enabled` | Aqua says not to use it: use cisBenchmarkForKubernetes. Only on host. |
| `controls.excessivePermissions` | true/false | `enforce_excessive_permissions` | Only on function. |
| `controls.functionIntegrity` | true/false | `function_integrity_enabled` | Only on function. |
| `controls.permissionsBlocked` | object | | Function permissions, as ``service:permission``. Only on function. |
| `controls.permissionsBlocked.enabled` | true/false | `blacklist_permissions_enabled` | The control's switch. |
| `controls.permissionsBlocked.permissions` | list of text | `blacklist_permissions` |  |
| `controls.kubernetesControls` | list of text | `kubernetes_controls_names` | The predefined and custom checks a Kubernetes policy runs, by name, as the console lists them ("Privileged", "Access to host network"). A name Aqua does not know is ignored by it, and reported by ``apply`` as not kept. Only on kubernetes. |
| `controls.autoScan` | object | | Rescan what the policy covers on a schedule. Only on cf_application, function, host, image. |
| `controls.autoScan.enabled` | true/false | `auto_scan_enabled` | The control's switch. |
| `controls.autoScan.iterationType` | text | `auto_scan_time.iteration_type` | ``once``, ``daily``, ``weekly`` or ``monthly``. |
| `controls.autoScan.iteration` | number | `auto_scan_time.iteration` |  |
| `controls.autoScan.time` | text | `auto_scan_time.time` |  |
| `controls.autoScan.weekDays` | list of text | `auto_scan_time.week_days` |  |
| `aquaName` | text | `name` | The name in Aqua, when it is not a valid `metadata.name`. Defaults to `metadata.name`. |
| `enforcement` | `Reconcile` \| `ReportOnly` | | `ReportOnly` reports drift and changes nothing. |

## Not offered

In Aqua's API, and left as Aqua has them: `apply` never changes these. Each was
checked against the API spec, the docs and a live tenant.

### RuntimePolicy

| API field | Why |
|---|---|
| `allowed_executables.allow_root_executables` | not in Aqua's console or docs' control lists, and no console-made policy uses it |
| `allowed_executables.separate_executables` | not in Aqua's console or docs' control lists, and no console-made policy uses it |
| `auditing.audit_brute_force_login` | the top-level audit_brute_force_login is the control |
| `auditing.audit_network_config` | not in Aqua's console or docs' control lists, and no console-made policy uses it |
| `auditing.audit_process_config` | not in Aqua's console or docs' control lists, and no console-made policy uses it |
| `author` | server-assigned |
| `block_container_exec` | vestigial: false even where the control is on; see container_exec |
| `created` | server-assigned |
| `cve` | vShield bookkeeping |
| `default_security_profile` | not in Aqua's console or docs' control lists, and no console-made policy uses it |
| `digest` | server-assigned |
| `domain` | server-assigned |
| `drift_prevention.image_lockdown` | not in Aqua's console or docs' control lists, and no console-made policy uses it |
| `enforce_scheduler_added_on` | server-assigned |
| `exclude_application_scopes` | The console has no way to exclude an application scope on a runtime policy, only Bypass Scope, which matches on attributes and cannot name a scope. Aqua keeps this field, but nothing shows it does anything, so apply would report success on a setting that may do nothing. What Aqua holds stays as it is: plan, apply and export name it |
| `failed_kubernetes_checks` | not in Aqua's console or docs' control lists, and no console-made policy uses it |
| `file_block.block_files_processes` | not in Aqua's console or docs' control lists, and no console-made policy uses it |
| `file_block.block_files_users` | not in Aqua's console or docs' control lists, and no console-made policy uses it |
| `file_block.exceptional_block_files` | not in Aqua's console or docs' control lists, and no console-made policy uses it |
| `file_block.exceptional_block_files_processes` | not in Aqua's console or docs' control lists, and no console-made policy uses it |
| `file_block.exceptional_block_files_users` | not in Aqua's console or docs' control lists, and no console-made policy uses it |
| `file_integrity_monitoring.monitored_files_attributes` | Aqua accepts it on create, then drops or refuses it on update (write-tested) |
| `file_integrity_monitoring.monitored_files_read` | Aqua accepts it on create, then drops or refuses it on update (write-tested) |
| `id` | server-assigned |
| `image_name` | vShield bookkeeping |
| `is_audit_checked` | not in Aqua's console or docs' control lists, and no console-made policy uses it |
| `is_auto_generated` | server-assigned |
| `is_ootb_policy` | server-assigned |
| `lastupdate` | server-assigned |
| `malware_scan_options.include_directories` | Aqua sets its own list and restores it on every save |
| `name` | the name is the file's |
| `package_block.block_packages_processes` | not in Aqua's console or docs' control lists, and no console-made policy uses it |
| `package_block.block_packages_users` | not in Aqua's console or docs' control lists, and no console-made policy uses it |
| `package_block.exceptional_block_packages_files` | not in Aqua's console or docs' control lists, and no console-made policy uses it |
| `package_block.exceptional_block_packages_processes` | not in Aqua's console or docs' control lists, and no console-made policy uses it |
| `package_block.exceptional_block_packages_users` | not in Aqua's console or docs' control lists, and no console-made policy uses it |
| `permission` | server-assigned |
| `readonly` | server-assigned |
| `readonly_files` | Read-Only Directories and Files: deprecated by Aqua, absent from the console, and refused when on for a container policy |
| `registry` | not in Aqua's console or docs' control lists, and no console-made policy uses it |
| `registry_access_monitoring.monitored_registry_read` | not in Aqua's console or docs' control lists, and no console-made policy uses it |
| `repo_name` | vShield bookkeeping |
| `resource_name` | vShield bookkeeping |
| `resource_type` | vShield bookkeeping |
| `runtime_mode` | server-assigned |
| `tripwire` | Honeypot (functions): does nothing without an AWS secret key, and the tool never manages credentials. Set it in the console |
| `type` | server-assigned |
| `updated` | server-assigned |
| `version` | server-assigned |
| `virtual_patch_audit_info` | vShield bookkeeping |
| `vpatch_version` | vShield bookkeeping |

### AssurancePolicy

| API field | Why |
|---|---|
| `FFMap` | server-assigned |
| `allowed_images` | Images Allowed: as images |
| `author` | server-assigned |
| `auto_scan_configured` | server-assigned |
| `category` | in the spec; Aqua does not return it |
| `custom_severity` | Aqua stores "" whatever is sent; use custom_severity_enabled |
| `cvss_severity_exclude_no_fix` | Aqua stores false whatever is sent; use control_exclude_no_fix |
| `disallow_resource_categories` | in the spec; Aqua does not return it |
| `domain` | in the spec; Aqua does not return it |
| `domain_name` | in the spec; Aqua does not return it |
| `enabled` | in the spec; Aqua does not return it |
| `exclude_application_scopes` | The versions tested (SaaS U14, console 10.8.1) drop it, so it could not be tested. It can come back once it can be, on SaaS U15 or 10.9.0: see Tested against. What Aqua holds stays as it is: plan, apply and export name it |
| `id` | server-assigned |
| `images` | Images Blocked: the console only lists decisions made on images in the inventory, and offers removing them. They are not in the policy: the API returns [] even with entries, stores [] whatever is sent, and an update leaves the entries alone (write-tested) |
| `kubernetes_controls` | what kubernetesControls is stored as; the client adapter keeps the three fields in step |
| `kubernetes_controls_avd_ids` | see kubernetes_controls |
| `labels` | Aqua stores [] whatever is sent |
| `lastupdate` | server-assigned |
| `maximum_score` | Aqua sets it from vulnerability_score_range, whatever is sent (write-tested) |
| `maximum_score_exclude_no_fix` | Aqua stores false whatever is sent; use control_exclude_no_fix |
| `name` | the name is the file's |
| `packages_black_list[]: format, epoch, release, arch, license` | Aqua stores "" whatever is sent (write-tested) |
| `packages_white_list[]: format, epoch, release, arch, license` | as packages_black_list |
| `permission` | server-assigned; Aqua stores "Write" whatever is sent |
| `policy_settings.is_audit_checked` | no label in Aqua's docs; audit_on_failure is the action on every shipped policy |
| `read_only` | Aqua refuses it for an API user (HTTP 403) |
| `registries` | Aqua stores [] whatever is sent |
| `resource_categories_enabled` | in the spec; Aqua does not return it |
| `scap_enabled` | see scap_files |
| `scap_files` | SCAP: the console offers it as a scanning setting, not a control of the policy |

## Tested against

`tests/integration/test_every_field.py` puts every control and setting through create, a re-save,
export, removal and update, on a live tenant, for each type that offers it. It also changes
`enabled`, the description, the scopes and the additional scope criteria, and refuses a change of type.

| Aqua | Signing in with | Result |
|---|---|---|
| SaaS U14 | user name and password | All of it, except writing `bypassScope`. All 61 policies export and plan only the marker. |
| Self-hosted, console 10.8.1 (its exports say version 2022.4) | user name and password, at `/api/v1/login` | All of it. All 32 policies export and plan only the marker. Aqua's default policies were adopted, edited and released, leaving them as they were. |

**Not tested live:** API key sign-in, an older self-hosted version, a CA bundle against a real console
(unit tests and a local HTTPS check cover it), and changing the scopes of a `cf_application` policy.

**`bypassScope`** is offered on the default container and host runtime policies. Only the self-hosted
test writes it, with `AQUASEC_CASC_LIVE_DEFAULTS=1`, since it edits Aqua's default policies and the
SaaS tenant is shared. On SaaS the round trip covers reading it, and nothing covers writing it.

**`excludeApplicationScopes`** is [not offered](#not-offered). On assurance policies, neither version
tested has it: both drop it. Aqua expects to ship it in SaaS U15 and in self-hosted 2022.4 U48 / 10.9.0.
That is Aqua's statement, not something seen here, and whether it must also be switched on is not
known. It can come back once it can be tested on one of those. That an update keeps what Aqua holds
was tested live on runtime policies, and by unit tests on assurance policies, which cannot hold it here.

**These tests show what Aqua stores, not that it acts on it.** Aqua keeps some fields it does not use,
so read-back cannot show that a version enforces a control. For one,
`vulnerabilityExploitabilityAndSeverity`'s `CISA` type needs build 2022.4.818 or later on self-hosted 2022.4.
