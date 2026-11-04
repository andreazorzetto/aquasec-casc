"""A sample value for every field the tool offers, with where the console offers it.

Used by the live test (``test_every_field.py``) and checked for completeness
without a tenant (``tests/unit/test_coverage.py``): a field added to a field map
and not given a sample here fails the build, so nothing goes untested.

Each sample is one console control and all its settings together, because that
is how it is stored: Aqua refuses some settings alone (a host malware action
needs its paths).
"""

from __future__ import annotations

CONTAINER, HOST, FUNCTION = "container", "host", "function"
IMAGE, KUBERNETES, TANZU = "image", "kubernetes", "cf_application"

ENTITIES = {"paths": ["/etc/casc-test/*"], "processes": ["/bin/casc-test"], "users": ["casc-test"]}
PACKAGE = [{"name": "casc-no-such", "version": "1.0", "versionRange": "Less Than"}]
LABEL = [{"key": "casc-test", "value": "x"}]
SCOPE = {"expression": "v1", "variables": [{"attribute": "image.name", "value": "casc-no-such-*"}]}

# path under spec -> (value, the types that offer it)
RUNTIME: dict[str, tuple[object, tuple[str, ...]]] = {
    "enforce": (True, (CONTAINER, HOST, FUNCTION)),
    "enforceAfterDays": (30, (CONTAINER, HOST)),
    "additionalScopeCriteria": (SCOPE, (CONTAINER, HOST, FUNCTION)),
    "controls.blockNonCompliantImages": (True, (CONTAINER,)),
    "controls.blockNonCompliantResources": (True, (CONTAINER,)),
    "controls.blockUnregisteredImages": (True, (CONTAINER,)),
    "controls.blockNonKubernetesContainers": (True, (CONTAINER,)),
    "controls.blockOutdatedImages": ({"olderThan": 6, "unit": "months"}, (CONTAINER,)),
    "controls.registriesAllowed": ({"registries": ["Docker Hub"]}, (CONTAINER,)),
    "controls.blockContainerExec": ({"allowedProcesses": ["/bin/casc-test"]}, (CONTAINER,)),
    "controls.blockReverseShell": ({"allowedProcesses": ["casc-test"], "whitelistedIps": ["10.0.0.0/8"]},
                                   (CONTAINER, HOST)),
    "controls.blockFilelessExec": ({"allowedProcesses": ["casc-test*"]}, (CONTAINER, HOST)),
    "controls.driftPrevention": ({"includeScriptFiles": True, "allowedProcesses": ["casc-*"],
                                  "applyToChildProcesses": True}, (CONTAINER, FUNCTION)),
    "controls.executablesAllowed": ({"executables": ["casc-test"]}, (CONTAINER,)),
    "controls.executablesBlocked": ({"executables": ["casc-test"]}, (CONTAINER, HOST, FUNCTION)),
    "controls.limitNewPrivileges": (True, (CONTAINER,)),
    "controls.limitContainerPrivileges": ({
        "privileged": True, "hostNetwork": True, "hostPid": True, "hostIpc": True, "hostUts": True,
        "hostUserNamespace": True, "rootUser": True, "lowPortBinding": True,
        "addCapabilities": True, "ownerUserContext": True}, (CONTAINER,)),
    "controls.capabilitiesBlock": ({"dropCapabilities": ["NET_RAW", "SYS_ADMIN"]}, (CONTAINER,)),
    "controls.forkGuard": ({"processLimit": 100}, (HOST,)),
    "controls.blockCryptocurrencyMining": (True, (CONTAINER, HOST)),
    "controls.dnsIpReputation": (True, (CONTAINER, HOST)),
    "controls.portScanningDetection": (True, (CONTAINER, HOST)),
    "controls.portBlock": ({"blockedInboundPorts": ["2222"], "blockedOutboundPorts": ["2223"]},
                           (CONTAINER, HOST)),
    "controls.bruteForceLoginDetection": (True, (HOST,)),
    "controls.fileBlock": ({"files": ["/etc/casc-test"]}, (CONTAINER, HOST)),
    "controls.packageBlock": ({"packages": ["casc-test"]}, (CONTAINER, HOST)),
    "controls.volumesBlocked": ({"volumes": ["/casc-test"]}, (CONTAINER,)),
    "controls.fileIntegrityMonitoring": ({"create": True, "modify": True, "delete": True,
                                          "monitor": ENTITIES, "exclude": ENTITIES}, (CONTAINER, HOST)),
    "controls.realTimeMalwareProtection": ({
        "action": "alert", "excludedPaths": ["/casc-test/*"], "excludedProcesses": ["casc-test"],
        "collectForensicFiles": True, "collectSelectiveMemoryDumps": True}, (CONTAINER, HOST)),
    "controls.forensics": ({
        "allProcesses": True, "fullCommandArguments": True, "allNetwork": True, "osUserActivity": True,
        "successfulLogins": True, "failedLogins": True, "userAccountManagement": True}, (CONTAINER, HOST)),
    "controls.systemIntegrityMonitoring": ({"systemTime": True, "windowsServicesMonitoring": True,
                                            "monitorSystemLogIntegrity": True}, (CONTAINER, HOST)),
    "controls.osUsersAndGroupsAllowed": ({"usersAllowed": ["casc-test"], "groupsAllowed": ["casc-test"]},
                                         (HOST,)),
    "controls.osUsersAndGroupsBlocked": ({"usersBlocked": ["casc-test"], "groupsBlocked": ["casc-test"]},
                                         (HOST,)),
    "controls.windowsRegistryMonitoring": ({"create": True, "modify": True, "delete": True,
                                            "attributes": True, "monitor": ENTITIES, "exclude": ENTITIES},
                                           (HOST,)),
    "controls.windowsRegistryProtection": ({"protect": ENTITIES, "exclude": ENTITIES}, (HOST,)),
    "controls.secureAiDiscovery": ({"ignoreList": ["OpenAI@gpt-4o-mini"]}, (CONTAINER, HOST)),
    "controls.secureAiUnauthorizedModels": ({"models": ["DeepSeek@*"]}, (CONTAINER, HOST)),
    "controls.secureAiProtection": (True, (CONTAINER, HOST)),
}

#: Fields offered and tested another way. Bypass Scope exists only on Aqua's two
#: default policies, so a throwaway policy cannot hold it.
RUNTIME_ELSEWHERE = {"spec.controls.bypassScope", "spec.description", "spec.enabled", "spec.runtimeType",
                     "spec.applicationScopes", "spec.excludeApplicationScopes"}

_ALL = (IMAGE, HOST, FUNCTION, TANZU)

ASSURANCE: dict[str, tuple[object, tuple[str, ...]]] = {
    "actions.createAuditMessage": (True, (*_ALL, KUBERNETES)),
    "actions.failCicd": (True, (IMAGE, FUNCTION, TANZU)),
    "actions.markNonCompliant": (True, (*_ALL, KUBERNETES)),
    "actions.blockResources": (True, (KUBERNETES,)),
    "actions.displayWarningMessage": ({"message": "casc test"}, (KUBERNETES,)),
    "exceptions.ignoreNoFix": (True, _ALL),
    "exceptions.ignoreRecentlyPublished": ({"days": 45}, _ALL),
    "exceptions.ignoreRecentlyPublishedRunning": ({"days": 45}, _ALL),
    "exceptions.ignoreRecentlyFixed": ({"days": 45}, (IMAGE, TANZU)),
    "exceptions.ignoreSpecificVulnerabilities": ({"cves": ["CVE-2021-44228"]}, _ALL),
    "exceptions.ignorePaths": ({"paths": ["/casc-test/"]}, _ALL),
    "exceptions.ignoreBaseImage": (True, (IMAGE, TANZU)),
    "controls.vulnerabilitySeverity": ({"severity": "high", "useCustomSeverity": True}, _ALL),
    "controls.vulnerabilityScore": ({"range": [5.0, 9.0]}, _ALL),
    "controls.vulnerabilityScoreAndSeverity": ({"range": [5.0, 9.0], "severity": "high",
                                                "useCustomSeverity": True}, (IMAGE, TANZU)),
    "controls.vulnerabilityExploitability": ({"exploitTypes": ["remote", "dos"]}, _ALL),
    "controls.cvesBlocked": ({"cves": ["CVE-2021-44228"]}, _ALL),
    "controls.malware": ({"scanNfsMounts": True, "scanWindowsRegistry": True, "inMemoryScan": True,
                          "scanArchives": True, "monitoredPaths": ["/casc-test/"],
                          "excludedPaths": ["/casc-test/x/"], "action": "alert",
                          "collectForensicFiles": True}, (HOST,)),
    "controls.malware#image": (True, (IMAGE, TANZU)),
    "controls.sensitiveData": ({"excludedPaths": ["/casc-test/"]}, (IMAGE, HOST, FUNCTION, TANZU)),
    "controls.packagesBlocked": ({"packages": PACKAGE}, (IMAGE, HOST, TANZU)),
    "controls.packagesRequired": ({"packages": PACKAGE}, (IMAGE, HOST, TANZU)),
    "controls.ossLicensesAllowed": ({"licenses": ["MIT"]}, (IMAGE, HOST, TANZU)),
    "controls.ossLicensesBlocked": ({"licenses": ["MIT"]}, (IMAGE, HOST, TANZU)),
    "controls.dynamicThreatAnalysis": ({"severity": "high"}, (IMAGE, TANZU)),
    "controls.labelsForbidden": ({"labels": LABEL}, (IMAGE, TANZU)),
    "controls.labelsRequired": ({"labels": LABEL}, (IMAGE, TANZU)),
    "controls.microEnforcer": (True, (IMAGE, TANZU)),
    "controls.osPackageManager": (True, (IMAGE, TANZU)),
    "controls.superuser": (True, (IMAGE, TANZU)),
    "controls.cisBenchmarkDocker": (True, (HOST,)),
    "controls.cisBenchmarkKubernetes": (True, (HOST,)),
    "controls.cisBenchmarkLinux": (True, (HOST,)),
    "controls.cisBenchmarkWindows": (True, (HOST,)),
    "controls.openshiftHardening": (True, (HOST,)),
    "controls.excessivePermissions": (True, (FUNCTION,)),
    "controls.functionIntegrity": (True, (FUNCTION,)),
    "controls.permissionsBlocked": ({"permissions": ["s3:GetObject"]}, (FUNCTION,)),
    "controls.kubernetesControls": (["Privileged", "Access to host network"], (KUBERNETES,)),
    "controls.autoScan": ({"iterationType": "daily", "iteration": 1, "time": "2030-01-01T00:00:00Z",
                           "weekDays": []}, (IMAGE, HOST, FUNCTION)),
}

#: Needs something registered on the tenant: built at run time by the live test.
ASSURANCE_AT_RUN_TIME = {"spec.controls.approvedBaseImage"}

ASSURANCE_ELSEWHERE = {"spec.assuranceType", "spec.description", "spec.applicationScopes",
                       "spec.excludeApplicationScopes", "spec.additionalScopeCriteria"}
