"""The RuntimePolicy kind -- the MVP centrepiece.

Canonical names are the console's labels in camelCase, translated to Aqua's
API names by ``FIELD_MAP``: the YAML reads like the console, and does not churn
when Aqua renames an API field or nests a control differently. API paths were
first mined from terraform-provider-aquasec v0.15.1 (commit 49182c7) and
verified against a live tenant.
"""

from __future__ import annotations

from enum import Enum
from typing import ClassVar

from pydantic import Field, field_validator, model_validator

from .base import API_VERSION, ManagedSpec, Metadata, Resource, StrictModel
from .fieldmap import FieldMap, FieldMapping
from .sections import (SCOPE_VARIABLE, AdditionalScopeCriteria, Heading, ScopeVariable, Section,
                       control as _control)

KIND = "RuntimePolicy"


class RuntimeType(str, Enum):
    """Which workload family the policy applies to.

    Aqua models container, host and function runtime policies as one object
    distinguished by this field, rather than as three endpoints.
    """

    CONTAINER = "container"
    HOST = "host"
    FUNCTION = "function"


def _renamed(new: str) -> str:
    return f"renamed: now {new!r}"


_NOT_IN_CONSOLE = ("no longer offered: it is not in Aqua's console. Remove it; "
                   "Aqua keeps the value the tenant has")


class AllowedProcesses(Section):
    """A blocking control with its Allowed Processes: Block Container Exec,
    Block Fileless Exec."""

    allowedProcesses: list[str] | None = None


class BlockReverseShell(AllowedProcesses):
    whitelistedIps: list[str] | None = None
    """Whitelisted IPs / CIDRs."""


class DriftPrevention(AllowedProcesses):
    """Drift Prevention: executables not in the original image do not run. On a
    function policy the console calls this Block Malicious Executables.

    The console's switch writes two API fields, ``enabled`` and
    ``exec_lockdown``; they are equal on every console-made policy. The API's
    ``image_lockdown`` is not in the console and not offered.
    """

    renamed: ClassVar[dict[str, str]] = {
        "exceptions": _renamed("allowedProcesses"),
        "execLockdownScripts": _renamed("includeScriptFiles"),
        "inheritToChild": _renamed("applyToChildProcesses"),
        "execLockdown": "not needed: switching driftPrevention on writes it, as the console does",
        "imageLockdown": _NOT_IN_CONSOLE,
    }

    includeScriptFiles: bool | None = None
    applyToChildProcesses: bool | None = None
    """Extend the Allowed Processes exemption to their child processes."""


class ForkGuard(Section):
    """Fork Guard (hosts; deprecated by Aqua). Aqua refuses it on a container policy."""

    processLimit: int | None = None


class LimitContainerPrivileges(Section):
    """Limit Container Privileges: each setting true prevents that privilege.
    The console's labels are sentences, so these are short forms."""

    privileged: bool | None = None
    """Privileged containers."""
    hostNetwork: bool | None = None
    """Access to host network."""
    hostPid: bool | None = None
    """Use the host PID namespace."""
    hostIpc: bool | None = None
    """Use the host IPC namespace."""
    hostUts: bool | None = None
    """Use the host UTS namespace."""
    hostUserNamespace: bool | None = None
    """Use the host user namespace."""
    rootUser: bool | None = None
    """Configured with 'root' user."""
    lowPortBinding: bool | None = None
    """Port binding lower than 1024. The only privilege that also applies to Windows."""
    addCapabilities: bool | None = None
    """Adding capabilities with --cap-add."""
    ownerUserContext: bool | None = None
    """Run in owner's user context (requires restart). In Aqua's docs; not shown
    by every console version."""


class CapabilitiesBlock(Section):
    """Capabilities Block: Linux capabilities containers may not use, named as
    in the console's list (``NET_RAW``, ``SYS_ADMIN``; ``ALL``). The console
    offers it only in enforce mode; the API accepts it in audit mode too (seen
    live), so the tool stores what the file says, as for Secure AI."""

    renamed: ClassVar[dict[str, str]] = {"capabilities": _renamed("dropCapabilities")}

    dropCapabilities: list[str] | None = None


class ExecutablesBlocked(Section):
    """Executables Blocked; Executables Blacklist on a function policy."""

    executables: list[str] | None = None


class ExecutablesAllowed(Section):
    """Executables Allowed: everything else is prevented from running."""

    renamed: ClassVar[dict[str, str]] = {
        "rootExecutables": _NOT_IN_CONSOLE, "separateRootExecutables": _NOT_IN_CONSOLE}

    executables: list[str] | None = None


class RegistriesAllowed(Section):
    """Registries Allowed: images may only come from these."""

    registries: list[str] | None = None


class VolumesBlocked(Section):
    """Volumes Blocked: host paths containers may not mount."""

    volumes: list[str] | None = None


class TimeUnit(str, Enum):
    DAYS = "days"
    WEEKS = "weeks"
    MONTHS = "months"
    YEARS = "years"


class BlockOutdatedImages(Section):
    """Block Outdated Images: images older than the threshold do not run."""

    renamed: ClassVar[dict[str, str]] = {"olderThan": _renamed("ageThreshold")}

    needs = ("ageThreshold", "unit")

    ageThreshold: int | None = None
    """Age Threshold: how old, in ``unit``."""
    unit: TimeUnit | None = None


class PortBlock(Section):
    renamed: ClassVar[dict[str, str]] = {
        "inbound": _renamed("blockedInboundPorts"), "outbound": _renamed("blockedOutboundPorts")}

    blockedInboundPorts: list[str] | None = None
    blockedOutboundPorts: list[str] | None = None


class FileBlock(Section):
    """File Block: no reading, writing or executing these files."""

    renamed: ClassVar[dict[str, str]] = dict.fromkeys(
        ("exceptions", "users", "exceptionUsers", "processes", "exceptionProcesses"),
        _NOT_IN_CONSOLE)

    files: list[str] | None = None


class PackageBlock(Section):
    """Package Block: no reading, writing or executing files of these packages."""

    renamed: ClassVar[dict[str, str]] = dict.fromkeys(
        ("exceptionFiles", "users", "exceptionUsers", "processes", "exceptionProcesses"),
        _NOT_IN_CONSOLE)

    packages: list[str] | None = None


class Entities(StrictModel):
    """One tab of a monitoring control: the paths, processes and users it covers."""

    paths: list[str] | None = None
    processes: list[str] | None = None
    users: list[str] | None = None


class FileIntegrityMonitoring(Section):
    """File Integrity Monitoring: audit events for the operations selected,
    never blocks. ``monitor`` and ``exclude`` are the console's Monitor and
    Exclude tabs; its presets are stored as the paths they expand to.

    The API also has read and attributes switches. Write-tested live: Aqua
    accepts them on create, then drops read and refuses attributes on every
    later update -- and the console does not show them -- so they are not
    offered here.
    """

    renamed: ClassVar[dict[str, str]] = {
        "paths": _renamed("monitor.paths"), "processes": _renamed("monitor.processes"),
        "users": _renamed("monitor.users"), "exceptions": _renamed("exclude.paths"),
        "exceptionProcesses": _renamed("exclude.processes"),
        "exceptionUsers": _renamed("exclude.users"),
        "monitorCreate": _renamed("create"), "monitorModify": _renamed("modify"),
        "monitorDelete": _renamed("delete")}

    create: bool | None = None
    modify: bool | None = None
    delete: bool | None = None
    monitor: Entities | None = None
    exclude: Entities | None = None


class WindowsRegistryMonitoring(Section):
    """Windows Registry Monitoring (hosts): audits registry operations."""

    renamed: ClassVar[dict[str, str]] = {
        **FileIntegrityMonitoring.renamed,
        "monitorAttributes": _renamed("attributes"), "monitorRead": _NOT_IN_CONSOLE}

    create: bool | None = None
    modify: bool | None = None
    delete: bool | None = None
    attributes: bool | None = None
    monitor: Entities | None = None
    exclude: Entities | None = None


class WindowsRegistryProtection(Section):
    """Windows Registry Protection (hosts): blocks changes to the registry."""

    renamed: ClassVar[dict[str, str]] = {
        "paths": _renamed("protect.paths"), "processes": _renamed("protect.processes"),
        "users": _renamed("protect.users"), "exceptions": _renamed("exclude.paths"),
        "exceptionProcesses": _renamed("exclude.processes"),
        "exceptionUsers": _renamed("exclude.users")}

    protect: Entities | None = None
    exclude: Entities | None = None


class OsUsersAndGroupsAllowed(Section):
    renamed: ClassVar[dict[str, str]] = {
        "users": _renamed("usersAllowed"), "groups": _renamed("groupsAllowed")}

    usersAllowed: list[str] | None = None
    groupsAllowed: list[str] | None = None


class OsUsersAndGroupsBlocked(Section):
    renamed: ClassVar[dict[str, str]] = {
        "users": _renamed("usersBlocked"), "groups": _renamed("groupsBlocked")}

    usersBlocked: list[str] | None = None
    groupsBlocked: list[str] | None = None


class MalwareAction(str, Enum):
    ALERT = "alert"
    BLOCK = "block"
    DELETE = "delete"


class RealTimeMalwareProtection(Section):
    """Real-time Malware Protection (needs the Advanced Malware Protection
    licence).

    The scanned directories are not configurable, as in the console: Aqua
    sets them itself and restores its own list on every save (write-tested).
    Only exclusions are yours. In audit mode, ``alert`` is the only action the
    console offers.
    """

    renamed: ClassVar[dict[str, str]] = {
        "excludeDirectories": _renamed("excludedPaths"),
        "excludeProcesses": _renamed("excludedProcesses"),
        "fileForensicCollection": _renamed("collectForensicFiles"),
        "memoryDumpCollection": _renamed("collectSelectiveMemoryDumps")}

    action: MalwareAction | None = None
    """Action for Malware Files."""
    excludedPaths: list[str] | None = None
    excludedProcesses: list[str] | None = None
    collectForensicFiles: bool | None = None
    collectSelectiveMemoryDumps: bool | None = None


class Forensics(Section):
    """Forensics: what goes into the audit log. The console's labels are
    sentences ("Audit all process activity of the container"), so these are
    short forms."""

    renamed: ClassVar[dict[str, str]] = {"processCommandLine": _renamed("fullCommandArguments")}

    allProcesses: bool | None = None
    fullCommandArguments: bool | None = None
    allNetwork: bool | None = None
    osUserActivity: bool | None = None
    successfulLogins: bool | None = None
    failedLogins: bool | None = None
    userAccountManagement: bool | None = None


class SystemIntegrityMonitoring(Section):
    """System Integrity Monitoring (hosts): audits, never blocks."""

    renamed: ClassVar[dict[str, str]] = {
        "systemTimeChanges": _renamed("systemTime"),
        "windowsServices": _renamed("windowsServicesMonitoring"),
        "auditLogIntegrity": _renamed("monitorSystemLogIntegrity")}

    systemTime: bool | None = None
    windowsServicesMonitoring: bool | None = None
    monitorSystemLogIntegrity: bool | None = None


def _ai_models(entries: list[str] | None) -> list[str] | None:
    """Entries are ``Service@model``: the service as the console lists it, then
    the model name or ``*`` for every model of that service. Aqua refuses any
    other shape (HTTP 400, write-tested); the service names themselves are left
    to Aqua, whose list grows from release to release."""
    for entry in entries or ():
        service, at, model = entry.partition("@")
        if not (service.strip() and at and model.strip()):
            raise ValueError(
                f"{entry!r} is not Service@model -- e.g. OpenAI@gpt-4o, or OpenAI@* "
                "for every model of a service")
    return entries


class SecureAiDiscovery(Section):
    """Secure AI - Discovery: reports AI services and models in use.

    Audit only, Linux only. The console switches the Secure AI controls off when
    a policy is in enforce mode; the API keeps them as written (write-tested), so
    this tool stores what the file says in either mode.
    """

    renamed: ClassVar[dict[str, str]] = {"ignore": _renamed("ignoreList")}

    ignoreList: list[str] | None = None
    """Models and services left out of discovery."""

    @field_validator("ignoreList")
    @classmethod
    def _service_at_model(cls, value):
        return _ai_models(value)


class SecureAiUnauthorizedModels(Section):
    """Secure AI - Unauthorized Models: flags the listed models as unauthorized
    (medium severity). Audit only, Linux only; same enforce-mode note as
    Discovery."""

    models: list[str] | None = None
    """Models and services flagged as unauthorized."""

    @field_validator("models")
    @classmethod
    def _service_at_model(cls, value):
        return _ai_models(value)


class BypassScope(Section):
    """Workloads exempt from this policy.

    Only the default container and host runtime policies have it -- the same as
    in the console. The default container policy ships with it on, exempting
    Aqua's own components, ``kube-system`` and pod sandboxes.
    """

    expression: str = ""
    """How the variables combine, e.g. ``v1 || v2 || v3``."""

    variables: list[ScopeVariable] = Field(default_factory=list)


class Controls(Heading):
    """The security controls a runtime policy turns on or off, named as in the
    console's control list. A control left out is off.

    Not offered, because the console does not show them (and no console-made
    policy on the lab uses them): Read-Only Files, failed Kubernetes checks,
    drift prevention's image lockdown, root executables, and
    File and Package Block's users, processes and exceptions. Nor: Honeypot
    (``tripwire``: serverless; carries an AWS secret key, and the tool never
    manages credential fields) and the auditing ``*_config`` objects. All of
    these are left as Aqua has them.
    """

    # Names from earlier versions of the schema, for "unknown field" hints.
    renamed: ClassVar[dict[str, str]] = {
        "onlyRegisteredImages": _renamed("blockUnregisteredImages"),
        "blockNonCompliantWorkloads": _renamed("blockNonCompliantResources"),
        "blockNonK8sContainers": _renamed("blockNonKubernetesContainers"),
        "enableIpReputation": _renamed("dnsIpReputation"),
        "enablePortScanProtection": _renamed("portScanningDetection"),
        "noNewPrivileges": _renamed("limitNewPrivileges"),
        "malwareProtection": _renamed("realTimeMalwareProtection"),
        "auditBruteForceLogin": _renamed("bruteForceLoginDetection"),
        "allowedOsUsers": _renamed("osUsersAndGroupsAllowed"),
        "blockedOsUsers": _renamed("osUsersAndGroupsBlocked"),
        "registryAccessMonitoring": _renamed("windowsRegistryMonitoring"),
        "readonlyRegistry": _renamed("windowsRegistryProtection"),
        "enableForkGuard": _renamed("forkGuard"),
        "forkGuardProcessLimit": _renamed("forkGuard.processLimit"),
        "containerExecAllowedProcesses": _renamed("blockContainerExec.allowedProcesses"),
        "reverseShellAllowedProcesses": _renamed("blockReverseShell.allowedProcesses"),
        "reverseShellAllowedIps": _renamed("blockReverseShell.whitelistedIps"),
        "filelessExecAllowedProcesses": _renamed("blockFilelessExec.allowedProcesses"),
        "readonlyFiles": _NOT_IN_CONSOLE,
        "failedKubernetesChecks": _NOT_IN_CONSOLE,
    }

    # --- images and workloads ------------------------------------------------
    blockNonCompliantImages: bool | None = None
    """Block images an assurance policy has marked non-compliant.

    Worth understanding before relying on audit mode: the enforcer evaluates
    compliance by image *hash*, so a non-compliant verdict from one policy blocks
    that hash everywhere the enforcer sees it -- including scopes meant to be in
    audit mode. Leaving this control out of a dev/test policy entirely is the
    recommended fix, rather than relying on audit mode to soften it.

    The API field is ``block_disallowed_images`` -- see FIELD_MAP.
    """

    blockNonCompliantResources: bool | None = None
    """Block non-compliant Kubernetes resources (KubeEnforcer)."""
    blockUnregisteredImages: bool | None = None
    blockNonKubernetesContainers: bool | None = None
    blockOutdatedImages: BlockOutdatedImages | None = None
    registriesAllowed: RegistriesAllowed | None = None

    # --- processes -------------------------------------------------------------
    blockContainerExec: AllowedProcesses | None = None
    blockReverseShell: BlockReverseShell | None = None
    blockFilelessExec: AllowedProcesses | None = None
    driftPrevention: DriftPrevention | None = None
    executablesAllowed: ExecutablesAllowed | None = None
    executablesBlocked: ExecutablesBlocked | None = None
    limitNewPrivileges: bool | None = None
    limitContainerPrivileges: LimitContainerPrivileges | None = None
    capabilitiesBlock: CapabilitiesBlock | None = None
    forkGuard: ForkGuard | None = None

    # --- network and behaviour -------------------------------------------------
    blockCryptocurrencyMining: bool | None = None
    dnsIpReputation: bool | None = None
    portScanningDetection: bool | None = None
    portBlock: PortBlock | None = None
    bruteForceLoginDetection: bool | None = None
    """Hosts."""

    # --- files, packages, volumes ------------------------------------------------
    fileBlock: FileBlock | None = None
    packageBlock: PackageBlock | None = None
    volumesBlocked: VolumesBlocked | None = None
    fileIntegrityMonitoring: FileIntegrityMonitoring | None = None
    realTimeMalwareProtection: RealTimeMalwareProtection | None = None

    # --- audit -------------------------------------------------------------------
    forensics: Forensics | None = None
    systemIntegrityMonitoring: SystemIntegrityMonitoring | None = None

    # --- hosts ---------------------------------------------------------------------
    osUsersAndGroupsAllowed: OsUsersAndGroupsAllowed | None = None
    osUsersAndGroupsBlocked: OsUsersAndGroupsBlocked | None = None
    windowsRegistryMonitoring: WindowsRegistryMonitoring | None = None
    windowsRegistryProtection: WindowsRegistryProtection | None = None

    # --- Secure AI -------------------------------------------------------------------
    secureAiDiscovery: SecureAiDiscovery | None = None
    secureAiUnauthorizedModels: SecureAiUnauthorizedModels | None = None
    secureAiProtection: bool | None = None
    """Secure AI - Protection. Needs the Prompt Protection toggle on the
    Integrations > Secure AI screen. Aqua's docs describe excluding services
    here; the API has only the switch."""

    # --- default policies only ---------------------------------------------------
    bypassScope: BypassScope | None = None
    """Only on "Aqua default runtime policy" and "Aqua default host runtime
    policy"; anywhere else it is reported as not allowed and not sent."""


_SERVER_ASSIGNED = "server-assigned"
_NOT_CONSOLE = "not in Aqua's console or docs' control lists, and no console-made policy uses it"
_DROPPED = "Aqua accepts it on create, then drops or refuses it on update (write-tested)"

#: In the API, and left as Aqua has them. Checked against Aqua's API spec by
#: tests/unit/test_coverage.py: a new field has to land here or in the map.
NOT_OFFERED: dict[str, str] = {
    "id": _SERVER_ASSIGNED, "name": "the name is the file's", "author": _SERVER_ASSIGNED,
    "created": _SERVER_ASSIGNED, "updated": _SERVER_ASSIGNED, "lastupdate": _SERVER_ASSIGNED,
    "version": _SERVER_ASSIGNED, "type": _SERVER_ASSIGNED, "permission": _SERVER_ASSIGNED,
    "domain": _SERVER_ASSIGNED, "digest": _SERVER_ASSIGNED, "is_ootb_policy": _SERVER_ASSIGNED,
    "is_auto_generated": _SERVER_ASSIGNED, "runtime_mode": _SERVER_ASSIGNED,
    "enforce_scheduler_added_on": _SERVER_ASSIGNED, "readonly": _SERVER_ASSIGNED,
    "cve": "vShield bookkeeping", "image_name": "vShield bookkeeping", "repo_name": "vShield bookkeeping",
    "resource_name": "vShield bookkeeping", "resource_type": "vShield bookkeeping",
    "vpatch_version": "vShield bookkeeping", "virtual_patch_audit_info": "vShield bookkeeping",
    "registry": _NOT_CONSOLE, "is_audit_checked": _NOT_CONSOLE, "default_security_profile": _NOT_CONSOLE,
    "block_container_exec": "vestigial: false even where the control is on; see container_exec",
    "allowed_executables.allow_root_executables": _NOT_CONSOLE,
    "allowed_executables.separate_executables": _NOT_CONSOLE,
    "auditing.audit_brute_force_login": "the top-level audit_brute_force_login is the control",
    "auditing.audit_network_config": _NOT_CONSOLE, "auditing.audit_process_config": _NOT_CONSOLE,
    "drift_prevention.image_lockdown": _NOT_CONSOLE,
    "failed_kubernetes_checks": _NOT_CONSOLE,
    "file_block.block_files_processes": _NOT_CONSOLE, "file_block.block_files_users": _NOT_CONSOLE,
    "file_block.exceptional_block_files": _NOT_CONSOLE,
    "file_block.exceptional_block_files_processes": _NOT_CONSOLE,
    "file_block.exceptional_block_files_users": _NOT_CONSOLE,
    "package_block.block_packages_processes": _NOT_CONSOLE, "package_block.block_packages_users": _NOT_CONSOLE,
    "package_block.exceptional_block_packages_files": _NOT_CONSOLE,
    "package_block.exceptional_block_packages_processes": _NOT_CONSOLE,
    "package_block.exceptional_block_packages_users": _NOT_CONSOLE,
    "file_integrity_monitoring.monitored_files_attributes": _DROPPED,
    "file_integrity_monitoring.monitored_files_read": _DROPPED,
    "registry_access_monitoring.monitored_registry_read": _NOT_CONSOLE,
    "malware_scan_options.include_directories": "Aqua sets its own list and restores it on every save",
    "readonly_files": "Read-Only Directories and Files: deprecated by Aqua, absent from the console, and refused when on for a container policy",
    "tripwire": "Honeypot (functions): does nothing without an AWS secret key, and the tool never manages credentials. Set it in the console",
}


class RuntimePolicySpec(ManagedSpec):
    """Desired state of an Aqua runtime policy."""

    description: str = ""
    enabled: bool = True

    enforce: bool = False
    """False is audit mode, True is enforce mode.

    Defaults to audit: a policy that silently starts enforcing on creation is
    the wrong default for a tool whose first run may be against production.
    """

    enforceAfterDays: int | None = None
    """Enforce Mode after this many days. When Aqua makes the switch, write ``enforce:
    true`` too: a file still saying ``false`` puts the policy back in audit."""
    runtimeType: RuntimeType = RuntimeType.CONTAINER

    applicationScopes: list[str] = Field(
        min_length=1,
        description=(
            "The application scopes this policy applies to. Required: when Aqua "
            "is given none it applies the policy to Global, meaning every "
            "workload. Write [\"Global\"] if that is what you intend."
        ),
    )
    """Required, with at least one entry.

    Aqua's own default for a policy with no scopes is ``["Global"]`` -- every
    workload (verified live). Writing ``["Global"]`` here produces exactly that
    policy; what is not allowed is getting it by leaving the field out, because
    in config-as-code an omission is far more often a mistake than a decision,
    and in enforce mode this one blocks workloads everywhere. Export always
    writes the scopes it reads, so adopting existing policies is unaffected.
    """
    excludeApplicationScopes: list[str] | None = None
    additionalScopeCriteria: AdditionalScopeCriteria | None = None

    controls: Controls = Field(default_factory=Controls)

    @model_validator(mode="after")
    def _sections_aqua_allows_for_this_runtime_type(self):
        """Aqua refuses this switched on (HTTP 400, write-tested); say so at
        validate time. Switched off they are fine: Aqua returns them, off, on
        every policy, so an export carries them."""
        if self.runtimeType is RuntimeType.FUNCTION and self.enabled is False:
            raise ValueError(
                "a function policy cannot be disabled: Aqua stores it enabled whatever is "
                "sent (write-tested). To keep one inert, narrow additionalScopeCriteria.")
        c = self.controls
        if (self.runtimeType is not RuntimeType.CONTAINER and c.blockOutdatedImages
                and c.blockOutdatedImages.enabled):
            raise ValueError(
                "controls.blockOutdatedImages is only available on container policies.")
        return self


class RuntimePolicy(Resource):
    apiVersion: str = API_VERSION
    kind: str = KIND
    metadata: Metadata
    spec: RuntimePolicySpec


# --------------------------------------------------------------------------- #
# Canonical path -> Aqua API path
#
# Fields NOT mapped here are deliberately not ours: `type`, `author`, `created`,
# `updated`, `lastupdate`, `digest`, `version`, `is_ootb_policy` and friends are
# server-assigned. The three-way diff leaves anything outside this table alone,
# so omitting them is what stops the tool trying to null out Aqua's own metadata.
# --------------------------------------------------------------------------- #

def _section(name: str, block: str, settings: dict[str, str]) -> list[FieldMapping]:
    """A control whose API fields all live in one object, switch included."""
    return _control(name, f"{block}.enabled",
                    {c: f"{block}.{a}" for c, a in settings.items()})


def _tabs(tabs: dict[str, dict[str, str]]) -> dict[str, str]:
    """Flatten Monitor/Exclude-style tabs into ``tab.setting`` settings."""
    return {f"{tab}.{c}": a for tab, fields in tabs.items() for c, a in fields.items()}


FIELD_MAP = FieldMap(
    kind=KIND,
    mappings=[
        # --- identity and lifecycle -------------------------------------------
        FieldMapping("spec.description", "description"),
        FieldMapping("spec.enabled", "enabled"),
        FieldMapping("spec.enforce", "enforce"),
        FieldMapping("spec.enforceAfterDays", "enforce_after_days"),
        FieldMapping("spec.runtimeType", "runtime_type"),
        FieldMapping("spec.applicationScopes", "application_scopes"),
        FieldMapping("spec.excludeApplicationScopes", "exclude_application_scopes"),
        FieldMapping("spec.additionalScopeCriteria.expression", "scope.expression"),
        FieldMapping("spec.additionalScopeCriteria.variables", "scope.variables", items=SCOPE_VARIABLE),

        # --- images and workloads -------------------------------------------------
        FieldMapping(
            "spec.controls.blockNonCompliantImages",
            "block_disallowed_images",
            note=(
                "RESOLVED against a SaaS lab tenant: all 47 "
                "runtime policies carry block_disallowed_images, and none "
                "carries block_non_compliant_images, a name neither the specs "
                "nor the docs use."
            ),
        ),
        FieldMapping("spec.controls.blockNonCompliantResources", "block_non_compliant_workloads"),
        FieldMapping(
            "spec.controls.blockUnregisteredImages",
            "only_registered_images",
        ),
        FieldMapping("spec.controls.blockNonKubernetesContainers", "block_non_k8s_containers"),
        *_section("blockOutdatedImages", "block_outdated_images",
                  {"ageThreshold": "threshold_value", "unit": "threshold_unit"}),
        *_section("registriesAllowed", "allowed_registries", {"registries": "allowed_registries"}),

        # --- processes -------------------------------------------------------------
        *_control(
            "blockContainerExec", "container_exec.block_container_exec",
            {"allowedProcesses": "container_exec.container_exec_proc_white_list"},
            # Gated: container_exec.enabled moves in lockstep with the block
            # flag on every console-made policy; the inner flag alone diffs
            # clean and does nothing. The top-level block_container_exec is
            # vestigial (false even where the control is on).
            also_set=("container_exec.enabled",),
        ),
        *_control(
            "blockReverseShell", "reverse_shell.block_reverse_shell",
            {"allowedProcesses": "reverse_shell.reverse_shell_proc_white_list",
             "whitelistedIps": "reverse_shell.reverse_shell_ip_white_list"},
            also_set=("reverse_shell.enabled",),
        ),
        *_control("blockFilelessExec", "block_fileless_exec",
                  {"allowedProcesses": "block_fileless_exec_proc_white_list"}),
        *_control(
            "driftPrevention", "drift_prevention.enabled",
            {"includeScriptFiles": "drift_prevention.exec_lockdown_scripts",
             "allowedProcesses": "drift_prevention.exec_lockdown_white_list",
             "applyToChildProcesses": "drift_prevention.exec_lockdown_inherit_to_child"},
            # The console's one switch writes both; equal on every console-made
            # policy on the lab. Not mapped: image_lockdown (not in the console)
            # and prevent_privileged (Aqua accepts and drops it, write-tested).
            also_set=("drift_prevention.exec_lockdown",),
        ),
        *_section("executablesAllowed", "allowed_executables", {"executables": "allow_executables"}),
        *_section("executablesBlocked", "executable_blacklist", {"executables": "executables"}),
        FieldMapping("spec.controls.limitNewPrivileges", "no_new_privileges"),
        *_section("limitContainerPrivileges", "limit_container_privileges", {
            "privileged": "privileged", "hostNetwork": "netmode", "hostPid": "pidmode",
            "hostIpc": "ipcmode", "hostUts": "utsmode", "hostUserNamespace": "usermode",
            "rootUser": "prevent_root_user", "lowPortBinding": "prevent_low_port_binding",
            "addCapabilities": "block_add_capabilities", "ownerUserContext": "use_host_user"}),
        *_section("capabilitiesBlock", "linux_capabilities",
                  {"dropCapabilities": "remove_linux_capabilities"}),
        *_control("forkGuard", "enable_fork_guard", {"processLimit": "fork_guard_process_limit"}),

        # --- network and behaviour -------------------------------------------------
        FieldMapping(
            "spec.controls.blockCryptocurrencyMining",
            "enable_crypto_mining_dns",
            note=(
                "The provider's data source maps block_cryptocurrency_mining onto "
                "EnableCryptoMiningDns, so the two are the same control despite "
                "the names reading differently."
            ),
        ),
        FieldMapping("spec.controls.dnsIpReputation", "enable_ip_reputation"),
        FieldMapping("spec.controls.portScanningDetection", "enable_port_scan_protection"),
        *_section("portBlock", "port_block", {
            "blockedInboundPorts": "block_inbound_ports",
            "blockedOutboundPorts": "block_outbound_ports"}),
        FieldMapping("spec.controls.bruteForceLoginDetection", "audit_brute_force_login"),

        # --- files, packages, volumes ------------------------------------------------
        *_section("fileBlock", "file_block", {"files": "filename_block_list"}),
        *_section("packageBlock", "package_block", {"packages": "packages_black_list"}),
        *_section("volumesBlocked", "restricted_volumes", {"volumes": "volumes"}),
        *_section("fileIntegrityMonitoring", "file_integrity_monitoring", {
            "create": "monitored_files_create", "modify": "monitored_files_modify",
            "delete": "monitored_files_delete",
            **_tabs({
                "monitor": {"paths": "monitored_files", "processes": "monitored_files_processes",
                            "users": "monitored_files_users"},
                "exclude": {"paths": "exceptional_monitored_files",
                            "processes": "exceptional_monitored_files_processes",
                            "users": "exceptional_monitored_files_users"}})}),
        *_section("realTimeMalwareProtection", "malware_scan_options", {
            "action": "action", "excludedPaths": "exclude_directories",
            "excludedProcesses": "exclude_processes",
            "collectForensicFiles": "file_forensic_collection",
            "collectSelectiveMemoryDumps": "selective_memory_dump_collection"}),

        # --- audit -------------------------------------------------------------------
        *_section("forensics", "auditing", {
            "allProcesses": "audit_all_processes", "fullCommandArguments": "audit_process_cmdline",
            "allNetwork": "audit_all_network", "osUserActivity": "audit_os_user_activity",
            "successfulLogins": "audit_success_login", "failedLogins": "audit_failed_login",
            "userAccountManagement": "audit_user_account_management"}),
        *_section("systemIntegrityMonitoring", "system_integrity_protection", {
            "systemTime": "audit_systemtime_change",
            "windowsServicesMonitoring": "windows_services_monitoring",
            "monitorSystemLogIntegrity": "monitor_audit_log_integrity"}),

        # --- hosts ---------------------------------------------------------------------
        *_section("osUsersAndGroupsAllowed", "whitelisted_os_users",
                  {"usersAllowed": "user_white_list", "groupsAllowed": "group_white_list"}),
        *_section("osUsersAndGroupsBlocked", "blacklisted_os_users",
                  {"usersBlocked": "user_black_list", "groupsBlocked": "group_black_list"}),
        *_section("windowsRegistryMonitoring", "registry_access_monitoring", {
            "create": "monitored_registry_create", "modify": "monitored_registry_modify",
            "delete": "monitored_registry_delete", "attributes": "monitored_registry_attributes",
            **_tabs({
                "monitor": {"paths": "monitored_registry_paths",
                            "processes": "monitored_registry_processes",
                            "users": "monitored_registry_users"},
                "exclude": {"paths": "exceptional_monitored_registry_paths",
                            "processes": "exceptional_monitored_registry_processes",
                            "users": "exceptional_monitored_registry_users"}})}),
        *_section("windowsRegistryProtection", "readonly_registry", _tabs({
            "protect": {"paths": "readonly_registry_paths",
                        "processes": "readonly_registry_processes",
                        "users": "readonly_registry_users"},
            "exclude": {"paths": "exceptional_readonly_registry_paths",
                        "processes": "exceptional_readonly_registry_processes",
                        "users": "exceptional_readonly_registry_users"}})),

        # --- Secure AI -------------------------------------------------------------------
        *_section("secureAiDiscovery", "secure_ai_discovery", {"ignoreList": "ignore_list"}),
        *_section("secureAiUnauthorizedModels", "secure_ai_unauthorized_models",
                  {"models": "unauthorized_list"}),
        FieldMapping("spec.controls.secureAiProtection", "secure_ai_protection.enabled"),

        # --- default policies only (see KindDef.only_on) --------------------------
        FieldMapping("spec.controls.bypassScope.enabled", "bypass_scope.enabled"),
        FieldMapping("spec.controls.bypassScope.expression", "bypass_scope.scope.expression"),
        FieldMapping("spec.controls.bypassScope.variables", "bypass_scope.scope.variables",
                     items=SCOPE_VARIABLE),
    ],
)
