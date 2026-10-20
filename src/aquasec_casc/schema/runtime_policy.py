"""The RuntimePolicy kind -- the MVP centrepiece.

Canonical field names are chosen for a human reading a pull request, and are
translated to Aqua's API names by ``FIELD_MAP``. Where Aqua has a good name
already, we keep it; where Aqua nests a control or has renamed it across
versions, the mapping absorbs that.

API paths were mined from terraform-provider-aquasec v0.15.1 (commit 49182c7).
"""

from __future__ import annotations

from enum import Enum

from pydantic import Field, field_validator, model_validator

from .base import API_VERSION, ManagedSpec, Metadata, Resource, StrictModel
from .fieldmap import FieldMap, FieldMapping

KIND = "RuntimePolicy"


class RuntimeType(str, Enum):
    """Which workload family the policy applies to.

    Aqua models container, host and function runtime policies as one object
    distinguished by this field, rather than as three endpoints.
    """

    CONTAINER = "container"
    HOST = "host"
    FUNCTION = "function"


class Section(StrictModel):
    """A console control section: an on/off switch plus its settings.

    Writing any setting turns the section on unless ``enabled: false`` is
    written too. In the API the switch and the settings are separate fields,
    and settings under a switch that is off do nothing -- silently. Asking for
    a file block list and getting no file block is exactly that trap.
    """

    enabled: bool = False

    @model_validator(mode="before")
    @classmethod
    def _settings_turn_the_section_on(cls, data):
        if isinstance(data, dict) and data and "enabled" not in data:
            return {**data, "enabled": True}
        return data


class DriftPrevention(Section):
    """Drift prevention, including exec lockdown and its allow-list."""

    execLockdown: bool = False
    imageLockdown: bool = False

    execLockdownScripts: bool = False
    """Extend exec lockdown to scripts, not just binaries."""

    inheritToChild: bool = False
    """Apply the exec lockdown decision to child processes."""


    exceptions: list[str] = Field(default_factory=list)
    """Processes exempt from exec lockdown.

    Aqua calls this ``exec_lockdown_white_list``. This is where legitimate
    startup processes go when drift prevention blocks them.
    """


# --------------------------------------------------------------------------- #
# Control sections, named as in the console. Lists of names accept the
# console's wildcard syntax.
# --------------------------------------------------------------------------- #

class LimitContainerPrivileges(Section):
    """Limit Container Privileges: each setting true prevents that privilege."""

    privileged: bool | None = None
    """Privileged containers."""
    hostNetwork: bool | None = None
    """Access to the host network."""
    hostPid: bool | None = None
    """Use of the host PID namespace."""
    hostIpc: bool | None = None
    """Use of the host IPC namespace."""
    hostUts: bool | None = None
    """Use of the host UTS namespace."""
    hostUserNamespace: bool | None = None
    """Use of the host user namespace."""
    rootUser: bool | None = None
    """Containers configured with the "root" user."""
    lowPortBinding: bool | None = None
    """Port binding lower than 1024 (the only one that applies to Windows)."""
    addCapabilities: bool | None = None
    """Adding capabilities with --cap-add."""
    ownerUserContext: bool | None = None
    """Running in the owner's user context (requires a restart)."""


class CapabilitiesBlock(Section):
    """Capabilities Block: Linux capabilities containers may not use."""

    capabilities: list[str] | None = None


class ExecutablesBlocked(Section):
    """Executables Blocked."""

    executables: list[str] | None = None


class ExecutablesAllowed(Section):
    """Executables Allowed: everything else is prevented from running."""

    executables: list[str] | None = None
    rootExecutables: list[str] | None = None
    """Executables allowed to run as root, when listed separately."""
    separateRootExecutables: bool | None = None


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

    olderThan: int | None = None
    unit: TimeUnit | None = None


class FailedKubernetesChecks(Section):
    checks: list[str] | None = None


class PortBlock(Section):
    """Port Block: ports containers may not use."""

    inbound: list[str] | None = None
    outbound: list[str] | None = None


class FileRules(Section):
    """Shared shape of File Block, Read-Only Files and Read-Only Registry."""

    exceptions: list[str] | None = None
    users: list[str] | None = None
    exceptionUsers: list[str] | None = None
    processes: list[str] | None = None
    exceptionProcesses: list[str] | None = None


class FileBlock(FileRules):
    """File Block: no reading, writing or executing these files."""

    files: list[str] | None = None


class ReadonlyFiles(FileRules):
    """Read-Only Files."""

    files: list[str] | None = None


class ReadonlyRegistry(FileRules):
    """Read-Only Registry (Windows hosts)."""

    paths: list[str] | None = None


class PackageBlock(Section):
    """Package Block: no reading, writing or executing files of these packages."""

    packages: list[str] | None = None
    exceptionFiles: list[str] | None = None
    users: list[str] | None = None
    exceptionUsers: list[str] | None = None
    processes: list[str] | None = None
    exceptionProcesses: list[str] | None = None


class Monitoring(FileRules):
    """Shared shape of File Integrity and Registry Access Monitoring: which
    operations raise audit events. They audit; they never block."""

    paths: list[str] | None = None
    monitorCreate: bool | None = None
    monitorModify: bool | None = None
    monitorDelete: bool | None = None


class FileIntegrityMonitoring(Monitoring):
    """File Integrity Monitoring: create, modify and delete, as in the console.

    The API also has read and attributes switches. Write-tested live: Aqua
    accepts them on create, then drops read and refuses attributes on every
    later update -- so they are not offered here.
    """


class RegistryAccessMonitoring(Monitoring):
    """Registry Access Monitoring (Windows hosts)."""

    monitorRead: bool | None = None
    monitorAttributes: bool | None = None


class OsUsers(Section):
    users: list[str] | None = None
    groups: list[str] | None = None


class MalwareAction(str, Enum):
    ALERT = "alert"
    BLOCK = "block"
    DELETE = "delete"


class MalwareProtection(Section):
    """Real-time Malware Protection (needs the Advanced Malware Protection
    licence).

    The scanned directories are not configurable, as in the console: Aqua
    sets them itself and restores its own list on every save (write-tested).
    Only exclusions are yours. In audit mode, ``alert`` is the only action.
    """

    action: MalwareAction | None = None
    excludeDirectories: list[str] | None = None
    excludeProcesses: list[str] | None = None
    fileForensicCollection: bool | None = None
    memoryDumpCollection: bool | None = None


class Forensics(Section):
    """Forensics: what goes into the audit log."""

    allProcesses: bool | None = None
    processCommandLine: bool | None = None
    allNetwork: bool | None = None
    osUserActivity: bool | None = None
    successfulLogins: bool | None = None
    failedLogins: bool | None = None
    userAccountManagement: bool | None = None


class SystemIntegrityMonitoring(Section):
    """System Integrity Monitoring (hosts): audits, never blocks."""

    systemTimeChanges: bool | None = None
    windowsServices: bool | None = None
    auditLogIntegrity: bool | None = None


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

    ignore: list[str] | None = None
    """Models and services left out of discovery ("Ignore List")."""

    @field_validator("ignore")
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


class ScopeVariable(StrictModel):
    """One term of a scope expression, e.g. a container label match."""

    attribute: str
    value: str
    name: str | None = None


class BypassScope(StrictModel):
    """Workloads exempt from this policy.

    Only the default container and host runtime policies have it -- the same as
    in the console. The default container policy ships with it on, exempting
    Aqua's own components, ``kube-system`` and pod sandboxes.
    """

    enabled: bool = False
    expression: str = ""
    """How the variables combine, e.g. ``v1 || v2 || v3``."""

    variables: list[ScopeVariable] = Field(default_factory=list)


class Controls(StrictModel):
    """The security controls a runtime policy turns on or off.

    Flattened relative to the API, which nests several of these inside their own
    objects alongside their exception lists.
    """

    # --- image compliance --------------------------------------------------------
    blockNonCompliantImages: bool | None = None
    """Block images an assurance policy has marked non-compliant.

    Worth understanding before relying on audit mode: the enforcer evaluates
    compliance by image *hash*, so a non-compliant verdict from one policy blocks
    that hash everywhere the enforcer sees it -- including scopes meant to be in
    audit mode. Leaving this control out of a dev/test policy entirely is the
    recommended fix, rather than relying on audit mode to soften it.

    The API field is ``block_disallowed_images``, not the documented
    ``block_non_compliant_images`` -- see FIELD_MAP.
    """

    blockNonCompliantWorkloads: bool | None = None
    """Block containers in non-compliant Kubernetes pods."""

    onlyRegisteredImages: bool | None = None
    """Allow only images registered in Aqua to run."""

    # --- exec and shell --------------------------------------------------------
    blockContainerExec: bool | None = None
    containerExecAllowedProcesses: list[str] | None = None
    blockReverseShell: bool | None = None
    reverseShellAllowedProcesses: list[str] | None = None
    reverseShellAllowedIps: list[str] | None = None
    blockFilelessExec: bool | None = None
    filelessExecAllowedProcesses: list[str] | None = None

    # --- drift -----------------------------------------------------------------
    driftPrevention: DriftPrevention | None = None

    # --- detection -------------------------------------------------------------
    blockCryptocurrencyMining: bool | None = None
    enableForkGuard: bool | None = None
    forkGuardProcessLimit: int | None = None
    enableIpReputation: bool | None = None
    enablePortScanProtection: bool | None = None

    # --- kubernetes / privileges ----------------------------------------------
    blockNonK8sContainers: bool | None = None
    noNewPrivileges: bool | None = None
    auditBruteForceLogin: bool | None = None

    # --- control sections (console names) ----------------------------------------
    limitContainerPrivileges: LimitContainerPrivileges | None = None
    capabilitiesBlock: CapabilitiesBlock | None = None
    executablesBlocked: ExecutablesBlocked | None = None
    executablesAllowed: ExecutablesAllowed | None = None
    registriesAllowed: RegistriesAllowed | None = None
    volumesBlocked: VolumesBlocked | None = None
    blockOutdatedImages: BlockOutdatedImages | None = None
    failedKubernetesChecks: FailedKubernetesChecks | None = None
    portBlock: PortBlock | None = None
    fileBlock: FileBlock | None = None
    packageBlock: PackageBlock | None = None
    readonlyFiles: ReadonlyFiles | None = None
    fileIntegrityMonitoring: FileIntegrityMonitoring | None = None
    malwareProtection: MalwareProtection | None = None
    forensics: Forensics | None = None
    allowedOsUsers: OsUsers | None = None
    """Whitelisted OS users (hosts)."""
    blockedOsUsers: OsUsers | None = None
    """Blacklisted OS users (hosts)."""
    systemIntegrityMonitoring: SystemIntegrityMonitoring | None = None
    readonlyRegistry: ReadonlyRegistry | None = None
    registryAccessMonitoring: RegistryAccessMonitoring | None = None
    secureAiDiscovery: SecureAiDiscovery | None = None
    secureAiUnauthorizedModels: SecureAiUnauthorizedModels | None = None
    # Not covered: tripwire (serverless; carries a password, and the tool never
    # manages credential fields), secure_ai_protection (not in the console's
    # list; needs prompt protection set up first), and the auditing.*_config
    # objects (no documented shape).

    # --- default policies only ---------------------------------------------------
    bypassScope: BypassScope | None = None
    """Only on "Aqua default runtime policy" and "Aqua default host runtime
    policy"; anywhere else it is reported as not allowed and not sent."""


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

    controls: Controls = Field(default_factory=Controls)

    @model_validator(mode="after")
    def _sections_aqua_allows_for_this_runtime_type(self):
        """Aqua refuses these switched on (HTTP 400, write-tested); say so at
        validate time. Switched off they are fine: Aqua returns them, off, on
        every policy, so an export carries them."""
        c = self.controls
        if self.runtimeType is RuntimeType.CONTAINER and c.readonlyFiles and c.readonlyFiles.enabled:
            raise ValueError(
                "controls.readonlyFiles is not available on container policies -- Aqua "
                "refuses it there (deprecated). controls.fileBlock blocks access to files.")
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

def _section(name: str, block: str, fields: dict[str, str]) -> list[FieldMapping]:
    """Mappings for one control section: its switch, then each setting."""
    base = f"spec.controls.{name}"
    return [FieldMapping(f"{base}.enabled", f"{block}.enabled"),
            *(FieldMapping(f"{base}.{c}", f"{block}.{a}") for c, a in fields.items())]


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

        # --- image compliance --------------------------------------------------
        FieldMapping(
            "spec.controls.blockNonCompliantImages",
            "block_disallowed_images",
            api_aliases=("block_non_compliant_images",),
            note=(
                "RESOLVED against the eu-1 lab tenant (11 Sep 2026): all 47 "
                "runtime policies carry block_disallowed_images, and none "
                "carries block_non_compliant_images. The Terraform provider is "
                "right to treat the latter as a retired alias. The alias is "
                "kept for read only, in case an older on-prem build still "
                "returns it."
            ),
        ),
        FieldMapping(
            "spec.controls.blockNonCompliantWorkloads",
            "block_non_compliant_workloads",
        ),
        FieldMapping(
            "spec.controls.onlyRegisteredImages",
            "only_registered_images",
            api_aliases=("block_unregistered_images",),
            note="Renamed from block_unregistered_images; older tenants use the alias.",
        ),

        # --- exec and shell ----------------------------------------------------
        FieldMapping(
            "spec.controls.blockContainerExec",
            "container_exec.block_container_exec",
            also_set=("container_exec.enabled",),
            note=(
                "Nested, and gated. There is also a top-level "
                "block_container_exec, but on the lab tenant it is False on all "
                "47 policies including the 5 where the control is actually on -- "
                "it is vestigial, and the nested field is authoritative. The "
                "container_exec.enabled gate tracks the block flag exactly "
                "(42 false/false, 5 true/true, never divergent), so it is "
                "written alongside; setting the inner flag alone would produce "
                "a policy that diffs clean and does nothing."
            ),
        ),
        FieldMapping(
            "spec.controls.containerExecAllowedProcesses",
            "container_exec.container_exec_proc_white_list",
        ),
        FieldMapping(
            "spec.controls.blockReverseShell",
            "reverse_shell.block_reverse_shell",
            also_set=("reverse_shell.enabled",),
            note=(
                "Same gated pattern as container_exec. The top-level "
                "block_reverse_shell is absent entirely on this tenant."
            ),
        ),
        FieldMapping(
            "spec.controls.reverseShellAllowedProcesses",
            "reverse_shell.reverse_shell_proc_white_list",
        ),
        FieldMapping(
            "spec.controls.reverseShellAllowedIps",
            "reverse_shell.reverse_shell_ip_white_list",
        ),
        FieldMapping("spec.controls.blockFilelessExec", "block_fileless_exec"),

        # --- drift prevention ---------------------------------------------------
        FieldMapping("spec.controls.driftPrevention.enabled", "drift_prevention.enabled"),
        FieldMapping(
            "spec.controls.driftPrevention.execLockdown",
            "drift_prevention.exec_lockdown",
        ),
        FieldMapping(
            "spec.controls.driftPrevention.imageLockdown",
            "drift_prevention.image_lockdown",
        ),
        FieldMapping(
            "spec.controls.driftPrevention.execLockdownScripts",
            "drift_prevention.exec_lockdown_scripts",
        ),
        FieldMapping(
            "spec.controls.driftPrevention.inheritToChild",
            "drift_prevention.exec_lockdown_inherit_to_child",
        ),
        # Not mapped: drift_prevention.prevent_privileged. The Terraform provider
        # declares it, but Aqua accepts it on create and update and then drops
        # it (write-tested live) -- managing it would show drift forever.
        # Blocking privileged containers is limit_container_privileges.privileged.
        FieldMapping(
            "spec.controls.driftPrevention.exceptions",
            "drift_prevention.exec_lockdown_white_list",
            note="Named 'exceptions' in our schema; it is the exec lockdown allow-list.",
        ),

        # --- detection ----------------------------------------------------------
        FieldMapping(
            "spec.controls.blockCryptocurrencyMining",
            "enable_crypto_mining_dns",
            note=(
                "The provider's data source maps block_cryptocurrency_mining onto "
                "EnableCryptoMiningDns, so the two are the same control despite "
                "the names reading differently."
            ),
        ),
        FieldMapping("spec.controls.enableForkGuard", "enable_fork_guard"),
        FieldMapping("spec.controls.forkGuardProcessLimit", "fork_guard_process_limit"),
        FieldMapping(
            "spec.controls.enableIpReputation",
            "enable_ip_reputation",
            api_aliases=("enable_ip_reputation_security",),
        ),
        FieldMapping(
            "spec.controls.enablePortScanProtection",
            "enable_port_scan_protection",
            api_aliases=("enable_port_scan_detection",),
        ),

        # --- kubernetes and privileges -------------------------------------------
        FieldMapping("spec.controls.blockNonK8sContainers", "block_non_k8s_containers"),
        FieldMapping(
            "spec.controls.noNewPrivileges",
            "no_new_privileges",
            api_aliases=("limit_new_privileges",),
        ),
        FieldMapping("spec.controls.auditBruteForceLogin", "audit_brute_force_login"),

        FieldMapping("spec.controls.filelessExecAllowedProcesses",
                     "block_fileless_exec_proc_white_list"),

        # --- control sections -------------------------------------------------------
        *_section("limitContainerPrivileges", "limit_container_privileges", {
            "privileged": "privileged", "hostNetwork": "netmode", "hostPid": "pidmode",
            "hostIpc": "ipcmode", "hostUts": "utsmode", "hostUserNamespace": "usermode",
            "rootUser": "prevent_root_user", "lowPortBinding": "prevent_low_port_binding",
            "addCapabilities": "block_add_capabilities", "ownerUserContext": "use_host_user"}),
        *_section("capabilitiesBlock", "linux_capabilities",
                  {"capabilities": "remove_linux_capabilities"}),
        *_section("executablesBlocked", "executable_blacklist", {"executables": "executables"}),
        *_section("executablesAllowed", "allowed_executables", {
            "executables": "allow_executables", "rootExecutables": "allow_root_executables",
            "separateRootExecutables": "separate_executables"}),
        *_section("registriesAllowed", "allowed_registries", {"registries": "allowed_registries"}),
        *_section("volumesBlocked", "restricted_volumes", {"volumes": "volumes"}),
        *_section("blockOutdatedImages", "block_outdated_images",
                  {"olderThan": "threshold_value", "unit": "threshold_unit"}),
        *_section("failedKubernetesChecks", "failed_kubernetes_checks", {"checks": "failed_checks"}),
        *_section("portBlock", "port_block",
                  {"inbound": "block_inbound_ports", "outbound": "block_outbound_ports"}),
        *_section("fileBlock", "file_block", {
            "files": "filename_block_list", "exceptions": "exceptional_block_files",
            "users": "block_files_users", "exceptionUsers": "exceptional_block_files_users",
            "processes": "block_files_processes",
            "exceptionProcesses": "exceptional_block_files_processes"}),
        *_section("packageBlock", "package_block", {
            "packages": "packages_black_list", "exceptionFiles": "exceptional_block_packages_files",
            "users": "block_packages_users", "exceptionUsers": "exceptional_block_packages_users",
            "processes": "block_packages_processes",
            "exceptionProcesses": "exceptional_block_packages_processes"}),
        *_section("readonlyFiles", "readonly_files", {
            "files": "readonly_files", "exceptions": "exceptional_readonly_files",
            "users": "readonly_files_users", "exceptionUsers": "exceptional_readonly_files_users",
            "processes": "readonly_files_processes",
            "exceptionProcesses": "exceptional_readonly_files_processes"}),
        *_section("fileIntegrityMonitoring", "file_integrity_monitoring", {
            "paths": "monitored_files", "exceptions": "exceptional_monitored_files",
            "users": "monitored_files_users", "exceptionUsers": "exceptional_monitored_files_users",
            "processes": "monitored_files_processes",
            "exceptionProcesses": "exceptional_monitored_files_processes",
            "monitorCreate": "monitored_files_create", "monitorModify": "monitored_files_modify",
            "monitorDelete": "monitored_files_delete"}),
        *_section("malwareProtection", "malware_scan_options", {
            "action": "action", "excludeDirectories": "exclude_directories", "excludeProcesses": "exclude_processes",
            "fileForensicCollection": "file_forensic_collection",
            "memoryDumpCollection": "selective_memory_dump_collection"}),
        *_section("forensics", "auditing", {
            "allProcesses": "audit_all_processes", "processCommandLine": "audit_process_cmdline",
            "allNetwork": "audit_all_network", "osUserActivity": "audit_os_user_activity",
            "successfulLogins": "audit_success_login", "failedLogins": "audit_failed_login",
            "userAccountManagement": "audit_user_account_management"}),
        *_section("allowedOsUsers", "whitelisted_os_users",
                  {"users": "user_white_list", "groups": "group_white_list"}),
        *_section("blockedOsUsers", "blacklisted_os_users",
                  {"users": "user_black_list", "groups": "group_black_list"}),
        *_section("systemIntegrityMonitoring", "system_integrity_protection", {
            "systemTimeChanges": "audit_systemtime_change",
            "windowsServices": "windows_services_monitoring",
            "auditLogIntegrity": "monitor_audit_log_integrity"}),
        *_section("readonlyRegistry", "readonly_registry", {
            "paths": "readonly_registry_paths", "exceptions": "exceptional_readonly_registry_paths",
            "users": "readonly_registry_users", "exceptionUsers": "exceptional_readonly_registry_users",
            "processes": "readonly_registry_processes",
            "exceptionProcesses": "exceptional_readonly_registry_processes"}),
        *_section("registryAccessMonitoring", "registry_access_monitoring", {
            "paths": "monitored_registry_paths", "exceptions": "exceptional_monitored_registry_paths",
            "users": "monitored_registry_users",
            "exceptionUsers": "exceptional_monitored_registry_users",
            "processes": "monitored_registry_processes",
            "exceptionProcesses": "exceptional_monitored_registry_processes",
            "monitorRead": "monitored_registry_read", "monitorModify": "monitored_registry_modify",
            "monitorAttributes": "monitored_registry_attributes",
            "monitorCreate": "monitored_registry_create",
            "monitorDelete": "monitored_registry_delete"}),
        *_section("secureAiDiscovery", "secure_ai_discovery", {"ignore": "ignore_list"}),
        *_section("secureAiUnauthorizedModels", "secure_ai_unauthorized_models",
                  {"models": "unauthorized_list"}),

        # --- default policies only (see KindDef.only_on) --------------------------
        FieldMapping("spec.controls.bypassScope.enabled", "bypass_scope.enabled"),
        FieldMapping("spec.controls.bypassScope.expression", "bypass_scope.scope.expression"),
        FieldMapping("spec.controls.bypassScope.variables", "bypass_scope.scope.variables"),
    ],
)
