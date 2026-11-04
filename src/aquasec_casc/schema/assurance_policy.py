"""The AssurancePolicy kind: what a scan result must satisfy.

One kind for the console's five kinds of assurance policy, told apart by
``spec.assuranceType``, as they are in the API: ``/assurance_policy/{type}/{name}``.
Names are unique only within a type -- every type has its own "Default" -- so
an object's key is ``image/Default`` (``KindDef.key``).

Names are the console's labels in camelCase, under the console's three headings:
``actions``, ``exceptions`` and ``controls``. As for runtime policies, the file
is the whole policy: what it leaves out under those headings is off.

Everything mapped here was write-tested against a live tenant, through create,
update and a later re-save. What Aqua accepts and then drops is not offered; see
``NOT_OFFERED``.
"""

from __future__ import annotations

from enum import Enum

from pydantic import Field, field_validator, model_validator

from .base import API_VERSION, ManagedSpec, Metadata, Resource, StrictModel
from .fieldmap import FieldMap, FieldMapping
from .sections import AdditionalScopeCriteria, Heading, Section, control

KIND = "AssurancePolicy"


class AssuranceType(str, Enum):
    IMAGE = "image"
    HOST = "host"
    FUNCTION = "function"
    KUBERNETES = "kubernetes"
    CF_APPLICATION = "cf_application"
    """VMware Tanzu applications."""


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ExploitType(str, Enum):
    """The API's values, as the console's CISA, DoS, Local, Remote and Web Apps."""

    CISA = "CISA"
    DOS = "dos"
    LOCAL = "local"
    REMOTE = "remote"
    WEBAPPS = "webapps"


# --------------------------------------------------------------------------- #
# Actions: what Aqua does when the policy fails
# --------------------------------------------------------------------------- #

class DisplayWarningMessage(Section):
    """Display warning message in Linux shell (Kubernetes)."""

    message: str | None = None


class Actions(Heading):
    """The console's Actions. Left out means not done."""

    createAuditMessage: bool | None = None
    """Create an audit message when the policy fails."""
    failCicd: bool | None = None
    """Fail the Aqua step in CI/CD."""
    markNonCompliant: bool | None = None
    """Mark failed images (hosts, resources) as non-compliant. On a function
    policy: Block function if non-compliant."""
    blockResources: bool | None = None
    """Block resources if policy fails (Kubernetes)."""
    displayWarningMessage: DisplayWarningMessage | None = None


# --------------------------------------------------------------------------- #
# Exceptions: what evaluating the policy ignores
# --------------------------------------------------------------------------- #

class GracePeriod(Section):
    days: int | None = Field(default=None, ge=1, le=999)

    @model_validator(mode="after")
    def _days_are_needed(self):
        if self.enabled and self.days is None:
            raise ValueError("needs 'days': how long the grace period is (1-999)")
        return self


class IgnoreSpecificVulnerabilities(Section):
    cves: list[str] | None = None


class IgnorePaths(Section):
    """Ignore vulnerabilities, malware and sensitive data found in these paths
    (gitignore syntax)."""

    paths: list[str] | None = None


class Exceptions(Heading):
    """The console's Exceptions. Left out means nothing is ignored."""

    ignoreNoFix: bool | None = None
    """Ignore vulnerabilities that have no available fix."""
    ignoreRecentlyPublished: GracePeriod | None = None
    """Ignore vulnerabilities published in the last [days] days."""
    ignoreRecentlyPublishedRunning: GracePeriod | None = None
    """The same for running workloads. In the API, not the docs; stored as written."""
    ignoreRecentlyFixed: GracePeriod | None = None
    """Ignore vulnerabilities fixed in the last [days] days (Trivy Premium)."""
    ignoreSpecificVulnerabilities: IgnoreSpecificVulnerabilities | None = None
    ignorePaths: IgnorePaths | None = None
    ignoreBaseImage: bool | None = None
    """Ignore vulnerabilities found in the base image."""


# --------------------------------------------------------------------------- #
# Controls: the tests themselves
# --------------------------------------------------------------------------- #

class Package(StrictModel):
    name: str
    version: str | None = None
    versionRange: str | None = None
    """How ``version`` compares, in the console's words, e.g. ``Less Than``."""


class Packages(Section):
    packages: list[Package] | None = None


class Label(StrictModel):
    key: str
    value: str | None = None
    """Left out: the key must (not) exist, with any value."""


class Labels(Section):
    labels: list[Label] | None = None


class BaseImage(StrictModel):
    registry: str
    """The registry, as named in Aqua."""
    image: str
    """A registered image, or ``repository:*`` for everything in a repository.
    Aqua refuses one it does not know."""


class ApprovedBaseImage(Section):
    images: list[BaseImage] | None = None


class CvesBlocked(Section):
    cves: list[str] | None = None


class Licenses(Section):
    licenses: list[str] | None = None


class PermissionsBlocked(Section):
    """Function permissions, as ``service:permission``."""

    permissions: list[str] | None = None


class DynamicThreatAnalysis(Section):
    severity: Severity | None = None
    """Fails on issues of this severity or higher."""


class Malware(Section):
    """Malware. The settings are the host policy's."""

    scanNfsMounts: bool | None = None
    """Enable NFS share scan."""
    scanWindowsRegistry: bool | None = None
    """Scan Windows registry hives."""
    inMemoryScan: bool | None = None
    """Enable In-memory scan."""
    scanArchives: bool | None = None
    monitoredPaths: list[str] | None = None
    excludedPaths: list[str] | None = None
    action: str | None = None
    """Action for Malware Files: ``alert`` or ``delete``."""
    collectForensicFiles: bool | None = None


class SensitiveData(Section):
    excludedPaths: list[str] | None = None
    """Directories and file names ignored when scanning for sensitive data."""


class VulnerabilityExploitability(Section):
    exploitTypes: list[ExploitType] | None = None


class VulnerabilityScore(Section):
    range: list[float] | None = Field(default=None, min_length=2, max_length=2)
    """``[from, to]``: fails on vulnerabilities whose score is in the range."""


class VulnerabilityScoreAndSeverity(Section):
    range: list[float] | None = Field(default=None, min_length=2, max_length=2)
    severity: Severity | None = None
    useCustomSeverity: bool | None = None


class VulnerabilitySeverity(Section):
    severity: Severity | None = None
    """Fails at this severity or higher."""
    useCustomSeverity: bool | None = None


class AutoScan(Section):
    """Rescan what the policy covers on a schedule."""

    iterationType: str | None = None
    """``once``, ``daily``, ``weekly`` or ``monthly``."""
    iteration: int | None = None
    time: str | None = None
    weekDays: list[str] | None = None


#: Controls the console offers on some types only. Aqua stores them on any type
#: and they do nothing there, silently, so ``validate`` says so.
ONLY_ON: dict[str, frozenset[AssuranceType]] = {
    "approvedBaseImage": frozenset({AssuranceType.IMAGE, AssuranceType.CF_APPLICATION}),
    "dynamicThreatAnalysis": frozenset({AssuranceType.IMAGE, AssuranceType.CF_APPLICATION}),
    "labelsForbidden": frozenset({AssuranceType.IMAGE, AssuranceType.CF_APPLICATION}),
    "labelsRequired": frozenset({AssuranceType.IMAGE, AssuranceType.CF_APPLICATION}),
    "microEnforcer": frozenset({AssuranceType.IMAGE, AssuranceType.CF_APPLICATION}),
    "osPackageManager": frozenset({AssuranceType.IMAGE, AssuranceType.CF_APPLICATION}),
    "superuser": frozenset({AssuranceType.IMAGE, AssuranceType.CF_APPLICATION}),
    "cisBenchmarkDocker": frozenset({AssuranceType.HOST}),
    "cisBenchmarkKubernetes": frozenset({AssuranceType.HOST}),
    "cisBenchmarkLinux": frozenset({AssuranceType.HOST}),
    "cisBenchmarkWindows": frozenset({AssuranceType.HOST}),
    "openshiftHardening": frozenset({AssuranceType.HOST}),
    "excessivePermissions": frozenset({AssuranceType.FUNCTION}),
    "functionIntegrity": frozenset({AssuranceType.FUNCTION}),
    "permissionsBlocked": frozenset({AssuranceType.FUNCTION}),
    "kubernetesControls": frozenset({AssuranceType.KUBERNETES}),
}


class Controls(Heading):
    """The console's Controls. A control left out is off.

    Which type offers which is in ``ONLY_ON``; the rest are on the image, host
    and function policies, as the console lists them.
    """

    # --- vulnerabilities ---------------------------------------------------------
    vulnerabilitySeverity: VulnerabilitySeverity | None = None
    vulnerabilityScore: VulnerabilityScore | None = None
    vulnerabilityScoreAndSeverity: VulnerabilityScoreAndSeverity | None = None
    vulnerabilityExploitability: VulnerabilityExploitability | None = None
    cvesBlocked: CvesBlocked | None = None

    # --- contents ---------------------------------------------------------------
    malware: Malware | None = None
    sensitiveData: SensitiveData | None = None
    packagesBlocked: Packages | None = None
    packagesRequired: Packages | None = None
    ossLicensesAllowed: Licenses | None = None
    ossLicensesBlocked: Licenses | None = None

    # --- images ------------------------------------------------------------------
    approvedBaseImage: ApprovedBaseImage | None = None
    dynamicThreatAnalysis: DynamicThreatAnalysis | None = None
    labelsForbidden: Labels | None = None
    labelsRequired: Labels | None = None
    microEnforcer: bool | None = None
    osPackageManager: bool | None = None
    superuser: bool | None = None

    # --- hosts -------------------------------------------------------------------
    cisBenchmarkDocker: bool | None = None
    cisBenchmarkKubernetes: bool | None = None
    cisBenchmarkLinux: bool | None = None
    cisBenchmarkWindows: bool | None = None
    openshiftHardening: bool | None = None
    """Aqua says not to use it: use cisBenchmarkKubernetes."""

    # --- functions ---------------------------------------------------------------
    excessivePermissions: bool | None = None
    functionIntegrity: bool | None = None
    permissionsBlocked: PermissionsBlocked | None = None

    # --- Kubernetes --------------------------------------------------------------
    kubernetesControls: list[str] | None = None
    """The predefined and custom checks a Kubernetes policy runs, by name, as the
    console lists them ("Privileged", "Access to host network"). A name Aqua does
    not know is ignored by it, and reported by ``apply`` as not kept."""

    # --- scheduling -------------------------------------------------------------
    autoScan: AutoScan | None = None

    @field_validator("kubernetesControls")
    @classmethod
    def _in_a_stable_order(cls, value):
        return sorted(value) if value else value


#: In the API, and left as Aqua has them. The reason is what a live write test or
#: Aqua's docs showed.
NOT_OFFERED: dict[str, str] = {
    "packages_black_list[]: format, epoch, release, arch, license": "Aqua stores \"\" whatever is sent (write-tested)",
    "packages_white_list[]: format, epoch, release, arch, license": "as packages_black_list",
    "maximum_score": "Aqua sets it from vulnerability_score_range, whatever is sent (write-tested)",
    "custom_severity": "Aqua stores \"\" whatever is sent; use custom_severity_enabled",
    "cvss_severity_exclude_no_fix": "Aqua stores false whatever is sent; use control_exclude_no_fix",
    "maximum_score_exclude_no_fix": "Aqua stores false whatever is sent; use control_exclude_no_fix",
    "registries": "Aqua stores [] whatever is sent",
    "labels": "Aqua stores [] whatever is sent",
    "images": "Images Blocked: decisions on single images, made with the Block action; Aqua stores [] here",
    "allowed_images": "Images Allowed: decisions on single images, made with the Approve action; Aqua stores [] here",
    "exploitability_and_severity": "Vulnerability Exploitability and Severity: free-form and undocumented, and empty on every policy seen, so its field names cannot be checked",
    "custom_checks": "Custom Compliance Checks: scripts are objects of their own on the tenant",
    "custom_checks_enabled": "see custom_checks",
    "scap_files": "SCAP: scripts are objects of their own on the tenant",
    "scap_enabled": "see scap_files",
    "auto_scan_configured": "server-assigned",
    "kubernetes_controls": "what kubernetesControls is stored as; the client adapter keeps the three fields in step",
    "kubernetes_controls_avd_ids": "see kubernetes_controls",
    "read_only": "Aqua refuses it for an API user (HTTP 403)",
    "policy_settings.is_audit_checked": "no console label; audit_on_failure is the action",
    "permission": "server-assigned; Aqua stores \"Write\" whatever is sent",
    "id": "server-assigned", "name": "the name is the file's", "author": "server-assigned",
    "lastupdate": "server-assigned", "FFMap": "server-assigned",
    "category": "in the spec; Aqua does not return it", "domain": "in the spec; Aqua does not return it",
    "domain_name": "in the spec; Aqua does not return it", "enabled": "in the spec; Aqua does not return it",
    "resource_categories_enabled": "in the spec; Aqua does not return it",
    "disallow_resource_categories": "in the spec; Aqua does not return it",
}


class AssurancePolicySpec(ManagedSpec):
    """Desired state of an Aqua assurance policy."""

    assuranceType: AssuranceType
    description: str = ""

    applicationScopes: list[str] = Field(
        min_length=1,
        description=(
            "The application scopes this policy applies to. Required: when Aqua "
            "is given none it applies the policy to Global, meaning everything. "
            "Write [\"Global\"] if that is what you intend."
        ),
    )
    excludeApplicationScopes: list[str] | None = None
    additionalScopeCriteria: AdditionalScopeCriteria | None = None

    actions: Actions = Field(default_factory=Actions)
    exceptions: Exceptions = Field(default_factory=Exceptions)
    controls: Controls = Field(default_factory=Controls)

    @model_validator(mode="after")
    def _controls_this_type_offers(self):
        for name, types in ONLY_ON.items():
            value = getattr(self.controls, name)
            on = value.enabled if isinstance(value, Section) else bool(value)
            if on and self.assuranceType not in types:
                names = " and ".join(sorted(t.value for t in types))
                raise ValueError(f"controls.{name} is only available on {names} policies.")
        return self


class AssurancePolicy(Resource):
    apiVersion: str = API_VERSION
    kind: str = KIND
    metadata: Metadata
    spec: AssurancePolicySpec


def _list_control(name: str, switch: str, setting: str, api: str,
                  items: dict[str, str] | None = None) -> list[FieldMapping]:
    """A switch and one list beside it, as most assurance controls are."""
    base = f"spec.controls.{name}"
    return [FieldMapping(f"{base}.enabled", switch),
            FieldMapping(f"{base}.{setting}", api, items=items)]


_PACKAGE = {"name": "name", "version": "version", "versionRange": "version_range"}
_LABEL = {"key": "key", "value": "value"}


def _exception(name: str, switch: str, settings: dict[str, str]) -> list[FieldMapping]:
    return control(name, switch, settings, under="spec.exceptions")


FIELD_MAP = FieldMap(
    kind=KIND,
    mappings=[
        FieldMapping("spec.assuranceType", "assurance_type"),
        FieldMapping("spec.description", "description"),
        FieldMapping("spec.applicationScopes", "application_scopes"),
        FieldMapping("spec.excludeApplicationScopes", "exclude_application_scopes"),
        FieldMapping("spec.additionalScopeCriteria.expression", "scope.expression"),
        FieldMapping("spec.additionalScopeCriteria.variables", "scope.variables"),

        # --- actions -----------------------------------------------------------------
        FieldMapping("spec.actions.createAuditMessage", "audit_on_failure"),
        FieldMapping("spec.actions.failCicd", "fail_cicd"),
        FieldMapping("spec.actions.markNonCompliant", "block_failed"),
        FieldMapping("spec.actions.blockResources", "policy_settings.enforce"),
        *control("displayWarningMessage", "policy_settings.warn",
                 {"message": "policy_settings.warning_message"}, under="spec.actions"),

        # --- exceptions --------------------------------------------------------------
        FieldMapping("spec.exceptions.ignoreNoFix", "control_exclude_no_fix"),
        *_exception("ignoreRecentlyPublished", "ignore_recently_published_vln",
                    {"days": "ignore_recently_published_vln_period"}),
        *_exception("ignoreRecentlyPublishedRunning", "ignore_recently_published_running_vln",
                    {"days": "ignore_recently_published_running_vln_period"}),
        *_exception("ignoreRecentlyFixed", "ignore_recently_published_fix_vln",
                    {"days": "ignore_recently_published_fix_vln_period"}),
        *_exception("ignoreSpecificVulnerabilities", "cves_white_list_enabled",
                    {"cves": "cves_white_list"}),
        *_exception("ignorePaths", "ignore_risk_resources_enabled",
                    {"paths": "ignored_risk_resources"}),
        FieldMapping("spec.exceptions.ignoreBaseImage", "ignore_base_image_vln"),

        # --- vulnerabilities ---------------------------------------------------------
        *control("vulnerabilitySeverity", "cvss_severity_enabled", {
            "severity": "cvss_severity", "useCustomSeverity": "custom_severity_enabled"}),
        *control("vulnerabilityScore", "maximum_score_enabled", {
            "range": "vulnerability_score_range"}),
        *control("vulnerabilityScoreAndSeverity", "aggregated_vulnerability.enabled", {
            "range": "aggregated_vulnerability.score_range",
            "severity": "aggregated_vulnerability.severity",
            "useCustomSeverity": "aggregated_vulnerability.custom_severity_enabled"}),
        *_list_control("vulnerabilityExploitability", "vulnerability_exploitability",
                       "exploitTypes", "disallow_exploit_types"),
        *_list_control("cvesBlocked", "cves_black_list_enabled", "cves", "cves_black_list"),

        # --- contents ----------------------------------------------------------------
        *control("malware", "disallow_malware", {
            "scanNfsMounts": "scan_nfs_mounts", "scanWindowsRegistry": "scan_windows_registry",
            "inMemoryScan": "scan_process_memory", "scanArchives": "scan_malware_in_archives",
            "monitoredPaths": "monitored_malware_paths",
            "excludedPaths": "exceptional_monitored_malware_paths",
            "action": "malware_action", "collectForensicFiles": "file_forensic_collection"}),
        *control("sensitiveData", "scan_sensitive_data",
                 {"excludedPaths": "ignored_sensitive_resources"}),
        *_list_control("packagesBlocked", "packages_black_list_enabled", "packages",
                       "packages_black_list", items=_PACKAGE),
        *_list_control("packagesRequired", "packages_white_list_enabled", "packages",
                       "packages_white_list", items=_PACKAGE),
        *_list_control("ossLicensesAllowed", "whitelisted_licenses_enabled", "licenses",
                       "whitelisted_licenses"),
        *_list_control("ossLicensesBlocked", "blacklisted_licenses_enabled", "licenses",
                       "blacklisted_licenses"),

        # --- images ------------------------------------------------------------------
        *_list_control("approvedBaseImage", "trusted_base_images_enabled", "images",
                       "trusted_base_images",
                       items={"registry": "registry", "image": "imagename"}),
        *control("dynamicThreatAnalysis", "dta_enabled", {"severity": "dta_severity"}),
        *_list_control("labelsForbidden", "forbidden_labels_enabled", "labels",
                       "forbidden_labels", items=_LABEL),
        *_list_control("labelsRequired", "required_labels_enabled", "labels",
                       "required_labels", items=_LABEL),
        FieldMapping("spec.controls.microEnforcer", "force_microenforcer"),
        FieldMapping("spec.controls.osPackageManager", "partial_results_image_fail"),
        FieldMapping("spec.controls.superuser", "only_none_root_users"),

        # --- hosts -------------------------------------------------------------------
        FieldMapping("spec.controls.cisBenchmarkDocker", "docker_cis_enabled"),
        FieldMapping("spec.controls.cisBenchmarkKubernetes", "kube_cis_enabled"),
        FieldMapping("spec.controls.cisBenchmarkLinux", "linux_cis_enabled"),
        FieldMapping("spec.controls.cisBenchmarkWindows", "windows_cis_enabled"),
        FieldMapping("spec.controls.openshiftHardening", "openshift_hardening_enabled"),

        # --- functions ---------------------------------------------------------------
        FieldMapping("spec.controls.excessivePermissions", "enforce_excessive_permissions"),
        FieldMapping("spec.controls.functionIntegrity", "function_integrity_enabled"),
        *_list_control("permissionsBlocked", "blacklist_permissions_enabled", "permissions",
                       "blacklist_permissions"),

        # --- Kubernetes --------------------------------------------------------------
        FieldMapping("spec.controls.kubernetesControls", "kubernetes_controls_names"),

        # --- scheduling -------------------------------------------------------------
        *control("autoScan", "auto_scan_enabled", {
            "iterationType": "auto_scan_time.iteration_type", "iteration": "auto_scan_time.iteration",
            "time": "auto_scan_time.time", "weekDays": "auto_scan_time.week_days"}),
    ],
)
