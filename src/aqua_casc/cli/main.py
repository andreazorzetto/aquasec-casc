"""Layer 3 -- the CLI. Run once and exit.

Thin on purpose: it loads files, connects, calls the reconciler, renders the
result and picks an exit code. Everything that decides *what* happens lives in
the reconciler, so the phase 2 operator can reuse it unchanged.

Exit codes:
  validate  0 valid, 1 invalid
  diff      0 nothing to do, 1 error, 2 changes pending
  apply     0 done, 1 error; 2 when something is left pending, only with
            --detailed-exitcode (Argo CD fails a sync on any non-zero exit)
  export    0 done, 1 error
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Callable, TextIO

import yaml

from . import NAME
from .. import export as exporting
from ..reconcile import Options, Outcome, RunSummary, marker, reconcile_all
from ..reconcile.client import ClientError
from ..schema import SchemaError, SchemaErrorGroup, load_dir
from ..schema.loader import CONFIG_FILENAMES
from ..schema.registry import REGISTRY

CONFIG_FILE = CONFIG_FILENAMES[0]
ENV_INSTANCE = "AQUA_CASC_INSTANCE"


class UsageError(Exception):
    """A problem with how the tool was invoked or configured. Exit 1."""


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #

class Out:
    """Writes text, coloured only when it goes to a terminal."""

    COLOURS = {"green": "32", "yellow": "33", "red": "31", "cyan": "36", "dim": "2", "bold": "1"}

    def __init__(self, stream: TextIO, colour: bool) -> None:
        self.stream = stream
        self.colour = colour

    def paint(self, text: str, colour: str) -> str:
        if not self.colour or colour not in self.COLOURS:
            return text
        return f"\033[{self.COLOURS[colour]}m{text}\033[0m"

    def line(self, text: str = "", colour: str = "") -> None:
        print(self.paint(text, colour) if colour else text, file=self.stream)


_LOOK = {
    Outcome.IN_SYNC: ("=", "unchanged", "dim"),
    Outcome.CREATED: ("+", "created", "green"),
    Outcome.UPDATED: ("~", "updated", "yellow"),
    Outcome.ADOPTED: ("~", "adopted", "cyan"),
    Outcome.DELETED: ("-", "deleted", "red"),
    Outcome.DRIFT_DETECTED: ("!", "drift detected (ReportOnly)", "yellow"),
    Outcome.BLOCKED: ("x", "blocked", "red"),
    Outcome.ORPHANED: ("?", "orphaned", "yellow"),
    Outcome.FAILED: ("x", "FAILED", "red"),
}
_PLANNED = {
    "create": ("+", "will be created", "green"),
    "adopt": ("~", "will be adopted", "cyan"),
    "update": ("~", "will be updated", "yellow"),
    "delete": ("-", "will be deleted", "red"),
}


def _value(v) -> str:
    """A value as it would appear in the YAML: true/false, quoted strings, lists."""
    return json.dumps(v, ensure_ascii=False, default=str)


def change_lines(result, instance: str) -> list[str]:
    """A result's field changes in the vocabulary the user edited.

    The YAML name leads (``controls.blockNonCompliantImages``), with the API
    name in brackets for anyone checking the console or logs. A control's
    ``enabled`` gate, written alongside it, joins the control's own line rather
    than appearing as a separate change nobody asked for.
    """
    kind = REGISTRY.get(result.kind)
    field_map = kind.field_map if kind else None
    changed = {c.path for c in result.plan.changes}
    lines = []

    for change in result.plan.changes:
        if change.path == "description" and marker.strip(change.before) == marker.strip(change.after):
            lines.append(f"+ ownership marker ({marker.marker(instance)})")
            continue

        mapping, is_gate = field_map.for_api_path(change.path) if field_map else (None, False)
        if is_gate and mapping.api in changed:
            continue                                   # shown on the control's line

        name = mapping.canonical.removeprefix("spec.") if mapping else change.path
        if mapping and not is_gate:
            api = change.path
            gates = [g for g in mapping.also_set if g in changed]
            if gates:
                api += " + " + ", ".join(g.rsplit(".", 1)[-1] for g in gates)
        else:
            api = change.path

        if change.change.value == "add":
            text = f"+ {name}: {_value(change.after)}"
        else:
            text = f"! {name}: {_value(change.before)} -> {_value(change.after)}"
        if api != name:
            text += f"   (API: {api})"
        lines.append(text)
    return lines


def render_text(summary: RunSummary, out: Out, instance: str, verbose: bool = False) -> None:
    for r in summary.results:
        if r.outcome is Outcome.IN_SYNC and not r.not_allowed and not verbose:
            continue
        sym, label, colour = (_PLANNED.get(r.action) if r.outcome is Outcome.PLANNED
                              else _LOOK.get(r.outcome, ("*", r.outcome.value, "")))
        ref = f"{r.kind}/{r.name}"
        shown = ref if (r.aqua_name in (None, r.name)) else f"{ref} ({r.aqua_name!r})"
        out.line(f"{sym} {shown}: {label}", colour)
        if r.plan and r.outcome is not Outcome.CREATED and r.action != "create":
            for text in change_lines(r, instance):
                out.line(f"    {text}")
        for item in r.not_allowed:
            out.line(f"    not allowed: {item}", "red")
        if r.message:
            out.line(f"    {r.message}", "dim")
    out.line(summary.summary_line(), "bold")


def render_json(summary: RunSummary, exit_code: int) -> str:
    def plan_json(r):
        if not r.plan:
            return []
        kind = REGISTRY.get(r.kind)
        out = []
        for c in r.plan.changes:
            mapping, _ = kind.field_map.for_api_path(c.path) if kind else (None, False)
            out.append({"field": mapping.canonical.removeprefix("spec.") if mapping else c.path,
                        "path": c.path, "change": c.change.value,
                        "before": c.before, "after": c.after})
        return out

    return json.dumps({
        "summary": summary.summary_line(),
        "exitCode": exit_code,
        "results": [{
            "kind": r.kind, "name": r.name, "aquaName": r.aqua_name,
            "outcome": r.outcome.value, "action": r.action or None,
            "reason": r.reason or None, "message": r.message or None,
            "changes": plan_json(r), "notAllowed": r.not_allowed,
            "pending": r.pending,
        } for r in summary.results],
    }, indent=2, default=str)


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

def config_root(path: Path) -> Path:
    return path if path.is_dir() else path.parent


def read_config_file(root: Path) -> dict:
    for name in CONFIG_FILENAMES:
        candidate = root / name
        if candidate.is_file():
            try:
                data = yaml.safe_load(candidate.read_text(encoding="utf-8")) or {}
            except yaml.YAMLError as exc:
                raise UsageError(f"{candidate}: invalid YAML: {exc}")
            if not isinstance(data, dict):
                raise UsageError(f"{candidate}: expected a mapping like 'instance: platform'")
            unknown = sorted(set(data) - {"instance"})
            if unknown:
                raise UsageError(f"{candidate}: unknown setting(s) {', '.join(unknown)}; "
                                 "the only setting is 'instance'")
            return data
    return {}


def resolve_instance(flag: str | None, root: Path, env=os.environ) -> str:
    """--instance, then $AQUA_CASC_INSTANCE, then aqua-casc.yaml. Required."""
    value = flag or env.get(ENV_INSTANCE) or read_config_file(root).get("instance")
    if not value:
        raise UsageError(
            f"No instance name. Set it in {root / CONFIG_FILE} ('instance: platform'), "
            f"or pass --instance / set {ENV_INSTANCE}. It is written into every object "
            "this tool manages, so that two repositories on one tenant never treat "
            "each other's objects as their own."
        )
    try:
        return marker.validate_instance(str(value))
    except marker.InvalidInstance as exc:
        raise UsageError(str(exc))


def load_resources(path: Path):
    try:
        result = load_dir(path)
    except (SchemaError, SchemaErrorGroup) as exc:
        raise UsageError(str(exc))
    return result


def default_connect(profile: str | None):
    """Build a live client. Separate so tests can swap it out."""
    from ..client import ConfigError, connect, settings_from_env, settings_from_profile

    try:
        settings = settings_from_profile(profile) if profile else settings_from_env()
        return connect(settings)
    except ConfigError as exc:
        raise UsageError(str(exc))


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #

def cmd_validate(args, out: Out, connect: Callable) -> int:
    path = Path(args.file)
    result = load_resources(path)
    read_config_file(config_root(path))          # validates aqua-casc.yaml if present
    for warning in result.warnings:
        out.line(f"warning: {warning}", "yellow")
    if args.output == "json":
        out.line(json.dumps({"valid": True, "resources": [r.ref for r in result.resources]}, indent=2))
    else:
        out.line(f"{len(result.resources)} resource(s) valid", "green")
    return 0


def _reconcile(args, out: Out, connect: Callable, dry_run: bool) -> int:
    path = Path(args.file)
    instance = resolve_instance(args.instance, config_root(path))
    result = load_resources(path)
    for warning in result.warnings:
        out.line(f"warning: {warning}", "yellow")

    client = connect(args.profile)
    options = Options(instance=instance, dry_run=dry_run, no_delete=args.no_delete,
                      allow_empty=args.allow_empty)
    summary = reconcile_all(result.resources, client, options)

    detailed = True if dry_run else args.detailed_exitcode
    code = summary.exit_code(detailed=detailed)
    if args.output == "json":
        out.line(render_json(summary, code))
    else:
        render_text(summary, out, instance, verbose=args.verbose)
    return code


def cmd_diff(args, out, connect):
    return _reconcile(args, out, connect, dry_run=True)


def cmd_apply(args, out, connect):
    return _reconcile(args, out, connect, dry_run=False)


def cmd_export(args, out: Out, connect: Callable) -> int:
    target = Path(args.out_dir)
    if target.exists() and not target.is_dir():
        raise UsageError(f"{target} exists and is not a directory")
    instance = resolve_instance(args.instance, target)
    client = connect(args.profile)

    kind = REGISTRY["RuntimePolicy"]
    result = exporting.export_kind(client, kind, instance=instance, scope=args.scope,
                                   names=args.name or None)

    existing = [e.filename for e in result.exported if (target / e.filename).exists()]
    if existing and not args.force:
        raise UsageError(
            f"{len(existing)} file(s) already exist in {target} (e.g. {existing[0]}); "
            "refusing to overwrite. Pass --force to replace them."
        )

    target.mkdir(parents=True, exist_ok=True)
    for item in result.exported:
        header = (f"# Exported from Aqua by {NAME}.\n"
                  + ("# Shipped by Aqua: the tool adopts it but never creates or deletes it.\n"
                     if item.shipped else ""))
        body = yaml.safe_dump(item.document, sort_keys=False, default_flow_style=False,
                              allow_unicode=True)
        (target / item.filename).write_text(header + body, encoding="utf-8")

    config_written = False
    if not any((target / n).exists() for n in CONFIG_FILENAMES):
        (target / CONFIG_FILE).write_text(
            f"# {NAME} settings. Commit this file with the configuration.\n"
            f"# The instance name is written into every object this tool manages.\n"
            f"instance: {instance}\n", encoding="utf-8")
        config_written = True

    if args.output == "json":
        out.line(json.dumps({
            "exported": [{"aquaName": e.aqua_name, "file": e.filename, "shipped": e.shipped}
                         for e in result.exported],
            "skipped": [{"aquaName": s.aqua_name, "reason": s.reason} for s in result.skipped],
            "configWritten": config_written,
        }, indent=2))
    else:
        for e in result.exported:
            out.line(f"+ {e.filename}  ({e.aqua_name!r}{', shipped by Aqua' if e.shipped else ''})", "green")
        for s in result.skipped:
            out.line(f"  skipped {s.aqua_name!r}: {s.reason}", "yellow")
        if config_written:
            out.line(f"+ {CONFIG_FILE}  (instance: {instance})", "green")
        out.line(f"{len(result.exported)} exported, {len(result.skipped)} skipped -> {target}", "bold")
        if result.exported:
            out.line(f"Next: commit, then '{NAME} apply -f {target}'. The first apply only adds "
                     "the ownership marker.", "dim")
    return 0


# --------------------------------------------------------------------------- #
# Wiring
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=NAME, allow_abbrev=False,
        description="Config-as-code for Aqua Security: make Aqua match what Git says.",
    )
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    def common(p, needs_files=True):
        if needs_files:
            p.add_argument("-f", "--file", required=True, metavar="PATH",
                           help="config directory (or a single YAML file)")
        p.add_argument("--output", choices=("text", "json"), default="text")
        p.add_argument("--no-color", action="store_true", help="never colour the output")

    def connection(p):
        p.add_argument("--profile", metavar="NAME",
                       help="use a saved aquasec-lib profile instead of AQUA_* variables")
        p.add_argument("--instance", metavar="NAME",
                       help=f"instance name (default: ${ENV_INSTANCE}, then {CONFIG_FILE})")

    p = sub.add_parser("validate", help="check the YAML against the schema (no network)")
    common(p)
    p.set_defaults(handler=cmd_validate)

    for name, handler, help_ in (("diff", cmd_diff, "show what apply would change (read-only)"),
                                 ("apply", cmd_apply, "make Aqua match the YAML")):
        p = sub.add_parser(name, help=help_)
        common(p)
        connection(p)
        p.add_argument("--no-delete", action="store_true",
                       help="report orphaned objects instead of deleting them")
        p.add_argument("--allow-empty", action="store_true",
                       help="allow deletions even when no resources were loaded")
        p.add_argument("-v", "--verbose", action="store_true", help="also list unchanged objects")
        if name == "apply":
            p.add_argument("--detailed-exitcode", action="store_true",
                           help="exit 2 when anything is left pending (drift in ReportOnly, "
                                "blocked objects, orphans kept by --no-delete)")
        p.set_defaults(handler=handler)

    p = sub.add_parser("export", help="write existing Aqua configuration as YAML (read-only)")
    common(p, needs_files=False)
    connection(p)
    p.add_argument("-o", "--out-dir", required=True, metavar="DIR")
    p.add_argument("--scope", required=True, help="application scope to export, e.g. Global")
    p.add_argument("--name", action="append", metavar="PATTERN",
                   help="only objects whose name matches (glob; repeatable)")
    p.add_argument("--force", action="store_true", help="overwrite existing files")
    p.set_defaults(handler=cmd_export)

    return parser


def main(argv: list[str] | None = None, *, stdout: TextIO | None = None,
         stderr: TextIO | None = None, connect: Callable[[str | None], Any] | None = None) -> int:
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    args = build_parser().parse_args(argv)

    colour = (not args.no_color and "NO_COLOR" not in os.environ
              and hasattr(stdout, "isatty") and stdout.isatty())
    out, err = Out(stdout, colour), Out(stderr, colour)

    try:
        return args.handler(args, out, connect or default_connect)
    except UsageError as exc:
        err.line(f"error: {exc}", "red")
        return 1
    except ClientError as exc:
        err.line(f"error: {exc}", "red")
        return 1


def run() -> None:
    """Console-script entry point."""
    sys.exit(main())
