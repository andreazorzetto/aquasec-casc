"""Layer 3 -- the CLI. Run once and exit.

Thin on purpose: it loads files, connects, calls the reconciler, renders the
result and picks an exit code. Everything that decides *what* happens lives in
the reconciler, so the phase 2 operator can reuse it unchanged.

Exit codes:
  validate  0 valid, 1 invalid
  plan      0 success, 1 error; 2 when changes are pending, only with
            --detailed-exitcode (as terraform plan)
  apply     0 done, 1 error; 2 when something is left pending, only with
            --detailed-exitcode (Argo CD fails a sync on any non-zero exit)
  export    0 done, 1 error, or an object left out because it does not fit the schema
  release   0 done (or nothing to release), 1 error
  destroy   0 done (or nothing to destroy), 1 error or not confirmed
  schema, setup, profile   0 done, 1 error

Credentials: --profile, else AQUA_* variables, else the default saved profile.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Callable, TextIO

import yaml

from . import NAME
from .. import export as exporting
from ..reconcile import (DestroyOptions, Options, Outcome, ReleaseOptions, RunSummary,
                         destroy_all, marker, reconcile_all, release_all)
from ..reconcile.client import ClientError
from ..schema import SchemaError, SchemaErrorGroup, load_dir
from ..schema.loader import CONFIG_FILENAMES, StrictLoader
from ..schema.registry import REGISTRY

CONFIG_FILE = CONFIG_FILENAMES[0]
ENV_INSTANCE = "AQUASEC_CASC_INSTANCE"


class UsageError(Exception):
    """A problem with how the tool was invoked or configured. Exit 1."""


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #

_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


class Out:
    """Writes text, coloured only when it goes to a terminal."""

    COLOURS = {"green": "32", "yellow": "33", "red": "31", "cyan": "36", "dim": "2", "bold": "1"}

    def __init__(self, stream: TextIO, colour: bool, notes: "Out | None" = None) -> None:
        self.stream = stream
        self.colour = colour
        self.notes = notes or self
        """Where warnings and questions go: not standard output, which may be JSON."""

    def paint(self, text: str, colour: str) -> str:
        if not self.colour or colour not in self.COLOURS:
            return text
        return f"\033[{self.COLOURS[colour]}m{text}\033[0m"

    def line(self, text: str = "", colour: str = "") -> None:
        # Names and messages come from the server: no terminal control through them.
        text = _CONTROL.sub("?", text)
        print(self.paint(text, colour) if colour else text, file=self.stream)


_LOOK = {
    Outcome.IN_SYNC: ("=", "unchanged", "dim"),
    Outcome.CREATED: ("+", "created", "green"),
    Outcome.UPDATED: ("~", "updated", "yellow"),
    Outcome.ADOPTED: ("~", "adopted", "cyan"),
    Outcome.DELETED: ("-", "deleted", "red"),
    Outcome.RELEASED: ("~", "released", "cyan"),
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
    "release": ("~", "will be released", "cyan"),
    "hand-over": ("~", "will be handed over", "cyan"),
}

#: Reads the destroy confirmation. Module-level so tests can replace it.
ask = input


def stdin_is_terminal() -> bool:
    return sys.stdin.isatty()


def _one_line(text: str | None) -> str:
    """Server text on one line: a newline in a name could forge a line of output."""
    return " ".join(str(text).splitlines()) if text else ""


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


def render_text(summary: RunSummary, out: Out, instance: str, verbose: bool = False,
                line: str | None = None) -> None:
    for r in summary.results:
        if r.outcome is Outcome.IN_SYNC and not r.not_allowed and not verbose:
            continue
        if r.outcome is Outcome.PLANNED:
            sym, label, colour = _PLANNED.get(r.action)
        elif r.outcome is Outcome.RELEASED and r.action == "hand-over":
            sym, label, colour = ("~", "handed over", "cyan")
        else:
            sym, label, colour = _LOOK.get(r.outcome, ("*", r.outcome.value, ""))
        ref = f"{r.kind}/{_one_line(r.name)}"
        shown = ref if (r.aqua_name in (None, r.name)) else f"{ref} ({_one_line(r.aqua_name)!r})"
        out.line(f"{sym} {shown}: {label}", colour)
        if r.plan and r.outcome is not Outcome.CREATED and r.action != "create":
            for text in change_lines(r, instance):
                out.line(f"    {text}")
        for item in r.not_allowed:
            out.line(f"    not allowed: {item}", "red")
        for item in r.not_kept:
            out.line(f"    not kept by Aqua: {item}", "red")
        if r.message:
            out.line(f"    {_one_line(r.message)}", "dim")
    out.line(line or summary.summary_line(), "bold")


def render_json(summary: RunSummary, exit_code: int, line: str | None = None) -> str:
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
        "summary": line or summary.summary_line(),
        "exitCode": exit_code,
        "results": [{
            "kind": r.kind, "name": r.name, "aquaName": r.aqua_name,
            "outcome": r.outcome.value, "action": r.action or None,
            "reason": r.reason or None, "message": r.message or None,
            "changes": plan_json(r), "notAllowed": r.not_allowed, "notKept": r.not_kept,
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
                data = yaml.load(candidate.read_text(encoding="utf-8"), Loader=StrictLoader) or {}
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
    """--instance, then $AQUASEC_CASC_INSTANCE, then aquasec-casc.yaml. Required."""
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


def _given(path: str) -> Path:
    """A path the user gave. An empty one is an unset variable, and "" reads as the
    current directory, or in ``destroy`` as "everything", so it is refused."""
    if not path.strip():
        raise UsageError("-f is empty. Is the variable that should hold the path set?")
    return Path(path)


def load_resources(path: Path):
    try:
        result = load_dir(path)
    except (SchemaError, SchemaErrorGroup) as exc:
        raise UsageError(str(exc))
    return result


def default_connect(profile: str | None):
    """Build a live client. Separate so tests can swap it out.

    Says on stderr which credentials it used, so stdout stays clean for
    ``--output json`` and a run never silently acts as an unexpected identity.
    """
    from ..client import ConfigError, connect, resolve_settings

    try:
        settings = resolve_settings(profile)
        print(f"Using {settings.source}.", file=sys.stderr)
        if settings.verify is False:
            print("warning: TLS verification is off (AQUA_TLS_INSECURE): the password goes "
                  "over a connection nothing has verified.", file=sys.stderr)
        return connect(settings)
    except ConfigError as exc:
        raise UsageError(str(exc))


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #

def cmd_validate(args, out: Out, connect: Callable) -> int:
    path = _given(args.file)
    result = load_resources(path)
    instance = read_config_file(config_root(path)).get("instance")      # checks the file too
    if instance is not None:
        try:
            marker.validate_instance(str(instance))
        except marker.InvalidInstance as exc:
            raise UsageError(f"{CONFIG_FILE}: {exc}")
    for warning in result.warnings:
        out.notes.line(f"warning: {warning}", "yellow")
    if args.output == "json":
        out.line(json.dumps({"valid": True, "resources": [r.ref for r in result.resources]}, indent=2))
    else:
        out.line(f"{len(result.resources)} resource(s) valid", "green")
    return 0


def _reconcile(args, out: Out, connect: Callable, dry_run: bool) -> int:
    path = _given(args.file)
    instance = resolve_instance(args.instance, config_root(path))
    result = load_resources(path)
    for warning in result.warnings:
        out.notes.line(f"warning: {warning}", "yellow")

    client = connect(args.profile)
    # One file is part of the configuration: the rest has no file in this run, and
    # that does not mean it should go.
    options = Options(instance=instance, dry_run=dry_run, no_delete=args.no_delete,
                      allow_empty=args.allow_empty, scan_orphans=not path.is_file())
    summary = reconcile_all(result.resources, client, options)

    detailed = args.detailed_exitcode
    code = summary.exit_code(detailed=detailed)
    if args.output == "json":
        out.line(render_json(summary, code))
    else:
        render_text(summary, out, instance, verbose=args.verbose)
    return code


def cmd_plan(args, out, connect):
    return _reconcile(args, out, connect, dry_run=True)


def cmd_apply(args, out, connect):
    return _reconcile(args, out, connect, dry_run=False)


def cmd_export(args, out: Out, connect: Callable) -> int:
    target = _given(args.out_dir)
    if target.exists() and not target.is_dir():
        raise UsageError(f"{target} exists and is not a directory")
    instance = resolve_instance(args.instance, target)
    client = connect(args.profile)

    result = exporting.ExportResult()
    for kind in REGISTRY.values() if not args.kind else (REGISTRY[args.kind],):
        part = exporting.export_kind(client, kind, instance=instance, scope=args.scope,
                                     names=args.name or None)
        result.exported.extend(part.exported)
        result.skipped.extend(part.skipped)
        result.left_outside.extend(part.left_outside)

    linked = [e.filename for e in result.exported if (target / e.filename).is_symlink()]
    if linked:
        raise UsageError(f"{target / linked[0]} is a symbolic link; refusing to write through it.")
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
    if not any((target / n).exists() or (target / n).is_symlink() for n in CONFIG_FILENAMES):
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
            "leftOutside": result.left_outside,
            "leftOut": {e.aqua_name: e.left_out for e in result.exported if e.left_out},
            "configWritten": config_written,
        }, indent=2))
    else:
        for e in result.exported:
            out.line(f"+ {e.filename}  ({e.aqua_name!r}{', shipped by Aqua' if e.shipped else ''})", "green")
        for s in result.skipped:
            out.line(f"  skipped {_one_line(s.aqua_name)!r}: {_one_line(s.reason)}", "yellow")
        for e in result.exported:
            for path in e.left_out:
                out.line(f"  {e.aqua_name!r}: {path} is on in Aqua and does nothing on this type; "
                         "left out, so the first apply switches it off", "yellow")
        if config_written:
            out.line(f"+ {CONFIG_FILE}  (instance: {instance})", "green")
        out.line(f"{len(result.exported)} exported, {len(result.skipped)} skipped -> {target}", "bold")
        if result.exported and not result.skipped_for_schema():
            out.line(f"Next: commit, then '{NAME} apply -f {target}'. The first apply only adds "
                     "the ownership marker.", "dim")
    if result.left_outside:
        out.notes.line(f"warning: {len(result.left_outside)} object(s) this instance manages are "
                       f"outside --scope or --name, so have no file here, and an apply of this "
                       f"folder deletes them: {', '.join(result.left_outside)}", "yellow")
    # No file for an object means deleting it, if this instance owns it, so an
    # export that left one out has not done its job.
    if result.skipped_for_schema():
        raise UsageError("objects were left out because they do not fit the schema. If this "
                         "instance manages them, an apply of this folder deletes them: stop "
                         f"managing them first with '{NAME} release --name NAME', and they stay "
                         "with the console.")
    return 0


def cmd_release(args, out: Out, connect: Callable) -> int:
    instance = resolve_instance(args.instance, config_root(_given(args.file)))
    to = None
    if args.to is not None:
        try:
            to = marker.validate_instance(args.to)
        except marker.InvalidInstance as exc:
            raise UsageError(f"--to: {exc}")
        if to == instance:
            raise UsageError(f"--to {to!r} is this instance already; nothing to hand over")

    client = connect(args.profile)
    summary = release_all(client, ReleaseOptions(
        instance=instance, to=to, names=tuple(args.name or ()), dry_run=args.dry_run))

    count = len(summary.of(Outcome.PLANNED if args.dry_run else Outcome.RELEASED))
    verb = ("to hand over" if to else "to release") if args.dry_run else (
        "handed over" if to else "released")
    line = f"{count} {verb}"
    if summary.failed:
        line += f", {len(summary.failed)} failed"
    code = summary.exit_code(detailed=False)

    if args.output == "json":
        out.line(render_json(summary, code, line))
        return code

    if not summary.results:
        out.line(f"Nothing to release: no object carries '{marker.marker(instance)}'"
                 + (" and matches --name." if args.name else "."), "bold")
        return code
    render_text(summary, out, instance, line=line)
    if count:
        lead = "Afterwards" if args.dry_run else "Next"
        if to:
            out.line(f"{lead}: move these objects' files to the '{to}' configuration and remove "
                     f"them here. Until then, applies from '{instance}' report them as blocked.",
                     "dim")
        else:
            out.line(f"{lead}: remove these objects' files from Git, or stop the pipeline. "
                     "While they remain, the next apply adopts the objects again.", "dim")
    return code


def cmd_destroy(args, out: Out, connect: Callable) -> int:
    """Show the plan, confirm, then delete -- or release what Aqua ships."""
    if args.file is not None:
        path = _given(args.file)
        instance = resolve_instance(args.instance, config_root(path))
        loaded = load_resources(path)
        for warning in loaded.warnings:
            out.notes.line(f"warning: {warning}", "yellow")
        resources = tuple(loaded.resources)
    else:
        instance = resolve_instance(args.instance, Path("."))
        resources = None

    client = connect(args.profile)
    options = DestroyOptions(instance=instance, resources=resources,
                             names=tuple(args.name or ()), dry_run=True)
    plan = destroy_all(client, options)

    def counts(summary, dry):
        n_del = sum(1 for r in summary.results if (r.action == "delete" and dry)
                    or (r.outcome is Outcome.DELETED and not dry))
        n_rel = sum(1 for r in summary.results if r.action == "release"
                    and r.outcome is (Outcome.PLANNED if dry else Outcome.RELEASED))
        parts = [f"{n_del} {'to destroy' if dry else 'destroyed'}"]
        if n_rel:
            parts.append(f"{n_rel} {'to release' if dry else 'released'}")
        for outcome, label in ((Outcome.BLOCKED, "blocked"), (Outcome.FAILED, "failed")):
            if summary.of(outcome):
                parts.append(f"{len(summary.of(outcome))} {label}")
        return n_del + n_rel, ", ".join(parts)

    todo, line = counts(plan, dry=True)
    what = f"the objects described in {args.file}" if args.file else \
        f"every object carrying '{marker.marker(instance)}'"

    if args.output == "json" and (args.dry_run or not todo):
        out.line(render_json(plan, plan.exit_code(detailed=False), line))
        return plan.exit_code(detailed=False)
    if args.output != "json":
        if not todo and not plan.blocked_or_failed():
            where = (f"none of the objects described in {args.file} exist in Aqua" if args.file
                     else f"no object carries '{marker.marker(instance)}'")
            out.line(f"Nothing to destroy: {where}"
                     + (" (with --name)." if args.name else "."), "bold")
            return 0
        render_text(plan, out, instance, line=line)
    if args.dry_run or not todo:
        return plan.exit_code(detailed=False)

    if not args.yes:
        if not stdin_is_terminal():
            raise UsageError("destroy needs confirmation: run it in a terminal, or pass --yes.")
        out.notes.line(f"This deletes {what} owned by instance '{instance}'. It cannot be undone.",
                       "red")
        if ask(f"Type the instance name ({instance}) to confirm: ").strip() != instance:
            out.notes.line("Destroy cancelled. Nothing was changed.", "bold")
            return 1

    done = destroy_all(client, DestroyOptions(instance=instance, resources=resources,
                                              names=tuple(args.name or ()), dry_run=False))
    code = done.exit_code(detailed=False)
    _, line = counts(done, dry=False)
    if args.output == "json":
        out.line(render_json(done, code, line))
        return code
    out.line()
    render_text(done, out, instance, line=line)
    if done.of(Outcome.DELETED):
        out.line(("Next: remove these files from Git, or stop the pipeline. While they remain, "
                  "the next apply recreates the objects.") if args.file else
                 (f"Next: stop any pipeline that applies instance '{instance}'. Its next apply "
                  "recreates whatever its files describe."), "dim")
    return code


def cmd_schema(args, out: Out, connect: Callable) -> int:
    """JSON Schema, for editors and for checking YAML in CI without this tool."""
    from ..schema import jsonschema
    out.line(json.dumps(jsonschema.for_kind(args.kind), indent=2))
    return 0


def cmd_setup(args, out: Out, connect: Callable) -> int:
    from ..client import profiles
    return 0 if profiles.setup(args.name) else 1


def _profile_lines(info: dict) -> list[str]:
    lines = [f"Profile:        {info['name']}{'  (default)' if info.get('is_default') else ''}",
             f"Authentication: {info.get('auth_method', 'unknown')}",
             f"Console URL:    {info.get('csp_endpoint') or '-'}"]
    if info.get("api_endpoint"):
        lines.append(f"API endpoint:   {info['api_endpoint']}")
    ref = info.get("credentials_ref")
    lines.append(f"Credentials:    {'present (ref ' + ref + ')' if ref else 'missing'}")
    return lines


def cmd_profile(args, out: Out, connect: Callable) -> int:
    from ..client import profiles
    as_json = args.output == "json"

    if args.action == "list":
        infos = profiles.all_info()
        if as_json:
            out.line(json.dumps(infos, indent=2))
        elif not infos:
            out.line(f"No saved profiles. Create one with '{NAME} setup'.")
        else:
            width = max(len(i["name"]) for i in infos)
            out.line(f"  {'PROFILE'.ljust(width)}  {'AUTH'.ljust(9)}  CONSOLE", "bold")
            for i in infos:
                mark = "*" if i.get("is_default") else " "
                out.line(f"{mark} {i['name'].ljust(width)}  {str(i.get('auth_method')).ljust(9)}  "
                         f"{i.get('csp_endpoint') or '-'}")
            out.line("* default: used when neither --profile nor AQUA_* credentials are given",
                     "dim")
        return 0

    if args.action == "show":
        info = profiles.info(args.name)
        if info is None:
            raise UsageError(f"No saved profile {args.name or profiles.default_name()!r}. "
                             f"See '{NAME} profile list'.")
        out.line(json.dumps(info, indent=2) if as_json else "\n".join(_profile_lines(info)))
        return 0

    known = {i["name"] for i in profiles.all_info()}
    if args.name not in known:
        raise UsageError(f"No saved profile {args.name!r}. See '{NAME} profile list'.")
    result = (profiles.delete(args.name) if args.action == "delete"
              else profiles.set_default(args.name))
    if not result.get("success"):
        raise UsageError(f"{args.action} {args.name!r} failed: {result.get('error') or 'unknown error'}")
    if as_json:
        out.line(json.dumps(result, indent=2))
    else:
        out.line(f"Deleted profile {args.name!r}." if args.action == "delete"
                 else f"{args.name!r} is now the default profile.", "green")
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
                           help="config directory, or a single YAML file (one file deletes nothing)")
        p.add_argument("--output", choices=("text", "json"), default="text")
        p.add_argument("--no-color", action="store_true", help="never colour the output")

    def connection(p, ignored=False):
        note = " (accepted and ignored: validate never connects)" if ignored else ""
        p.add_argument("--profile", metavar="NAME",
                       help="saved profile to use (default: AQUA_* variables if set, "
                            "else the default profile)" + note)
        p.add_argument("--instance", metavar="NAME",
                       help=f"instance name (default: ${ENV_INSTANCE}, then {CONFIG_FILE})"
                            + note)

    p = sub.add_parser("validate", help="check the YAML against the schema (no network)")
    common(p)
    # Accepted so that 'diff ... --profile X' can become 'validate ... --profile X'
    # by changing one word.
    connection(p, ignored=True)
    p.set_defaults(handler=cmd_validate)

    for name, handler, help_ in (("plan", cmd_plan, "show what apply would change (read-only)"),
                                 ("apply", cmd_apply, "make Aqua match the YAML")):
        p = sub.add_parser(name, help=help_)
        common(p)
        connection(p)
        p.add_argument("--no-delete", action="store_true",
                       help="report orphaned objects instead of deleting them")
        p.add_argument("--allow-empty", action="store_true",
                       help="allow deletions even when no resources were loaded")
        p.add_argument("-v", "--verbose", action="store_true", help="also list unchanged objects")
        p.add_argument("--detailed-exitcode", action="store_true",
                       help="exit 2 when anything is (or is left) pending: changes to make, "
                            "drift in ReportOnly, blocked objects, orphans kept by --no-delete")
        p.set_defaults(handler=handler)

    p = sub.add_parser("export", help="write existing Aqua configuration as YAML (read-only)")
    common(p, needs_files=False)
    connection(p)
    p.add_argument("-o", "--out-dir", required=True, metavar="DIR")
    p.add_argument("--scope", required=True, help="application scope to export, e.g. Global")
    p.add_argument("--kind", choices=sorted(REGISTRY),
                   help="export only this kind (default: all of them)")
    p.add_argument("--name", action="append", metavar="PATTERN",
                   help="only objects whose name matches (glob; repeatable)")
    p.add_argument("--force", action="store_true", help="overwrite existing files")
    p.set_defaults(handler=cmd_export)

    p = sub.add_parser(
        "release", help="stop managing objects without deleting them (removes the marker)",
        description=("Remove this instance's ownership marker from the objects it manages, "
                     "changing nothing else, so they are left exactly as they are. With "
                     "--to, hand them to another instance instead. Needs no YAML: objects "
                     "are found by their marker."))
    common(p, needs_files=False)
    connection(p)
    p.add_argument("-f", "--file", default=".", metavar="PATH",
                   help=f"where to look for {CONFIG_FILE} for the instance name "
                        "(default: the current directory)")
    p.add_argument("--name", action="append", metavar="PATTERN",
                   help="only objects whose Aqua name matches (glob; repeatable)")
    p.add_argument("--to", metavar="INSTANCE",
                   help="hand the objects over to this instance instead of releasing them")
    p.add_argument("--dry-run", action="store_true", help="show what would be released")
    p.set_defaults(handler=cmd_release)

    p = sub.add_parser(
        "destroy", help="delete what this instance manages (asks for confirmation)",
        description=("Delete the objects the files in PATH describe -- or, without -f, every "
                     "object carrying this instance's marker. Only objects this instance "
                     "manages are touched; policies Aqua ships cannot be deleted and are "
                     "released instead."))
    common(p, needs_files=False)
    connection(p)
    p.add_argument("-f", "--file", metavar="PATH",
                   help="destroy what these files describe (default: everything this "
                        "instance manages)")
    p.add_argument("--name", action="append", metavar="PATTERN",
                   help="only objects whose Aqua name matches (glob; repeatable)")
    p.add_argument("--dry-run", action="store_true", help="show what would be destroyed")
    p.add_argument("--yes", action="store_true",
                   help="do not ask for confirmation (for scripts)")
    p.set_defaults(handler=cmd_destroy)

    p = sub.add_parser("schema", help="print a kind's JSON Schema, for editors and CI (no network)")
    p.add_argument("kind", choices=sorted(REGISTRY))
    p.add_argument("--no-color", action="store_true", help=argparse.SUPPRESS)
    p.set_defaults(handler=cmd_schema, output="json")

    p = sub.add_parser("setup", help="save credentials as a profile (interactive)",
                       description="The aquasec-lib setup wizard: asks for the connection "
                                   "details, tests them, and saves them encrypted in ~/.aqua. "
                                   "The same profiles the other aquasec tools use.")
    p.add_argument("name", nargs="?", help="profile name (asked for if omitted)")
    p.add_argument("--no-color", action="store_true", help=argparse.SUPPRESS)
    p.set_defaults(handler=cmd_setup, output="text")

    p = sub.add_parser("profile", help="list, show, delete saved profiles, or set the default")
    actions = p.add_subparsers(dest="action", required=True, metavar="ACTION")
    for action, help_, name_arg in (
            ("list", "list saved profiles", None),
            ("show", "show one profile (default: the default profile); never shows secrets", "?"),
            ("delete", "delete a saved profile", 1),
            ("set-default", "make a profile the default", 1)):
        a = actions.add_parser(action, help=help_)
        if name_arg == "?":
            a.add_argument("name", nargs="?")
        elif name_arg:
            a.add_argument("name")
        a.add_argument("--output", choices=("text", "json"), default="text")
        a.add_argument("--no-color", action="store_true", help="never colour the output")
        a.set_defaults(handler=cmd_profile)

    return parser


def main(argv: list[str] | None = None, *, stdout: TextIO | None = None,
         stderr: TextIO | None = None, connect: Callable[[str | None], Any] | None = None) -> int:
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    args = build_parser().parse_args(argv)

    colour = (not args.no_color and "NO_COLOR" not in os.environ
              and hasattr(stdout, "isatty") and stdout.isatty())
    err = Out(stderr, colour)
    out = Out(stdout, colour, notes=err)

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
