# aquasec-casc

Config-as-code for Aqua Security: describe Aqua configuration in YAML, keep it
in Git, and make Aqua match it.

```
YAML in Git  ──►  aquasec-casc plan / apply  ──►  Aqua REST API
```

- **Run once and exit.** From a laptop, a CI job, or an Argo CD PreSync hook.
- **Stateless.** Ownership is a marker line in each object's description
  (`managed-by: aquasec-casc/<instance>`); there is no state file.
- **Owns only what the YAML says.** Fields the YAML leaves out stay with the
  console.
- **Git-driven deletion**, with guardrails: only this instance's objects, never
  Aqua's own, never on an empty run.

Supported today: **runtime policies**.

## Try it

[docs/try-it.md](docs/try-it.md) is a fifteen-minute guided tour against your
own tenant, using the safe playground in [examples/playground](examples/playground).

## Install

```sh
python3 -m venv .venv && .venv/bin/pip install -e .
```

Python 3.11+. Talks to Aqua through [aquasec-lib](https://pypi.org/project/aquasec/).

## Configure

Credentials come from a saved profile or the environment -- never from a file
in the repo. In order: `--profile NAME`; `AQUA_*` variables if any are set (see
[.env.example](.env.example)), which is what CI and Argo CD use; the default
profile. Profiles are shared with the other aquasec tools:

```sh
aquasec-casc setup [NAME]                  # interactive; tests the connection, saves encrypted
aquasec-casc profile list | show [NAME] | set-default NAME | delete NAME
```

The **instance name** goes in `aquasec-casc.yaml` at the root of the config
folder (`instance: platform`), or `--instance` / `$AQUASEC_CASC_INSTANCE`.

## Commands

| Command | |
|---|---|
| `validate -f DIR` | Check the YAML against the schema. No network. |
| `plan -f DIR` | Show what `apply` would change. Read-only. |
| `apply -f DIR` | Make Aqua match the YAML. `--no-delete` holds back deletions. |
| `export --scope S -o DIR` | Write existing configuration as YAML, ready to adopt. Read-only. |
| `release` | Stop managing objects without deleting them; `--to` hands them over. |
| `destroy [-f DIR]` | Delete what the files describe, or everything this instance manages. Asks first. |
| `setup`, `profile` | Save and manage credential profiles. |

## Documentation

- [docs/try-it.md](docs/try-it.md): guided tour
- [docs/schema-examples.md](docs/schema-examples.md): the YAML, field by field
- [docs/architecture.md](docs/architecture.md): how it works, and why
