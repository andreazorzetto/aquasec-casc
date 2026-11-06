# aquasec-casc

Config-as-code for Aqua Security: describe Aqua configuration in YAML, keep it
in Git, and make Aqua match it.

```
YAML in Git  ──►  aquasec-casc plan / apply  ──►  Aqua REST API
```

- **Run once and exit.** From a laptop, a CI job, or an Argo CD hook.
- **Stateless.** Ownership is a marker line in each object's description
  (`managed-by: aquasec-casc/<instance>`); there is no state file.
- **The file is the whole policy.** What the YAML leaves out of a policy's controls
  is off, so a control switched on in the console is drift. Settings the tool does
  not cover stay with the console, and each is [listed](docs/schema-reference.md#not-offered).
- **Git-driven deletion**, with guardrails: only this instance's objects, never
  Aqua's own, never for a kind with no files in the run, never while a file of that
  kind has failed, and never when given a single file.
- **It checks what it wrote.** Aqua silently drops fields it does not know, and
  versions differ, so `apply` reads each object back and fails if a field was not kept.

Supported: **runtime policies** (container, host, function) and **assurance policies**
(image, host, function, Kubernetes, VMware Tanzu). Every control has been
[written and read back](tests/integration/test_every_field.py) against live SaaS and
self-hosted tenants: see [what it was tested against](docs/schema-reference.md#tested-against).

## A policy

```yaml
apiVersion: config.aquasec.com/v1alpha1
kind: RuntimePolicy
metadata:
  name: prod-baseline
spec:
  enforce: true
  applicationScopes: [AccProd]
  controls:
    blockNonCompliantImages: true
    blockContainerExec: true
    driftPrevention:
      allowedProcesses: ["redis-*"]
```

```
$ aquasec-casc plan -f aqua/policies
~ RuntimePolicy/prod-baseline: will be updated
    ! controls.blockNonCompliantImages: false -> true   (API: block_disallowed_images)
0 unchanged, 0 created, 0 updated, 0 adopted, 0 deleted, 1 planned
```

## Quick start

[docs/try-it.md](docs/try-it.md) is a fifteen-minute guided tour against your own
tenant, using the safe playground in [examples/playground](examples/playground).

```sh
python3 -m venv .venv && .venv/bin/pip install .     # Python 3.11+
source .venv/bin/activate

export AQUA_URL=https://aqua.internal.example        # self-hosted Aqua
export AQUA_USER=... AQUA_PASSWORD=...
export AQUA_CA_BUNDLE=/path/to/internal-ca.pem       # if it has an internal CA

aquasec-casc validate -f examples/playground         # no network
aquasec-casc plan -f examples/playground             # read-only
```

Or run the image, which is what CI and Argo CD do:

```sh
docker run --rm --read-only -v "$PWD/examples/playground:/config:ro" \
  -e AQUA_URL -e AQUA_USER -e AQUA_PASSWORD \
  andreazorzetto/aquasec-casc:0.1.0 plan -f /config
```

With an internal CA, add `-v "$PWD/internal-ca.pem:/ca.pem:ro" -e AQUA_CA_BUNDLE=/ca.pem`.

## Configure

Credentials come from a saved profile or the environment -- never from a file
in the repo. In order: `--profile NAME`; `AQUA_*` variables if any are set (see
[.env.example](.env.example)), which is what CI and Argo CD use, and an incomplete set
is an error rather than a fallback; the default profile. Profiles are shared with the other aquasec tools:

```sh
aquasec-casc setup [NAME]                  # interactive; tests the connection, saves encrypted
aquasec-casc profile list | show [NAME] | set-default NAME | delete NAME
```

Profiles are for a person's laptop: they are encrypted with a key kept beside them, so
treat them as you would a password in your home directory. CI and Argo CD use the
variables, from their own secret stores.

The **instance name** goes in `aquasec-casc.yaml` at the root of the config
folder (`instance: platform`), or `--instance` / `$AQUASEC_CASC_INSTANCE`.

TLS is verified by default, and the tool refuses `http://` addresses and redirects, so
credentials go only where you pointed them. Point `AQUA_CA_BUNDLE` at an internal CA.
`AQUA_TLS_INSECURE=true` turns off certificate checks and allows `http://`, and the
password goes over that connection with it, so keep it to throwaway labs.

## Commands

| Command | |
|---|---|
| `validate -f DIR` | Check the YAML against the schema. No network. |
| `plan -f DIR` | Show what `apply` would change. Read-only. |
| `apply -f DIR` | Make Aqua match the YAML. `--no-delete` holds back deletions. |
| `export --scope S -o DIR` | Write existing configuration as YAML, ready to adopt. Read-only. |
| `release` | Stop managing all this instance's objects, or those `--name` picks, without deleting them; `--to` hands them over. |
| `destroy [-f DIR]` | Delete what the files describe, or everything this instance manages. Asks first. |
| `schema KIND` | Print a kind's JSON Schema, for editors and CI. |
| `setup`, `profile` | Save and manage credential profiles. |

Exit codes follow Terraform: 0 success, 1 error; `--detailed-exitcode` adds 2 when
`plan` or `apply` leaves changes pending. `--output json` on everything that talks to Aqua.

## Documentation

| | |
|---|---|
| [docs/argocd.md](docs/argocd.md) | **Setting it up in Argo CD**, and mirroring the image into an air-gapped registry |
| [docs/adoption.md](docs/adoption.md) | Bringing an already configured tenant under management |
| [docs/try-it.md](docs/try-it.md) | A guided tour against your own tenant |
| [docs/demo.md](docs/demo.md) | The demo: from export to drift correction, with exact commands |
| [docs/schema-reference.md](docs/schema-reference.md) | Every field, its API name, and what is not offered and why |
| [docs/schema-examples.md](docs/schema-examples.md) | The YAML in use |
| [docs/architecture.md](docs/architecture.md) | How it works, and why |
| [examples/github-actions](examples/github-actions) | A GitHub Actions workflow: plan on a pull request, apply on merge |

## Limits, plainly

- **It corrects drift when it runs, and at no other time.** A console change stays
  until the next run. Schedule the run if that gap matters; closing it properly is what
  an operator would do, and that is a later phase.
- **A rename is a delete and a create**, because Aqua has no rename. Creates run before
  deletes, and a failed create holds the delete back, so a policy is never left with
  neither.
- **Field support varies by Aqua version.** A field a version does not keep is reported at
  `apply`, not guessed at. A field it keeps but does not act on cannot be seen from the API,
  so try a new control on your own version first. See
  [what it was tested against](docs/schema-reference.md#tested-against).
- **One Aqua instance per run**, and no scheduling of its own.

## Roadmap

Enforcer groups, with the registration token kept out of logs and Git; application
scopes; a Kubernetes operator with these same objects as CRDs, for continuous
correction. Users, roles, registries, notifications and response policies are not
planned, and neither is parity with the Terraform provider.

## Licence

MIT. See [LICENSE](LICENSE).
