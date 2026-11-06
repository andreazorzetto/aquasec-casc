# Config as Code for Aqua Security

**Keep your Aqua policies in Git. Review every change in a pull request. Apply it from Argo CD, CI or a laptop.**

[![CI](https://github.com/andreazorzetto/aquasec-casc/actions/workflows/ci.yml/badge.svg)](https://github.com/andreazorzetto/aquasec-casc/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/andreazorzetto/aquasec-casc)](https://github.com/andreazorzetto/aquasec-casc/releases/latest)
[![Image](https://img.shields.io/docker/v/andreazorzetto/aquasec-casc?sort=semver&label=image)](https://hub.docker.com/r/andreazorzetto/aquasec-casc)
[![Licence](https://img.shields.io/github/license/andreazorzetto/aquasec-casc)](LICENSE)

`aquasec-casc` reads policies from YAML, shows what would change, and makes Aqua match. It runs once and exits, and keeps no state.

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

## Why use it

- **Start from what you have.** `export` writes your existing policies as YAML, and the first `apply` adds only an ownership marker.
- **Git is the source of truth.** A control the file leaves out is off, a console change is drift, and removing a file deletes the policy.
- **Deleting is guarded.** It only touches policies this instance owns, never Aqua's own, and holds back if anything looks wrong.
- **It checks what it wrote.** Aqua silently drops fields it does not know, so `apply` reads each policy back and fails if a field was not kept.
- **Built for air gaps.** One image with every dependency pinned, running as non-root on a read-only filesystem, talking only to the Aqua API.

Supports **runtime policies** (container, host, function) and **assurance policies** (image, host, function, Kubernetes, VMware Tanzu).

## Quick start

```sh
git clone https://github.com/andreazorzetto/aquasec-casc.git && cd aquasec-casc
python3 -m venv .venv && source .venv/bin/activate
pip install .                                    # Python 3.11+

export AQUA_URL=https://aqua.internal.example    # your console
export AQUA_USER=... AQUA_PASSWORD=...

aquasec-casc validate -f examples/playground     # no network
aquasec-casc plan -f examples/playground         # read-only
```

If your console uses an internal CA, also set `AQUA_CA_BUNDLE=/path/to/ca.pem`. On SaaS, run `aquasec-casc setup` instead of setting the variables.

Or use the image, as CI and Argo CD do:

```sh
docker run --rm --read-only -v "$PWD/examples/playground:/config:ro" \
  -e AQUA_URL -e AQUA_USER -e AQUA_PASSWORD \
  andreazorzetto/aquasec-casc:0.1.0 plan -f /config
```

## Where next

| I want to... | Read |
|---|---|
| **Run it from Argo CD**, and mirror the image into an air gap | [Argo CD setup](docs/argocd.md) |
| Bring an existing tenant under management | [Adopting existing policies](docs/adoption.md) |
| Try every command safely, in about 15 minutes | [Guided tour](docs/try-it.md) |
| Write my own policies | [Writing policies](docs/writing-policies.md) |
| Look up a field, or see why one is not offered | [Schema reference](docs/schema-reference.md) |
| Understand the rules behind what it does | [How it works](docs/how-it-works.md) |
| Run it from GitHub Actions | [Example workflow](examples/github-actions/aquasec-casc.yml) |

## Commands

| Command | |
|---|---|
| `validate -f DIR` | Check the YAML. No network. |
| `plan -f DIR` | Show what `apply` would change. Read-only. |
| `apply -f DIR` | Make Aqua match the YAML. `--no-delete` holds back deletions. |
| `export --scope S -o DIR` | Write existing policies as YAML. Read-only. |
| `release` | Stop managing policies, without deleting them. |
| `destroy [-f DIR]` | Delete what this instance manages. Asks first. |
| `schema KIND` | Print a kind's JSON Schema, for editors and CI. |
| `setup`, `profile` | Save and manage credential profiles. |

Exit codes are 0 for success and 1 for an error, and `--detailed-exitcode` adds 2 when changes are pending. `--output json` works on everything that talks to Aqua.

## Configuration

**Instance name.** Each configuration folder has an `aquasec-casc.yaml` holding `instance: platform`. The name marks policies as this configuration's own, so two teams on one tenant cannot overwrite each other.

**Credentials** never go in the repo. The tool takes them from, in order:

1. `--profile NAME`: a profile saved with `aquasec-casc setup`, for a person's laptop. Its key is kept beside it, so treat it like a password in your home directory.
2. `AQUA_*` variables, for CI and Argo CD: see [.env.example](.env.example).
3. The default profile.

**TLS** is verified, and `http://` addresses and redirects are refused. `AQUA_TLS_INSECURE=true` turns that off, and sends the password over that connection, so keep it to throwaway labs.

## Limits

- **It corrects drift only when it runs.** A console change stays until the next run, so schedule one if that gap matters.
- **A rename is a delete and a create**, because Aqua has no rename. A failed create holds the delete back.
- **Versions differ.** A field your Aqua does not keep fails the `apply`. One it keeps but ignores cannot be seen from the API, so try new controls on your version first. See [what was tested](docs/schema-reference.md#tested-against).
- **Application scopes cannot be excluded.** `excludeApplicationScopes` is [not offered](docs/schema-reference.md#not-offered). If Aqua holds one, it stays, with a warning.

## Roadmap

Next are enforcer groups and application scopes, then a Kubernetes operator using these same objects as CRDs, for continuous correction. Users, roles, registries, notifications and response policies are not planned.

## Licence

[MIT](LICENSE)
