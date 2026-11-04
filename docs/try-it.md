# Try it: a guided tour against your own tenant

About fifteen minutes, from your laptop, against any Aqua tenant you can sign in
to. Every step below was run against a live SaaS tenant, and the output shown is
what it printed.

**It is safe on a shared tenant.** The playground's runtime policies are
**disabled**, so they exist but do nothing. Assurance policies have no such switch,
so its assurance policy is scoped to image names that match nothing. They are scoped
to `Global` because every tenant has it; their names start with `casc-playground-`;
and the last step deletes them.
The tool only ever deletes objects carrying its own marker for this instance
(`managed-by: aquasec-casc/playground`), so nothing else on the tenant is at risk.

---

## 0. Set up

```sh
python3 -m venv .venv
.venv/bin/pip install -e .
source .venv/bin/activate

cp -R examples/playground /tmp/playground     # work on a copy; you will edit it
```

Credentials come from a saved profile or the environment -- never from a file
in the repository. Profiles are the same encrypted ones the other aquasec tools
use, so if you have one already there is nothing to do:

```
$ aquasec-casc profile list
  PROFILE   AUTH       CONSOLE
* lab       api_keys   https://xxxxxxxxxx.cloud.aquasec.com
* default: used when neither --profile nor AQUA_* credentials are given

$ aquasec-casc setup lab          # otherwise: the interactive wizard
```

Each command says which credentials it used (`Using profile 'lab'.`, on
stderr). The order is `--profile NAME`, then `AQUA_*` variables if any are set
(see `.env.example`), then the default profile. `profile show`, `profile
set-default` and `profile delete` manage the rest; none of them print secrets.

The instance name, `playground`, comes from `aquasec-casc.yaml` in the folder.

---

## 1. Validate -- no network

```
$ aquasec-casc validate -f /tmp/playground
4 resource(s) valid
```

Try a typo (`enforcee: false`) to see the error: the file, the path, and a
"did you mean". Validation rejects unknown fields because Aqua ignores them --
a typo'd control would otherwise be accepted and silently do nothing.

## 2. Plan, then apply

```
$ aquasec-casc plan -f /tmp/playground
+ AssurancePolicy/casc-playground-image ('image/casc-playground-image'): will be created
+ RuntimePolicy/casc-playground-all-controls: will be created
+ RuntimePolicy/casc-playground-baseline: will be created
+ RuntimePolicy/casc-playground-strict: will be created
0 unchanged, 0 created, 0 updated, 0 adopted, 0 deleted, 4 planned

$ aquasec-casc apply -f /tmp/playground
+ AssurancePolicy/casc-playground-image ('image/casc-playground-image'): created
+ RuntimePolicy/casc-playground-all-controls: created
+ RuntimePolicy/casc-playground-baseline: created
+ RuntimePolicy/casc-playground-strict: created
0 unchanged, 4 created, 0 updated, 0 adopted, 0 deleted

$ aquasec-casc plan -f /tmp/playground
4 unchanged, 0 created, 0 updated, 0 adopted, 0 deleted
```

In the console (Policies → Runtime Policies, Assurance Policies), each description now ends with
`managed-by: aquasec-casc/playground`. That line is how the tool knows the
policy is its own -- there is no state file.

## 3. Change the YAML

In `runtime-policy-baseline.yaml`, set `enforce: true`:

```
$ aquasec-casc plan -f /tmp/playground
~ RuntimePolicy/casc-playground-baseline: will be updated
    ! enforce: false -> true
3 unchanged, 0 created, 0 updated, 0 adopted, 0 deleted, 1 planned

$ aquasec-casc apply -f /tmp/playground
~ RuntimePolicy/casc-playground-baseline: updated
    ! enforce: false -> true
```

One line changed in Git, one line in the plan.

## 4. Change it in the console: drift

In the console, open `casc-playground-strict` and switch off **Block fileless
execution**. Save.

```
$ aquasec-casc plan -f /tmp/playground
~ RuntimePolicy/casc-playground-strict: will be updated
    ! controls.blockFilelessExec.enabled: false -> true   (API: block_fileless_exec)

$ aquasec-casc apply -f /tmp/playground
~ RuntimePolicy/casc-playground-strict: updated
    ! controls.blockFilelessExec.enabled: false -> true   (API: block_fileless_exec)
```

Git wins. The YAML name leads, the API name is in brackets for anyone checking
the console or the logs.

Now switch on a control the YAML does **not** mention: add **Port Block** with
blocked inbound port `22`, and save. `plan` reports that too:

```
$ aquasec-casc plan -f /tmp/playground
~ RuntimePolicy/casc-playground-strict: will be updated
    ! controls.portBlock.enabled: true -> false   (API: port_block.enabled)
```

The file is the whole policy: a control it leaves out is off. To keep the port
block, write it into the YAML; to switch a control off, remove it.

Assurance policies behave the same. In `assurance-policy-image.yaml`, remove the line
`malware: true`:

```
$ aquasec-casc plan -f /tmp/playground
~ AssurancePolicy/casc-playground-image ('image/casc-playground-image'): will be updated
    ! controls.malware.enabled: true -> false   (API: disallow_malware)
```

Put it back before moving on. Their `actions` and `exceptions` are treated like
controls, too: what the file leaves out is off.

## 5. Report only

Add `enforcement: ReportOnly` at the end of `runtime-policy-strict.yaml`'s
`spec`, and switch **Block fileless execution** off in the console again:

```
$ aquasec-casc apply -f /tmp/playground
! RuntimePolicy/casc-playground-strict: drift detected (ReportOnly)
    ! controls.blockFilelessExec.enabled: false -> true   (API: block_fileless_exec)
    drift detected; spec.enforcement is ReportOnly, so apply changes nothing
```

Remove the line and apply again to put it back.

## 6. Delete by removing the file

```
$ rm /tmp/playground/runtime-policy-strict.yaml

$ aquasec-casc plan -f /tmp/playground
- RuntimePolicy/casc-playground-strict: will be deleted
    no file describes it; will be deleted

$ aquasec-casc apply -f /tmp/playground --no-delete
? RuntimePolicy/casc-playground-strict: orphaned
    orphaned, not deleted (--no-delete)

$ aquasec-casc apply -f /tmp/playground
- RuntimePolicy/casc-playground-strict: deleted
    no file describes it any more
```

As with Argo CD pruning: Git is the source of truth, `--no-delete` holds back.

## 7. Bring an existing policy under management

In the console, create a runtime policy named `casc-playground-handmade`
(container, scope Global, **disabled**), with any controls you like.

```
$ aquasec-casc export --scope Global --name casc-playground-handmade -o /tmp/playground
+ runtime-policy-casc-playground-handmade.yaml  ('casc-playground-handmade')
1 exported, 0 skipped -> /tmp/playground

$ aquasec-casc plan -f /tmp/playground
~ RuntimePolicy/casc-playground-handmade: will be adopted
    + ownership marker (managed-by: aquasec-casc/playground)

$ aquasec-casc apply -f /tmp/playground
~ RuntimePolicy/casc-playground-handmade: adopted
```

The exported file describes the policy exactly as it is, so adopting it changes
nothing but the marker. From now on it is managed like the others.

`export` is read-only and also works on the policies Aqua ships, but **do not
adopt those on a shared tenant**: every API edit rewrites a runtime policy's
`author` to your identity, and that cannot be undone.

## 8. Let go without deleting

```
$ aquasec-casc release -f /tmp/playground --dry-run
~ RuntimePolicy/casc-playground-all-controls: will be released
~ RuntimePolicy/casc-playground-baseline: will be released
~ RuntimePolicy/casc-playground-handmade: will be released
~ AssurancePolicy/image/casc-playground-image: will be released
4 to release

$ aquasec-casc release -f /tmp/playground
~ RuntimePolicy/casc-playground-all-controls: released
    marker removed; the object is no longer managed
~ RuntimePolicy/casc-playground-baseline: released
    marker removed; the object is no longer managed
~ RuntimePolicy/casc-playground-handmade: released
    marker removed; the object is no longer managed
~ AssurancePolicy/image/casc-playground-image: released
    marker removed; the object is no longer managed
4 released
Next: remove these objects' files from Git, or stop the pipeline. While they remain, the next apply adopts the objects again.
```

The policies stay exactly as they are, minus the marker. Running `plan` now
shows all four as `will be adopted` -- which is the warning above in action.
`--to <instance>` hands them to another instance instead. Put their files in that
instance's configuration first: without them, its next apply deletes them.

## 9. Clean up

`destroy` deletes what the files describe -- only objects this instance
manages -- after showing the plan and asking you to type the instance name:

```
$ aquasec-casc apply -f /tmp/playground            # re-adopts all four
$ aquasec-casc destroy -f /tmp/playground
- RuntimePolicy/casc-playground-all-controls: will be deleted
- RuntimePolicy/casc-playground-baseline: will be deleted
- RuntimePolicy/casc-playground-handmade: will be deleted
- AssurancePolicy/casc-playground-image ('image/casc-playground-image'): will be deleted
4 to destroy
This deletes the objects described in /tmp/playground owned by instance 'playground'. It cannot be undone.
Type the instance name (playground) to confirm: playground

- RuntimePolicy/casc-playground-all-controls: deleted
- RuntimePolicy/casc-playground-baseline: deleted
- RuntimePolicy/casc-playground-handmade: deleted
- AssurancePolicy/casc-playground-image ('image/casc-playground-image'): deleted
4 destroyed
Next: remove these files from Git, or stop the pipeline. While they remain, the next apply recreates the objects.
```

Without `-f`, `destroy` takes everything carrying this instance's marker,
files or not. `--dry-run` shows the plan only; `--yes` skips the question, for
scripts. Policies Aqua ships cannot be deleted, so `destroy` releases them
instead.

The Git way works too: remove the files and `apply`. A run with no files of a kind
deletes nothing of that kind unless you add `--allow-empty` -- the last safety net
against a wrong path or an empty mount.

---

## Useful switches

| | |
|---|---|
| `--output json` | machine-readable results, everything that talks to Aqua |
| `-v` | `plan`/`apply` also list unchanged objects |
| `--instance NAME` | override `aquasec-casc.yaml` |
| `--detailed-exitcode` | `plan`/`apply` exit 2 when changes are (left) pending, for scripts |

Exit codes, as Terraform: 0 success, 1 error; `plan` and `apply` exit 2 when
changes are pending only with `--detailed-exitcode`. See [architecture.md](architecture.md) for the reasoning behind each rule.
