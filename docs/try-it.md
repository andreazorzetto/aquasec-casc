# Try it: a guided tour against your own tenant

About fifteen minutes, from your laptop, against any Aqua tenant you can sign in
to. Every step below was run against a live SaaS tenant, and the output shown is
what it printed.

**It is safe on a shared tenant.** The playground policies are **disabled**, so
they exist but do nothing; they are scoped to `Global` because every tenant has
it; their names start with `casc-playground-`; and the last step deletes them.
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
2 resource(s) valid
```

Try a typo (`enforcee: false`) to see the error: the file, the path, and a
"did you mean". Validation rejects unknown fields because Aqua ignores them --
a typo'd control would otherwise be accepted and silently do nothing.

## 2. Diff, then apply

```
$ aquasec-casc diff -f /tmp/playground
+ RuntimePolicy/casc-playground-baseline: will be created
+ RuntimePolicy/casc-playground-strict: will be created
0 unchanged, 0 created, 0 updated, 0 adopted, 0 deleted, 2 planned
                                                            # exit code 2: changes pending

$ aquasec-casc apply -f /tmp/playground
+ RuntimePolicy/casc-playground-baseline: created
+ RuntimePolicy/casc-playground-strict: created
0 unchanged, 2 created, 0 updated, 0 adopted, 0 deleted

$ aquasec-casc diff -f /tmp/playground
2 unchanged, 0 created, 0 updated, 0 adopted, 0 deleted    # exit code 0: in sync
```

In the console (Policies → Runtime Policies), each description now ends with
`managed-by: aquasec-casc/playground`. That line is how the tool knows the
policy is its own -- there is no state file.

## 3. Change the YAML

In `runtime-policy-baseline.yaml`, set `enforce: true`:

```
$ aquasec-casc diff -f /tmp/playground
~ RuntimePolicy/casc-playground-baseline: will be updated
    ! enforce: false -> true
1 unchanged, 0 created, 0 updated, 0 adopted, 0 deleted, 1 planned

$ aquasec-casc apply -f /tmp/playground
~ RuntimePolicy/casc-playground-baseline: updated
    ! enforce: false -> true
```

One line changed in Git, one line in the diff.

## 4. Change it in the console: drift

In the console, open `casc-playground-strict` and switch off **Block fileless
execution**. Save.

```
$ aquasec-casc diff -f /tmp/playground
~ RuntimePolicy/casc-playground-strict: will be updated
    ! controls.blockFilelessExec: false -> true   (API: block_fileless_exec)

$ aquasec-casc apply -f /tmp/playground
~ RuntimePolicy/casc-playground-strict: updated
    ! controls.blockFilelessExec: false -> true   (API: block_fileless_exec)
```

Git wins. The YAML name leads, the API name is in brackets for anyone checking
the console or the logs.

Now change a setting the YAML does **not** mention, e.g. **Fork guard**. `diff`
stays at `2 unchanged`: fields the YAML leaves out belong to the console.

## 5. Report only

Add `enforcement: ReportOnly` at the end of `runtime-policy-strict.yaml`'s
`spec`, and switch **Block fileless execution** off in the console again:

```
$ aquasec-casc apply -f /tmp/playground
! RuntimePolicy/casc-playground-strict: drift detected (ReportOnly)
    ! controls.blockFilelessExec: false -> true   (API: block_fileless_exec)
    drift detected; spec.enforcement is ReportOnly, so apply changes nothing
```

Remove the line and apply again to put it back.

## 6. Delete by removing the file

```
$ rm /tmp/playground/runtime-policy-strict.yaml

$ aquasec-casc diff -f /tmp/playground
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

$ aquasec-casc diff -f /tmp/playground
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
~ RuntimePolicy/casc-playground-baseline: will be released
~ RuntimePolicy/casc-playground-handmade: will be released
2 to release

$ aquasec-casc release -f /tmp/playground
~ RuntimePolicy/casc-playground-baseline: released
    marker removed; the object is no longer managed
~ RuntimePolicy/casc-playground-handmade: released
    marker removed; the object is no longer managed
2 released
Next: remove these objects' files from Git, or stop the pipeline. While they remain, the next apply adopts the objects again.
```

The policies stay exactly as they are, minus the marker. Running `diff` now
shows both as `will be adopted` -- which is the warning above in action.
`--to <instance>` hands them to another instance instead.

## 9. Clean up

Adopt them again, then delete them the Git way:

```
$ aquasec-casc apply -f /tmp/playground            # re-adopts both
$ rm /tmp/playground/runtime-policy-*.yaml

$ aquasec-casc apply -f /tmp/playground
? RuntimePolicy/casc-playground-baseline: orphaned
    not deleted: no resources were loaded at all, which is more likely a wrong
    path or an empty mount than an instruction to delete everything. Pass
    --allow-empty if it is intended.

$ aquasec-casc apply -f /tmp/playground --allow-empty
- RuntimePolicy/casc-playground-baseline: deleted
- RuntimePolicy/casc-playground-handmade: deleted
```

The empty-folder guard is the last safety net: a run that loads nothing deletes
nothing unless told to.

---

## Useful switches

| | |
|---|---|
| `--output json` | machine-readable results, every command |
| `-v` | `diff`/`apply` also list unchanged objects |
| `--instance NAME` | override `aquasec-casc.yaml` |
| `--detailed-exitcode` | `apply` exits 2 when something is left pending |

Exit codes: `diff` 0 in sync, 1 error, 2 changes pending; `apply` 0 done, 1
error. See [architecture.md](architecture.md) for the reasoning behind each rule.
