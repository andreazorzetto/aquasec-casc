# Guided tour

Try every command against your own tenant, in about fifteen minutes. The output is real, shortened where it adds nothing.

**It is safe on a shared tenant.** The playground's runtime policies are disabled, and its assurance policy is scoped to image names that match nothing. Their names start with `casc-playground-`, and the last step deletes them. The tool only ever deletes objects carrying its own marker for this instance.

## Set up

From a clone of this repository, with [the tool installed and credentials set](../README.md#quick-start):

```sh
cp -R examples/playground /tmp/playground     # work on a copy; you will edit it
```

The instance name, `playground`, comes from `aquasec-casc.yaml` in that folder.

## 1. Validate

```
$ aquasec-casc validate -f /tmp/playground
4 resource(s) valid
```

Try a typo (`enforcee: false`) to see the error and a "did you mean". Unknown fields are refused because Aqua ignores them, so a mistyped control would otherwise silently do nothing.

## 2. Plan and apply

```
$ aquasec-casc plan -f /tmp/playground
+ AssurancePolicy/casc-playground-image ('image/casc-playground-image'): will be created
+ RuntimePolicy/casc-playground-all-controls: will be created
+ RuntimePolicy/casc-playground-baseline: will be created
+ RuntimePolicy/casc-playground-strict: will be created
0 unchanged, 0 created, 0 updated, 0 adopted, 0 deleted, 4 planned

$ aquasec-casc apply -f /tmp/playground
0 unchanged, 4 created, 0 updated, 0 adopted, 0 deleted

$ aquasec-casc plan -f /tmp/playground
4 unchanged, 0 created, 0 updated, 0 adopted, 0 deleted
```

In the console, each description now ends with `managed-by: aquasec-casc/playground`. That line is how the tool knows a policy is its own, so there is no state file.

## 3. Change the YAML

In `runtime-policy-baseline.yaml`, set `enforce: true`:

```
$ aquasec-casc plan -f /tmp/playground
~ RuntimePolicy/casc-playground-baseline: will be updated
    ! enforce: false -> true
3 unchanged, 0 created, 0 updated, 0 adopted, 0 deleted, 1 planned

$ aquasec-casc apply -f /tmp/playground
```

One line changed in Git, one line in the plan.

## 4. Change it in the console

In the console, open `casc-playground-strict` and switch off **Block fileless execution**. Then add **Port Block**, with blocked inbound port `22`, which the YAML does not mention. Save.

```
$ aquasec-casc plan -f /tmp/playground
~ RuntimePolicy/casc-playground-strict: will be updated
    ! controls.blockFilelessExec.enabled: false -> true   (API: block_fileless_exec)
    ! controls.portBlock.enabled: true -> false   (API: port_block.enabled)

$ aquasec-casc apply -f /tmp/playground
```

Git wins, and the file is the whole policy: a control it leaves out is off. To keep the port block, write it into the YAML. To switch a control off, remove it. Assurance policies work the same way.

To watch a policy instead of correcting it, add `enforcement: ReportOnly` to its `spec`: drift is reported, and nothing is written.

## 5. Delete by removing the file

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
```

## 6. Bring an existing policy under management

In the console, create a runtime policy named `casc-playground-handmade` (container, scope Global, **disabled**), with any controls you like.

```
$ aquasec-casc export --scope Global --name casc-playground-handmade -o /tmp/playground
+ runtime-policy-casc-playground-handmade.yaml  ('casc-playground-handmade')
1 exported, 0 skipped -> /tmp/playground

$ aquasec-casc plan -f /tmp/playground
~ RuntimePolicy/casc-playground-handmade: will be adopted
    + ownership marker (managed-by: aquasec-casc/playground)

$ aquasec-casc apply -f /tmp/playground
```

Adopting changes nothing but the marker. `export` also works on the policies Aqua ships, but **do not adopt those on a shared tenant**: every API edit rewrites a runtime policy's `author` to your identity, and that cannot be undone.

## 7. Let go without deleting

```
$ aquasec-casc release -f /tmp/playground --dry-run    # -f only finds the instance name
~ RuntimePolicy/casc-playground-all-controls: will be released
...
4 to release

$ aquasec-casc release -f /tmp/playground
4 released
```

The policies stay as they are, minus the marker. While their files remain, the next `apply` adopts them again. `--to <instance>` hands them to another instance instead: put their files in its configuration first, or its next apply deletes them.

## 8. Clean up

```
$ aquasec-casc apply -f /tmp/playground            # re-adopts all four
$ aquasec-casc destroy -f /tmp/playground
...
4 to destroy
Type the instance name (playground) to confirm: playground
4 destroyed
```

Without `-f`, `destroy` takes everything carrying this instance's marker. `--dry-run` shows the plan, and `--yes` skips the question, for scripts.

---

**Other useful switches:** `-v` lists unchanged objects too, and `--instance NAME` overrides `aquasec-casc.yaml`.

**Next:** [run it from Argo CD](argocd.md), or [adopt your own policies](adoption.md). Showing this to someone? [docs/demo.md](demo.md) is a ten-minute script.
