# The demo

From a console-configured policy to drift being corrected, about ten minutes. It
makes the case for the tool in the order it matters: adopting existing configuration
changes nothing; a change is one line in a diff; a console change does not survive.

Rehearsed against a live tenant with `scripts/rehearse_demo.sh`, which runs these
steps and checks every exit code.

**Before you start**

- Credentials set (`aquasec-casc setup`, or the `AQUA_*` variables).
- In the console, a **disabled** container runtime policy named `demo-devtest`, scope
  `Global`, with **Block Non-Compliant Images** ticked. Disabled, it does nothing.

```sh
mkdir demo && cd demo && git init -q
```

## 1. Export what is there

```
$ aquasec-casc export --scope Global --name demo-devtest --kind RuntimePolicy -o . --instance demo
+ runtime-policy-demo-devtest.yaml  ('demo-devtest')
+ aquasec-casc.yaml  (instance: demo)
1 exported, 0 skipped -> .

$ cat runtime-policy-demo-devtest.yaml
$ git add . && git commit -qm "Export from Aqua"
```

Show the file: the console's policy, in the console's words.

## 2. Applying it changes nothing

```
$ aquasec-casc plan -f .
~ RuntimePolicy/demo-devtest: will be adopted
    + ownership marker (managed-by: aquasec-casc/demo)

$ aquasec-casc apply -f .
~ RuntimePolicy/demo-devtest: adopted

$ aquasec-casc plan -f . --detailed-exitcode ; echo "exit $?"
1 unchanged, 0 created, 0 updated, 0 adopted, 0 deleted
exit 0
```

This is the safety argument: your existing configuration, in Git, and applying it
changes nothing but one ownership line in the description.

## 3. The fix is one line in a pull request

An enforcer judges compliance by image *hash*, so a non-compliant verdict from one
scope's assurance policy blocks that image wherever the enforcer sees it, including
a dev/test scope in audit mode. The fix is for dev/test not to have this control.

Delete the line `blockNonCompliantImages: true` from the file:

```
$ git diff --stat
 runtime-policy-demo-devtest.yaml | 1 -
 1 file changed, 1 deletion(-)
```

In the console that was a checkbox in the right policy in the right scope. Here it is
one line, with a commit message saying why:

```sh
git commit -qam "Dev/test does not block on the image's compliance verdict

Compliance follows the image hash, so another scope's verdict blocks it here too."
```

## 4. Plan shows that one field

```
$ aquasec-casc plan -f . --detailed-exitcode ; echo "exit $?"
~ RuntimePolicy/demo-devtest: will be updated
    ! controls.blockNonCompliantImages: true -> false   (API: block_disallowed_images)
0 unchanged, 0 created, 0 updated, 0 adopted, 0 deleted, 1 planned
exit 2
```

Exit 2 is what lets a pipeline gate on it.

## 5. Apply, and see it in the console

```
$ aquasec-casc apply -f .
~ RuntimePolicy/demo-devtest: updated
    ! controls.blockNonCompliantImages: true -> false   (API: block_disallowed_images)
```

Open the policy in the console: the box is clear.

## 6. Someone changes it in the console

Tick **Block Non-Compliant Images** again, and save.

```
$ aquasec-casc plan -f . --detailed-exitcode ; echo "exit $?"
~ RuntimePolicy/demo-devtest: will be updated
    ! controls.blockNonCompliantImages: true -> false   (API: block_disallowed_images)
exit 2

$ aquasec-casc apply -f .
~ RuntimePolicy/demo-devtest: updated
```

Git wins. This is drift being detected and corrected.

## 7. Assurance policies work the same way

```
$ cp <the tool's repo>/examples/playground/assurance-policy-image.yaml .

$ aquasec-casc apply -f .
+ AssurancePolicy/casc-playground-image ('image/casc-playground-image'): created

$ aquasec-casc plan -f . --detailed-exitcode ; echo "exit $?"
2 unchanged, 0 created, 0 updated, 0 adopted, 0 deleted
exit 0
```

This one is scoped to names that match nothing, so it stays inert.

## 8. This is what happens on every sync

Show the Job in [argocd.md](argocd.md): `apply -f /config`, as an Argo CD hook. Steps 4 to
6 are what happens on every sync. Say plainly what it does not do: a console
change stays until the next sync. Closing that gap is what an operator would do.

## Clean up

```sh
rm assurance-policy-image.yaml runtime-policy-demo-devtest.yaml
aquasec-casc apply -f . --allow-empty       # both files gone: both objects deleted
```
