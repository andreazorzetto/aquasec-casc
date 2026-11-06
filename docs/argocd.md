# Running it from Argo CD

Argo CD runs the tool as a Kubernetes `Job`, once on each sync. The policies are in a ConfigMap, so merging a change puts the application out of sync. Argo CD then applies the ConfigMap and runs the Job against it. A failed apply fails the sync.

```
  Git repository                      Kubernetes                         Aqua
  ┌───────────────────┐  Argo CD      ┌─────────────────────────┐       ┌─────────┐
  │ aqua/             │  syncs        │ ConfigMap: the policies │       │         │
  │  policies/*.yaml  │ ────────────► │ Job: aquasec-casc apply │ ────► │ REST API│
  │  Helm chart       │               │ Secret: credentials     │       │         │
  └───────────────────┘               └─────────────────────────┘       └─────────┘
```

The Job runs only when Argo CD syncs. A console change stays until the next sync, and Argo CD does not notice it: see [Between syncs](#between-syncs).

**You need:**

- Argo CD, and a Git repository it can read.
- An Aqua user that can read and write runtime and assurance policies.
- HTTPS access from the Job's namespace to the Aqua console, and nothing else.

## 1. Mirror the image

On a connected machine, for your cluster's architecture:

```sh
docker pull --platform linux/amd64 andreazorzetto/aquasec-casc:0.1.0
docker save andreazorzetto/aquasec-casc:0.1.0 -o aquasec-casc-0.1.0.tar
sha256sum aquasec-casc-0.1.0.tar > aquasec-casc-0.1.0.tar.sha256
```

Carry both files across, then on the inside:

```sh
sha256sum -c aquasec-casc-0.1.0.tar.sha256
docker load -i aquasec-casc-0.1.0.tar
docker tag andreazorzetto/aquasec-casc:0.1.0 registry.internal.example/aquasec-casc:0.1.0
docker run --rm --network none andreazorzetto/aquasec-casc:0.1.0 --version
docker push registry.internal.example/aquasec-casc:0.1.0
```

<details>
<summary>Or build it yourself from a clean checkout</summary>

It needs the base image and PyPI, or your mirrors of them. A mirror behind an internal CA also needs that CA in the build, so mirroring the image is simpler.

```sh
docker build -t aquasec-casc:0.1.0 \
  --build-arg BASE_IMAGE=registry.internal.example/python:3.12-slim \
  --build-arg PIP_INDEX_URL=https://pypi.internal.example/simple .
```

</details>

## 2. Put the credentials in a Secret

Create it by hand or with your secrets tooling. It does not go in Git.

```sh
kubectl create namespace aqua-casc

read -rs AQUA_PASSWORD                  # not on the command line, nor in shell history

kubectl -n aqua-casc create secret generic aqua-casc-credentials \
  --from-literal=AQUA_URL=https://aqua.internal.example \
  --from-literal=AQUA_USER=aquasec-casc \
  --from-file=AQUA_PASSWORD=<(printf %s "$AQUA_PASSWORD")
unset AQUA_PASSWORD
```

The address must be `https://`. If the console's certificate comes from an internal CA, add that CA too:

```sh
kubectl -n aqua-casc create configmap aqua-casc-ca --from-file=ca.pem=internal-ca.pem
```

## 3. Lay out the repository

A small Helm chart, with the policies in a folder. Argo CD renders it, so you do not need Helm installed.

```
aqua/
├── Chart.yaml
├── policies/
│   ├── aquasec-casc.yaml                instance: platform
│   ├── runtime-policy-devtest.yaml
│   ├── runtime-policy-prod.yaml
│   └── assurance-policy-prod.yaml
└── templates/
    ├── configmap.yaml
    └── job.yaml
```

Keep `policies/` flat, with `.yaml` names: the chart refuses to render anything else, rather than leave a file out. To start from what is already in Aqua, [`export`](adoption.md) writes this folder for you.

`Chart.yaml`:

```yaml
apiVersion: v2
name: aqua-config
version: 1.0.0
```

`templates/configmap.yaml` takes every file in `policies/`, so **removing a file deletes its policy from Aqua on the next sync**. Argo CD limits a ConfigMap to about 256 KB, which holds a lot of policies.

```yaml
{{- /* A file the glob below would miss has no policy in the Job, which deletes it. */ -}}
{{- range $path, $_ := .Files.Glob "policies/**" }}
{{- if not (regexMatch "^policies/[^/]+\\.yaml$" $path) }}
{{- fail (printf "%s will not reach the ConfigMap: keep policies/ flat, with .yaml names" $path) }}
{{- end }}
{{- end }}
apiVersion: v1
kind: ConfigMap
metadata:
  name: aqua-casc-config
data:
{{ (.Files.Glob "policies/*.yaml").AsConfig | indent 2 }}
```

`templates/job.yaml`. Remove the lines marked `internal CA` if you have none:

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  generateName: aqua-casc-apply-                 # not a fixed name: see below
  annotations:
    argocd.argoproj.io/hook: Sync
    argocd.argoproj.io/sync-wave: "1"            # after the ConfigMap, at wave 0
spec:
  backoffLimit: 0                   # do not retry a failed apply on its own
  ttlSecondsAfterFinished: 86400    # the Job and its log stay for a day
  template:
    spec:
      restartPolicy: Never
      automountServiceAccountToken: false    # it never talks to Kubernetes
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        seccompProfile:
          type: RuntimeDefault
      # imagePullSecrets: [{ name: your-registry }]    # if your mirror needs one
      containers:
        - name: aquasec-casc
          image: registry.internal.example/aquasec-casc:0.1.0   # your mirror; pin the digest
          args: ["apply", "-f", "/config"]
          envFrom:
            - secretRef:
                name: aqua-casc-credentials
          env:
            - { name: AQUA_CA_BUNDLE, value: /etc/aqua-ca/ca.pem }    # internal CA
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
          resources:
            requests: { cpu: 50m, memory: 64Mi }
            limits: { memory: 128Mi }
          volumeMounts:
            - { name: config, mountPath: /config, readOnly: true }
            - { name: ca, mountPath: /etc/aqua-ca, readOnly: true }   # internal CA
      volumes:
        - name: config
          configMap:
            name: aqua-casc-config
        - name: ca                                                    # internal CA
          configMap:                                                  # internal CA
            name: aqua-casc-ca                                        # internal CA
```

**Keep `generateName` and the `Sync` hook.** With a fixed Job name, Argo CD can read the previous Job's status and report a failed apply as a success, which we saw on Argo CD 3.6. That is also why this is a Helm chart: kustomize refuses `generateName`. A `PreSync` hook would run before the ConfigMap updates, and read the old files.

## 4. Create the Application

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: aqua-config
  namespace: argocd
spec:
  project: default
  source:
    repoURL: https://git.internal.example/platform/aqua-config.git
    targetRevision: main
    path: aqua
  destination:
    server: https://kubernetes.default.svc
    namespace: aqua-casc
  syncPolicy:
    automated:
      prune: true
```

Leave out `automated` to press Sync yourself for the first runs. There is deliberately no `retry`: Aqua locks an account after repeated failed sign-ins, and a wrong password retried automatically gets there quickly.

## 5. Try it

Start safely, with the Job's arguments as `["plan", "-f", "/config"]`. `plan` never writes, so the sync shows what `apply` would do. When that reads right, change it to `apply`.

**A file named like a policy already in Aqua takes that policy over, and turns off every control it leaves out.** Under automated sync nobody reads a plan first, so start from [`export`](adoption.md), which writes what is there.

To watch one policy for a while, set `spec.enforcement: ReportOnly` on it. That does not hold back deletions, so add `--no-delete` to the arguments if files may be missing.

Sync, then read the latest Job's log:

```sh
kubectl -n aqua-casc logs "$(kubectl -n aqua-casc get jobs --sort-by=.metadata.creationTimestamp -o name | tail -1)"
```

```
Using environment.
~ RuntimePolicy/devtest-baseline: adopted
    + ownership marker (managed-by: aquasec-casc/platform)
0 unchanged, 0 created, 0 updated, 1 adopted, 0 deleted
```

## When a sync fails

The sync operation fails, but **the Application can still read `Synced`**, since its ConfigMap matches Git. Alert on the last operation's phase, not on the sync status. The log says why:

| Log line | What it means | What to do |
|---|---|---|
| `error: ...: N validation problem` | A file does not match the schema. Nothing was sent. | Fix the file. `validate` catches this before a merge. |
| `x ...: FAILED` | Aqua or the tool refused it, and the message says which. Other policies still applied, and nothing of that kind was deleted. | Often a scope that does not exist in Aqua, or a file that does not say `enabled`, `enforce` or `runtimeType` where Aqua differs from their defaults. |
| `not kept by Aqua: ...` | Aqua accepted the write and did not keep a field, usually one this version lacks. | Update Aqua, or remove the setting. |
| `error: Sign-in failed` | The credentials, or the console's address. | Check the Secret. Aqua locks an account after repeated failures. |
| `error: ... could not connect to Aqua` | No route, or the NetworkPolicy. | Check the address and egress. |
| `the console's TLS certificate could not be verified` | The CA is not trusted. | Set `AQUA_CA_BUNDLE`. |

These do **not** fail the sync, so read the log if a sync looks too quiet:

| Log line | What it means |
|---|---|
| `x ...: blocked` | Another instance manages this policy, and nothing of that kind is deleted in this run. Remove it from one of them, or `release --to`. |
| `? ...: orphaned` | A policy with no file was not deleted, and the message says why. |
| `not allowed: ...` | A change Aqua does not allow, such as the scope of a default policy. The rest applied. |
| `warning: ...` | A setting Aqua holds that the tool does not offer, such as `excludeApplicationScopes`. It stays as it is. |

Do not use `--detailed-exitcode` in this Job: exit 2 fails the sync.

## Optional

### Between syncs

To catch a console change between syncs, run the same image from a `CronJob`, with the same ConfigMap and Secret:

- to report: `args: ["plan", "-f", "/config", "--detailed-exitcode"]`, and alert on a failed job (exit 2 means drift);
- to correct: `args: ["apply", "-f", "/config"]`.

### Limit the Job to the console

Add this NetworkPolicy to `templates/`. Its sync wave puts it in place before the Job.

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: aqua-casc
  annotations:
    argocd.argoproj.io/sync-wave: "-1"
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
  egress:
    - to:
        - ipBlock: { cidr: 10.0.0.10/32 }   # the Aqua console
      ports:
        - { protocol: TCP, port: 443 }
    - to:                                   # DNS, if the console has a name
        - namespaceSelector: {}
      ports:
        - { protocol: UDP, port: 53 }
        - { protocol: TCP, port: 53 }
```

---

Tested on Argo CD 3.6 on a local cluster, following this page, against a SaaS tenant: a merged change reaching Aqua, a schema error failing the sync, and a renamed policy being created and the old one deleted.
