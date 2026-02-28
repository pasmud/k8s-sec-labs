# k8s-sec-labs

An offline linter for rendered Kubernetes manifests. It checks selected Linux Pod Security Restricted controls, reviews broad RBAC grants, and highlights easy-to-miss NetworkPolicy behavior. It reads local files and reports source locations; no kubeconfig, cluster, container runtime, or credentials are needed.

## Quickstart

From the repository root, use Python 3.10 or newer. The only dependency is PyYAML; if version 6.0.3 is already installed, skip the virtual environment and installation steps.

```sh
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 -m k8s_sec_labs examples/restricted.yaml
```

For offline installation, use `python3 -m pip install --no-index --find-links /path/to/wheels -r requirements.txt` with a compatible PyYAML wheel staged locally. Once installed, scanning and tests are offline. The reference file contains a hardened Deployment, a namespaced Role and RoleBinding, and a policy that isolates that workload in both directions. The command prints nothing and exits `0`.

Pass one or more UTF-8 files explicitly: `python3 -m k8s_sec_labs workload.yaml policy.yaml`. YAML streams and JSON manifests are accepted. Directories, stdin, rendering, and recursive traversal are outside the interface. Exit status:

| Status | Meaning |
| --- | --- |
| `0` | Reviewed files have no findings for the implemented rules. |
| `1` | At least one finding; no scan errors. |
| `2` | Invalid invocation, unreadable or invalid input, or an unsupported object. Findings from other reviewed documents/files are still printed. |

A synthetic example from the unit tests:

```text
review.yaml:12:9: finding POD_PRIVILEGED [doc 1 $.spec.containers[0].securityContext.privileged] Do not run privileged containers.
```

Diagnostics go to stdout in argument order, then document, line, column, code, and field path order. Lines, columns, and document numbers start at 1; list indexes start at 0. Positions point to a field key or list item; for an absent field, the position points to its nearest existing ancestor and the diagnostic still names the missing field. Empty stream documents are skipped without renumbering. A file containing only empty documents is an error. Invalid YAML discards results for that file; a shape or support error in a well-formed document does not prevent review of later documents.

Use `python3 -m k8s_sec_labs --format json workload.yaml policy.yaml` for a single JSON array of diagnostics on stdout (`[]` for a clean scan). Each entry has `file` (the argument as passed), `document`, `line`, `column`, `path`, `level` (`finding` or `error`), `code`, and `message`. The `path` is an array of field names and numeric indexes; `[]` means the document root or a file-level error. Exit statuses and ordering are the same as in text mode, which remains the default. Invalid CLI arguments still print usage to stderr rather than emitting JSON.

## Scope and limits

| API version | Reviewed kinds |
| --- | --- |
| `v1` | `Pod`, `PodTemplate` |
| `apps/v1` | `Deployment`, `DaemonSet`, `StatefulSet`, `ReplicaSet` |
| `batch/v1` | `Job`, `CronJob` |
| `rbac.authorization.k8s.io/v1` | `Role`, `ClusterRole`, `RoleBinding`, `ClusterRoleBinding` |
| `networking.k8s.io/v1` | `NetworkPolicy` |

Use rendered objects with canonical Kubernetes field names. For `PodTemplate`, workload checks review the stored `.template.spec`; they do not infer how the template will be used. Other API version/kind pairs (including `List`, custom resources, and unrelated resources in mixed bundles) and explicitly non-Linux Pod specs report errors. Omitted Pod OS is reviewed as Linux; node placement is not inferred. Inputs are bounded to 1 MiB per file, 100 document slots, and 64 nested YAML nodes. Duplicate keys, non-string mapping keys, merge keys, anchors, aliases, explicit tags, and non-finite numeric values are rejected. Quote strings that resemble YAML 1.1 booleans or numbers, including mapping keys such as `on`. A `%YAML` directive must declare version `1.1`; other versions are rejected rather than silently read with YAML 1.1 scalar rules.

This is a selective manifest review, not Kubernetes schema validation, Pod Security Admission, an effective-permission calculator, or a connectivity test. Unscanned fields, admission mutations, controller behavior, installed profiles, and live cluster state can all change the outcome. See the [defensive learning notes](docs/defensive-review.md) for the implemented controls and concrete review guidance. The [risky fixture](tests/fixtures/risky.txt) is a YAML scalar containing synthetic text, so the checked-in file is not a Kubernetes object.

## Verification

```sh
python3 -m unittest discover -s tests -v
python3 -m k8s_sec_labs examples/restricted.yaml
python3 -m compileall -q k8s_sec_labs tests
git diff --check
```

GitHub Actions runs the unit tests and reference scan on push and pull requests with Python 3.10 and 3.14. Tests use local files and subprocesses only.

The commit timeline uses illustrative portfolio dates; it is not evidence of activity on those dates. Released under the [MIT license](LICENSE).
