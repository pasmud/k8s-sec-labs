# Kubernetes manifest review notes

Start with [`examples/restricted.yaml`](../examples/restricted.yaml). Its four documents show different controls: a bounded process, a narrow API grant, a binding to a named identity group, and network isolation. These controls solve different problems; none substitutes for the others.

## Pod Security Restricted controls

Pod Security Standards define admission profiles. This linter checks a subset of the Linux Restricted profile, including some controls inherited from Baseline:

| Check | What to look for |
| --- | --- |
| `POD_HOST_NAMESPACE`, `POD_HOST_PORT`, `POD_HOST_PATH` | Leave host PID, IPC, and networking disabled. Omit nonzero `hostPort` values and `hostPath` volumes. |
| `POD_PRIVILEGED`, `POD_ESCALATION` | Leave privilege disabled and explicitly set `allowPrivilegeEscalation: false` in each container security context. |
| `POD_NON_ROOT`, `POD_ROOT_UID` | Require `runAsNonRoot: true` at Pod level or on each container. Neither level should explicitly select UID 0 or disable `runAsNonRoot`. Choose a UID supported by the image. |
| `POD_SECCOMP` | Use `RuntimeDefault` or a `Localhost` profile with a path. The linter cannot verify that a custom profile is installed on the target nodes. |
| `POD_CAP_DROP`, `POD_CAP_ADD` | Drop `ALL` capabilities in each container and add none unless `NET_BIND_SERVICE` is needed. |

Pod-level non-root and seccomp settings can satisfy the corresponding requirements for containers that don't override them. The linter also checks init and ephemeral container entries. The reference Deployment sets a read-only root filesystem and disables automatic service-account token mounting as additional hardening; those settings are not scored. This project does not cover the full Restricted volume allowlist, SELinux, AppArmor, proc mount, sysctls, or all version-specific admission rules. Use your cluster's version-matched [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/) for enforcement.

## RBAC least privilege

Write down **who needs to do what, to which objects, and where** before writing a rule. The example grants only `get` on the `inventory-settings` ConfigMap in namespace `inventory`. Its RoleBinding names a specific group, which an identity provider would have to supply. The Deployment does not use this grant. Avoid adding `list` or `watch` when the consumer only fetches a known name; `resourceNames` is not a general field filter for arbitrary list requests.

- `RBAC_WILDCARD` flags broad API groups, resource or verb wildcards, and wildcard non-resource URLs. Explicit grants avoid automatically sweeping in new APIs or resources.
- `RBAC_SECRET_READ` flags `get`, `list`, `watch`, or `*` on core `secrets` or wildcard resources in the core or wildcard API group. Review the need for even a single Secret read.
- `RBAC_BROAD_SUBJECT` flags all-authenticated, all-unauthenticated, and broad service-account groups. A `RoleBinding` can bind a `ClusterRole` within one namespace; `RBAC_CLUSTER_BINDING` asks you to review every cluster-wide binding instead of assuming it is wrong.
- `RBAC_AGGREGATION` asks you to review ClusterRoles matched by an aggregation rule. This tool neither joins role references nor computes effective permissions, privilege delegation, or grants from other sources.

Reference: [Kubernetes RBAC good practices](https://kubernetes.io/docs/concepts/security/rbac-good-practices/).

## NetworkPolicy basics

A NetworkPolicy targets Pods in its own namespace. An empty **target** `podSelector: {}` selects every Pod in that namespace. The example deliberately narrows the target to the `app: quiet-workload` label. Selecting a Pod for a direction makes it isolated in that direction; policies selecting the same Pod combine their allow rules. An empty list of rules for a declared direction contributes no allows, but other policies can still permit traffic.

- `NET_IMPLICIT_TYPES`: Declare both directions you intend to control. If `policyTypes` is omitted, Kubernetes defaults to `Ingress` and adds `Egress` when there are egress rules. An empty `egress: []` alone does not declare egress isolation.
- `NET_ANY_PEER`: An empty rule (`ingress: [{}]`) is different from an empty rule list (`ingress: []`). An omitted or empty `from` or `to` inside a rule permits all peers on the rule's allowed ports. If `ports` is also omitted or empty, that rule matches all ports.
- `NET_ALL_NAMESPACES`: An empty `namespaceSelector: {}` in a peer matches any namespace. A `podSelector` in that same peer still filters Pods; separate entries in the peer list are alternatives. A peer `podSelector` by itself targets Pods in the policy's namespace.

When introducing default-deny policies, inventory required dependencies (often DNS, metrics, and upstream services) before allowing narrowly scoped traffic. An enforcing network plugin is required. The linter does not resolve labels, evaluate CIDRs or ports, model other policies, or predict what the plugin enforces. See [Kubernetes Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/) for exact behavior and exceptions.
