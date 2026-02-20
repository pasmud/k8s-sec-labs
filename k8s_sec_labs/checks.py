"""Manifest-only review rules. API validation and policy enforcement are out of scope."""

from .source import Diagnostic, Document, Path, load

WORKLOADS = {
    ("v1", "Pod"): ("spec",),
    **{
        ("apps/v1", kind): ("spec", "template", "spec")
        for kind in ("Deployment", "DaemonSet", "StatefulSet", "ReplicaSet")
    },
    ("batch/v1", "Job"): ("spec", "template", "spec"),
    ("batch/v1", "CronJob"): ("spec", "jobTemplate", "spec", "template", "spec"),
}
RBAC_VERSION = "rbac.authorization.k8s.io/v1"
READ_VERBS = {"get", "list", "watch", "*"}


class Review:
    def __init__(self, document: Document):
        self.document = document
        self.results: list[Diagnostic] = []

    def emit(self, code, path, message, *, error=False):
        self.results.append(self.document.diagnostic(path, code, message, error=error))

    def invalid(self, path, message):
        self.emit("INPUT_SHAPE", path, message, error=True)

    def field(self, parent, key, path, expected, *, required=False):
        if key not in parent:
            if required:
                self.invalid((*path, key), "Required field is missing.")
            return None
        value = parent[key]
        if type(value) is not expected:
            label = {dict: "a mapping", list: "a list", str: "a string", bool: "a boolean", int: "an integer"}
            self.invalid((*path, key), f"Expected {label[expected]}.")
            return None
        return value

    def mappings(self, values, path):
        for index, entry in enumerate(values or []):
            item_path = (*path, index)
            if not isinstance(entry, dict):
                self.invalid(item_path, "Expected a mapping.")
            else:
                yield item_path, entry

    def strings(self, parent, key, path, *, required=False):
        values = self.field(parent, key, path, list, required=required)
        result = set()
        for index, value in enumerate(values or []):
            if not isinstance(value, str):
                self.invalid((*path, key, index), "Expected a string.")
            else:
                result.add(value)
        return result

    def check(self):
        data = self.document.data
        if not isinstance(data, dict):
            self.invalid((), "A manifest document must be a mapping.")
            return self.results
        version = self.field(data, "apiVersion", (), str, required=True)
        kind = self.field(data, "kind", (), str, required=True)
        if version is None or kind is None:
            return self.results
        if not version or not kind:
            self.invalid(("apiVersion",) if not version else ("kind",), "Expected a nonempty string.")
        elif (version, kind) in WORKLOADS:
            self.workload(data, WORKLOADS[version, kind])
        elif version == RBAC_VERSION and kind in {"Role", "ClusterRole"}:
            self.role(data, kind)
        elif version == RBAC_VERSION and kind in {"RoleBinding", "ClusterRoleBinding"}:
            self.binding(data, kind)
        elif (version, kind) == ("networking.k8s.io/v1", "NetworkPolicy"):
            self.network_policy(data)
        else:
            self.emit(
                "UNSUPPORTED_GVK", ("kind",), "This apiVersion/kind pair is not reviewed.", error=True,
            )
        return self.results

    def workload(self, data, spec_path: Path):
        path: Path = ()
        spec = data
        for key in spec_path:
            spec = self.field(spec, key, path, dict, required=True)
            if spec is None:
                return
            path = (*path, key)

        pod_os = self.field(spec, "os", path, dict)
        if "os" in spec:
            if pod_os is None:
                return
            name = self.field(pod_os, "name", (*path, "os"), str, required=True)
            if name != "linux":
                if name is not None:
                    self.emit(
                        "UNSUPPORTED_OS", (*path, "os", "name"),
                        "Only Linux Pod specs are reviewed.", error=True,
                    )
                return

        for key in ("hostNetwork", "hostPID", "hostIPC"):
            if self.field(spec, key, path, bool):
                self.emit("POD_HOST_NAMESPACE", (*path, key), "Do not share the host namespace.")
        volumes = self.field(spec, "volumes", path, list)
        for volume_path, volume in self.mappings(volumes, (*path, "volumes")):
            if "hostPath" in volume:
                self.emit("POD_HOST_PATH", (*volume_path, "hostPath"), "Do not mount hostPath volumes.")

        pod_context = self.field(spec, "securityContext", path, dict)
        pod_context_path = (*path, "securityContext")
        if pod_context is not None:
            self.identity(pod_context, pod_context_path)
            self.seccomp(pod_context, pod_context_path)
        for key in ("containers", "initContainers", "ephemeralContainers"):
            entries = self.field(spec, key, path, list, required=key == "containers")
            if key == "containers" and entries == []:
                self.invalid((*path, key), "Expected at least one container.")
            for container_path, container in self.mappings(entries, (*path, key)):
                self.container(container, container_path, pod_context or {})

    def identity(self, context, path):
        if self.field(context, "runAsUser", path, int) == 0:
            self.emit("POD_ROOT_UID", (*path, "runAsUser"), "Do not set the effective UID to 0.")
        if self.field(context, "runAsNonRoot", path, bool) is False:
            self.emit("POD_NON_ROOT", (*path, "runAsNonRoot"), "Do not disable runAsNonRoot.")

    def seccomp(self, context, path):
        profile = self.field(context, "seccompProfile", path, dict)
        if profile is None:
            return
        profile_path = (*path, "seccompProfile")
        profile_type = self.field(profile, "type", profile_path, str, required=True)
        if profile_type is not None and profile_type not in {"RuntimeDefault", "Localhost"}:
            self.emit("POD_SECCOMP", (*profile_path, "type"), "Use RuntimeDefault or Localhost seccomp.")
        if profile_type == "Localhost":
            local = self.field(profile, "localhostProfile", profile_path, str, required=True)
            if local == "":
                self.invalid((*profile_path, "localhostProfile"), "Expected a nonempty profile path.")

    def container(self, container, path, pod_context):
        ports = self.field(container, "ports", path, list)
        for port_path, port in self.mappings(ports, (*path, "ports")):
            if self.field(port, "hostPort", port_path, int):
                self.emit("POD_HOST_PORT", (*port_path, "hostPort"), "Do not bind a host port.")

        context = self.field(container, "securityContext", path, dict)
        if context is None and "securityContext" in container:
            return
        context = context or {}
        path = (*path, "securityContext")
        self.identity(context, path)
        self.seccomp(context, path)
        if self.field(context, "privileged", path, bool):
            self.emit("POD_PRIVILEGED", (*path, "privileged"), "Do not run privileged containers.")
        escalation = self.field(context, "allowPrivilegeEscalation", path, bool)
        if "allowPrivilegeEscalation" not in context or escalation is True:
            self.emit(
                "POD_ESCALATION", (*path, "allowPrivilegeEscalation"),
                "Set allowPrivilegeEscalation to false.",
            )
        if "runAsNonRoot" not in context and "runAsNonRoot" not in pod_context:
            self.emit("POD_NON_ROOT", (*path, "runAsNonRoot"), "Set runAsNonRoot to true here or at Pod level.")
        if "seccompProfile" not in context and "seccompProfile" not in pod_context:
            self.emit("POD_SECCOMP", (*path, "seccompProfile"), "Set a seccomp profile here or at Pod level.")

        capabilities = self.field(context, "capabilities", path, dict)
        if capabilities is None and "capabilities" in context:
            return
        capabilities = capabilities or {}
        path = (*path, "capabilities")
        if "ALL" not in self.strings(capabilities, "drop", path):
            self.emit("POD_CAP_DROP", (*path, "drop"), "Drop ALL Linux capabilities.")
        if self.strings(capabilities, "add", path) - {"NET_BIND_SERVICE"}:
            self.emit("POD_CAP_ADD", (*path, "add"), "Do not add capabilities other than NET_BIND_SERVICE.")

    def role(self, data, kind):
        if kind == "ClusterRole" and self.field(data, "aggregationRule", (), dict) is not None:
            self.emit(
                "RBAC_AGGREGATION", ("aggregationRule",),
                "Review permissions contributed by matching ClusterRoles.",
            )
        rules = self.field(data, "rules", (), list)
        for path, rule in self.mappings(rules, ("rules",)):
            non_resource = "nonResourceURLs" in rule
            groups = self.strings(rule, "apiGroups", path, required=not non_resource)
            resources = self.strings(rule, "resources", path, required=not non_resource)
            verbs = self.strings(rule, "verbs", path, required=True)
            urls = self.strings(rule, "nonResourceURLs", path)
            for key, broad in (
                ("apiGroups", "*" in groups),
                ("resources", any("*" in resource for resource in resources)),
                ("verbs", "*" in verbs),
                ("nonResourceURLs", any("*" in url for url in urls)),
            ):
                if broad:
                    self.emit("RBAC_WILDCARD", (*path, key), "Prefer explicit permissions over wildcards.")
            if groups & {"", "*"} and resources & {"secrets", "*"} and verbs & READ_VERBS:
                self.emit("RBAC_SECRET_READ", (*path, "resources"), "Review whether reading core Secrets is necessary.")

    def binding(self, data, kind):
        if kind == "ClusterRoleBinding":
            self.emit("RBAC_CLUSTER_BINDING", ("kind",), "Review whether cluster-wide binding scope is needed.")
        role_ref = self.field(data, "roleRef", (), dict, required=True)
        if role_ref is not None:
            for key in ("apiGroup", "kind", "name"):
                self.field(role_ref, key, ("roleRef",), str, required=True)
        subjects = self.field(data, "subjects", (), list)
        for path, subject in self.mappings(subjects, ("subjects",)):
            subject_kind = self.field(subject, "kind", path, str, required=True)
            name = self.field(subject, "name", path, str, required=True)
            if subject_kind == "Group" and name is not None and (
                name in {"system:authenticated", "system:unauthenticated", "system:serviceaccounts"}
                or name.startswith("system:serviceaccounts:")
            ):
                self.emit("RBAC_BROAD_SUBJECT", (*path, "name"), "Prefer binding an explicitly intended identity.")

    def network_policy(self, data):
        spec = self.field(data, "spec", (), dict, required=True)
        if spec is None:
            return
        path = ("spec",)
        self.field(spec, "podSelector", path, dict, required=True)
        types = self.strings(spec, "policyTypes", path)
        if types - {"Ingress", "Egress"}:
            self.invalid((*path, "policyTypes"), "Expected Ingress and/or Egress.")
        if "policyTypes" not in spec or spec["policyTypes"] == []:
            self.emit("NET_IMPLICIT_TYPES", (*path, "policyTypes"), "Declare the intended policy directions explicitly.")
        for direction, peer_key in (("Ingress", "from"), ("Egress", "to")):
            key = direction.lower()
            rules = self.field(spec, key, path, list)
            if rules and types and direction not in types:
                self.invalid((*path, key), "Rules are defined for a direction missing from policyTypes.")
            for rule_path, rule in self.mappings(rules, (*path, key)):
                peers = self.field(rule, peer_key, rule_path, list)
                if peer_key not in rule or peers == []:
                    self.emit(
                        "NET_ANY_PEER", (*rule_path, peer_key),
                        "This rule permits any peer on its allowed ports.",
                    )
                for peer_path, peer in self.mappings(peers, (*rule_path, peer_key)):
                    namespaces = self.field(peer, "namespaceSelector", peer_path, dict)
                    self.field(peer, "podSelector", peer_path, dict)
                    self.field(peer, "ipBlock", peer_path, dict)
                    selectors = peer.keys() & {"namespaceSelector", "podSelector", "ipBlock"}
                    if not selectors:
                        self.invalid(peer_path, "Expected at least one peer selector.")
                    elif "ipBlock" in selectors and len(selectors) > 1:
                        self.invalid(peer_path, "ipBlock cannot be combined with Pod or namespace selectors.")
                    elif namespaces == {}:
                        self.emit(
                            "NET_ALL_NAMESPACES", (*peer_path, "namespaceSelector"),
                            "An empty namespaceSelector matches every namespace.",
                        )


def scan(text: str) -> list[Diagnostic]:
    documents, error = load(text)
    if error is not None:
        return [error]
    results = [result for document in documents for result in Review(document).check()]
    return sorted(results, key=lambda r: (r.document, r.line, r.column, r.code, r.path))
