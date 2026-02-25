import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

from k8s_sec_labs.__main__ import scan_file
from k8s_sec_labs.checks import scan
from k8s_sec_labs.source import MAX_BYTES, MAX_DEPTH, MAX_DOCUMENTS

ROOT = Path(__file__).resolve().parents[1]
RISKY = ROOT / "tests/fixtures/risky.txt"
REFERENCE = ROOT / "examples/restricted.yaml"
POD = "apiVersion: v1\nkind: Pod\n"


def codes(text):
    return [item.code for item in scan(text)]


class SourceTests(unittest.TestCase):
    def test_fixture_is_inert_and_reviewed_only_as_extracted_text(self):
        raw = RISKY.read_text(encoding="utf-8")
        self.assertEqual(codes(raw), ["INPUT_SHAPE"])
        findings = scan(yaml.safe_load(raw))
        self.assertEqual(
            [(r.document, r.line, r.column, r.code, r.path) for r in findings],
            [
                (1, 12, 9, "POD_PRIVILEGED", ("spec", "containers", 0, "securityContext", "privileged")),
                (2, 22, 5, "RBAC_SECRET_READ", ("rules", 0, "resources")),
                (2, 22, 5, "RBAC_WILDCARD", ("rules", 0, "resources")),
                (3, 31, 7, "NET_ANY_PEER", ("spec", "ingress", 0, "from")),
            ],
        )

    def test_empty_documents_count_toward_document_index(self):
        results = scan("---\n# empty\n---\n" + POD + "spec: {}\n---\n")
        self.assertEqual(len(results), 1)
        result = results[0]
        self.assertEqual((result.document, result.line, result.column), (2, 6, 1))
        self.assertEqual(result.path, ("spec", "containers"))

    def test_invalid_second_document_discards_findings_from_first(self):
        result, = scan(POD + "spec: {}\n---\nkey: value\nkey: duplicate\n")
        self.assertEqual((result.code, result.document, result.line, result.column), ("INPUT_YAML", 2, 6, 1))
        self.assertIn("Duplicate", result.message)

    def test_rejected_yaml_constructs(self):
        for text in ("a: *missing", "a: &a [*a]", "a: !!str b", "<<: {}", "{1: b}", "x: .inf", "x: ["):
            with self.subTest(text=text):
                self.assertEqual(codes(text), ["INPUT_YAML"])

    def test_empty_and_non_mapping_documents(self):
        for text in ("", "# comment\n", "---\n..."):
            with self.subTest(text=text):
                self.assertEqual(codes(text), ["INPUT_EMPTY"])
        for text in ("null", "[]", "false", "''"):
            with self.subTest(text=text):
                self.assertEqual(codes(text), ["INPUT_SHAPE"])

    def test_document_and_depth_limits(self):
        self.assertEqual(codes("---\n" * MAX_DOCUMENTS), ["INPUT_EMPTY"])
        result, = scan("---\n" * (MAX_DOCUMENTS + 1))
        self.assertEqual((result.code, result.document), ("INPUT_YAML", MAX_DOCUMENTS + 1))
        self.assertEqual(codes("[" * MAX_DEPTH + "]" * MAX_DEPTH), ["INPUT_SHAPE"])
        self.assertEqual(codes("[" * (MAX_DEPTH + 1) + "]" * (MAX_DEPTH + 1)), ["INPUT_YAML"])

    def test_unsupported_version_kind_and_windows_do_not_pass_silently(self):
        text = (
            "apiVersion: v1\nkind: List\nitems: []\n---\n"
            "apiVersion: hypothetical.example/v1\nkind: Pod\n---\n"
            + POD + "spec: {os: {name: windows}}\n"
        )
        results = scan(text)
        self.assertEqual([r.code for r in results], ["UNSUPPORTED_GVK", "UNSUPPORTED_GVK", "UNSUPPORTED_OS"])
        self.assertTrue(all(r.error for r in results))


class WorkloadTests(unittest.TestCase):
    def test_all_supported_pod_template_paths(self):
        spec = {"hostPID": True, "containers": []}
        template = {"template": {"spec": spec}}
        cases = (
            ("v1", "Pod", spec, ("spec",)),
            *(("apps/v1", kind, template, ("spec", "template", "spec"))
              for kind in ("Deployment", "StatefulSet", "ReplicaSet", "DaemonSet")),
            ("batch/v1", "Job", template, ("spec", "template", "spec")),
            ("batch/v1", "CronJob", {"jobTemplate": {"spec": template}},
             ("spec", "jobTemplate", "spec", "template", "spec")),
        )
        for version, kind, body, path in cases:
            with self.subTest(kind=kind):
                results = scan(json.dumps({"apiVersion": version, "kind": kind, "spec": body}))
                self.assertEqual([(r.code, r.path) for r in results], [
                    ("POD_HOST_NAMESPACE", (*path, "hostPID")),
                    ("INPUT_SHAPE", (*path, "containers")),
                ])

    def test_all_container_types_and_pod_defaults(self):
        results = scan(POD + """spec:
  securityContext:
    runAsNonRoot: true
    seccompProfile: {type: RuntimeDefault}
  containers:
    - securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}}
  initContainers:
    - securityContext: {runAsUser: 0, allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}}
  ephemeralContainers:
    - securityContext: {runAsNonRoot: false, allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}}
""")
        self.assertEqual([(r.code, r.path[1]) for r in results], [
            ("POD_ROOT_UID", "initContainers"), ("POD_NON_ROOT", "ephemeralContainers"),
        ])

    def test_missing_controls_share_nearest_ancestor_and_sort_by_code(self):
        results = scan(POD + "spec: {containers: [{name: demo}]}\n")
        self.assertEqual([(r.code, r.line, r.column) for r in results], [
            ("POD_CAP_DROP", 3, 21), ("POD_ESCALATION", 3, 21),
            ("POD_NON_ROOT", 3, 21), ("POD_SECCOMP", 3, 21),
        ])

    def test_host_controls_and_invalid_override(self):
        text = POD + """spec:
  hostIPC: yes
  hostNetwork: false
  volumes: [{name: fixture, hostPath: {}}]
  securityContext: {seccompProfile: {type: RuntimeDefault}, runAsNonRoot: true}
  containers:
    - ports: [{hostPort: 0}, {hostPort: 8080}]
      securityContext:
        seccompProfile: {type: Unconfined}
        allowPrivilegeEscalation: true
        capabilities: {drop: [ALL], add: [NET_BIND_SERVICE, CHOWN]}
"""
        self.assertEqual(codes(text), [
            "POD_HOST_NAMESPACE", "POD_HOST_PATH", "POD_HOST_PORT", "POD_SECCOMP", "POD_ESCALATION", "POD_CAP_ADD",
        ])

    def test_wrong_types_in_scanned_fields_are_errors(self):
        text = POD + """spec:
  hostIPC: 'true'
  securityContext: {runAsUser: false, runAsNonRoot: true, seccompProfile: {type: Localhost}}
  containers: [null, {securityContext: []}]
"""
        results = scan(text)
        self.assertEqual([r.path[-1] for r in results], [
            "hostIPC", "runAsUser", "localhostProfile", 0, "securityContext",
        ])
        self.assertTrue(all(r.code == "INPUT_SHAPE" and r.error for r in results))

    def test_restricted_volume_sources(self):
        results = scan(POD + """spec:
  volumes:
    - name: scratch
      emptyDir: {}
    - name: settings
      configMap: {name: fixture}
    - name: inputs
      projected: {sources: [{downwardAPI: {items: []}}]}
    - name: data
      persistentVolumeClaim: {claimName: fixture}
    - name: legacy
      nfs: {server: storage.example, path: /fixture}
    - name: local
      hostPath: {path: /fixture}
    - name: block
      iscsi: {targetPortal: '192.0.2.1:3260', iqn: iqn.2000-01.example:fixture, lun: 0}
  securityContext: {runAsNonRoot: true, seccompProfile: {type: RuntimeDefault}}
  containers:
    - securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}}
""")
        self.assertEqual([(r.code, r.path, r.line, r.column, r.error) for r in results], [
            ("POD_VOLUME_SOURCE", ("spec", "volumes", 4, "nfs"), 14, 7, False),
            ("POD_HOST_PATH", ("spec", "volumes", 5, "hostPath"), 16, 7, False),
            ("POD_VOLUME_SOURCE", ("spec", "volumes", 6, "iscsi"), 18, 7, False),
        ])

    def test_per_container_security_settings_can_replace_absent_pod_settings(self):
        text = POD + """spec:
  containers:
    - securityContext:
        runAsNonRoot: true
        seccompProfile: {type: Localhost, localhostProfile: profiles/example.json}
        allowPrivilegeEscalation: false
        capabilities: {drop: [ALL], add: [NET_BIND_SERVICE]}
"""
        self.assertEqual(codes(text), [])


class PolicyTests(unittest.TestCase):
    def test_rbac_respects_api_group_and_flags_wildcard_and_aggregation(self):
        text = """apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
aggregationRule: {clusterRoleSelectors: []}
rules:
  - {apiGroups: [synthetic.example], resources: [secrets], verbs: [get]}
  - {apiGroups: [''], resources: [secrets], verbs: [create]}
  - {apiGroups: ['*'], resources: [secrets], verbs: [watch]}
  - {nonResourceURLs: ['/healthz/*'], verbs: [get]}
"""
        self.assertEqual([r.path for r in scan(text)], [
            ("aggregationRule",), ("rules", 2, "apiGroups"), ("rules", 2, "resources"),
            ("rules", 3, "nonResourceURLs"),
        ])

    def test_rbac_broad_group_differs_from_named_identity(self):
        text = """apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: reader}
subjects:
  - {kind: User, name: 'system:authenticated'}
  - {kind: Group, name: 'system:serviceaccounts:inventory'}
"""
        results = scan(text)
        self.assertEqual([r.code for r in results], ["RBAC_CLUSTER_BINDING", "RBAC_BROAD_SUBJECT"])
        self.assertEqual(results[1].path, ("subjects", 1, "name"))

    def test_network_policy_deny_all_is_distinct_from_empty_rule(self):
        base = "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy\nspec:\n  podSelector: {}\n"
        self.assertEqual(codes(base + "  policyTypes: [Ingress, Egress]\n  ingress: []\n"), [])
        self.assertEqual(codes(base + "  ingress: [{}]\n  egress: [{to: []}]\n"), [
            "NET_IMPLICIT_TYPES", "NET_ANY_PEER", "NET_ANY_PORT", "NET_ANY_PORT", "NET_ANY_PEER",
        ])
        self.assertEqual(codes(base + "  policyTypes: [Egress]\n  ingress: [{from: [false], ports: [{port: 80}]}]\n"), [
            "INPUT_SHAPE", "INPUT_SHAPE",
        ])

    def test_network_policy_unrestricted_ports_are_independent_of_peer_scope(self):
        results = scan("""apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
  ingress:
    - from: [{podSelector: {matchLabels: {app: fixture}}}]
    - from: [{podSelector: {}}]
      ports: []
  egress:
    - to: [{ipBlock: {cidr: 192.0.2.1/32}}]
      ports:
        - {port: 53, protocol: UDP}
        - {protocol: TCP}
        - {port: null, protocol: UDP}
        - {endPort: 9000}
        - {port: 8000, endPort: 9000}
        - {port: metrics}
        - false
""")
        ingress = ("spec", "ingress")
        egress_ports = ("spec", "egress", 0, "ports")
        self.assertEqual([(r.code, r.path, r.error) for r in results], [
            ("NET_ANY_PORT", (*ingress, 0, "ports"), False),
            ("NET_ANY_PORT", (*ingress, 1, "ports"), False),
            ("NET_ANY_PORT", (*egress_ports, 1, "port"), False),
            ("NET_ANY_PORT", (*egress_ports, 2, "port"), False),
            ("INPUT_SHAPE", (*egress_ports, 3, "endPort"), True),
            ("INPUT_SHAPE", (*egress_ports, 6), True),
        ])

    def test_empty_namespace_selector_broadens_pod_selector(self):
        text = """apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
spec:
  podSelector: {}
  policyTypes: [Ingress]
  ingress:
    - from:
        - podSelector: {}
        - namespaceSelector: {}
          podSelector: {matchLabels: {app: allowed}}
        - ipBlock: {cidr: 192.0.2.0/24}
          podSelector: {}
      ports: [{port: 8080}]
"""
        results = scan(text)
        self.assertEqual([r.code for r in results], ["NET_ALL_NAMESPACES", "INPUT_SHAPE"])
        self.assertEqual(results[0].path, ("spec", "ingress", 0, "from", 1, "namespaceSelector"))


class CLITests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, "-m", "k8s_sec_labs", *map(str, args)],
            cwd=ROOT, text=True, capture_output=True, check=False, timeout=10,
        )

    def test_reference_is_clean(self):
        run = self.run_cli(REFERENCE)
        self.assertEqual((run.returncode, run.stdout, run.stderr), (0, "", ""))

    def test_exit_statuses_order_and_output(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            path = Path(directory) / "review with spaces.yaml"
            path.write_text(yaml.safe_load(RISKY.read_text(encoding="utf-8")), encoding="utf-8")
            findings = self.run_cli(path)
            self.assertEqual(findings.returncode, 1)
            self.assertEqual(findings.stderr, "")
            self.assertEqual(len(findings.stdout.splitlines()), 4)
            self.assertEqual(findings.stdout.splitlines()[0], (
                f"{path}:12:9: finding POD_PRIVILEGED [doc 1 $.spec.containers[0].securityContext.privileged]"
                " Do not run privileged containers."
            ))
            missing = Path(directory) / "absent.yaml"
            mixed = self.run_cli(missing, path)
            self.assertEqual(mixed.returncode, 2)
            error, other = mixed.stdout.split("\n", 1)
            self.assertIn("error INPUT_FILE", error)
            self.assertEqual(other, findings.stdout)

    def test_file_size_encoding_and_nonregular_inputs(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            path = Path(directory) / "input.yaml"
            path.write_bytes(b"#" + b" " * (MAX_BYTES - 1))
            self.assertEqual(scan_file(path)[0].code, "INPUT_EMPTY")
            with path.open("ab") as stream:
                stream.write(b" ")
            self.assertEqual(scan_file(path)[0].code, "INPUT_SIZE")
            path.write_bytes(b"\xff")
            self.assertEqual(scan_file(path)[0].code, "INPUT_ENCODING")
            path.write_bytes(b"\xef\xbb\xbf" + REFERENCE.read_bytes())
            self.assertEqual(scan_file(path), [])
            self.assertEqual(scan_file(Path(directory))[0].code, "INPUT_FILE")
            if hasattr(os, "mkfifo"):
                fifo = Path(directory) / "pipe"
                os.mkfifo(fifo)
                self.assertEqual(self.run_cli(fifo).returncode, 2)

    def test_json_reports_ordered_findings_and_errors_with_locations(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            path = (Path(directory) / "review with spaces.yaml").relative_to(ROOT)
            (ROOT / path).write_text(yaml.safe_load(RISKY.read_text(encoding="utf-8")), encoding="utf-8")
            missing = path.with_name("absent.yaml")
            findings = self.run_cli("--format", "json", path)
            mixed = self.run_cli("--format", "json", missing, path)
        self.assertEqual((findings.returncode, findings.stderr), (1, ""))
        self.assertEqual((mixed.returncode, mixed.stderr), (2, ""))
        records = json.loads(findings.stdout)
        self.assertEqual([r["code"] for r in records], [
            "POD_PRIVILEGED", "RBAC_SECRET_READ", "RBAC_WILDCARD", "NET_ANY_PEER",
        ])
        self.assertEqual(records[0], {
            "file": str(path), "document": 1, "line": 12, "column": 9,
            "path": ["spec", "containers", 0, "securityContext", "privileged"],
            "level": "finding", "code": "POD_PRIVILEGED", "message": "Do not run privileged containers.",
        })
        self.assertEqual((records[-1]["document"], records[-1]["line"], records[-1]["column"], records[-1]["path"]),
                         (3, 31, 7, ["spec", "ingress", 0, "from"]))
        self.assertEqual(json.loads(mixed.stdout), [{
            "file": str(missing), "document": 1, "line": 1, "column": 1, "path": [],
            "level": "error", "code": "INPUT_FILE", "message": "Expected a readable regular file.",
        }, *records])

    def test_json_clean_scan_and_argument_errors(self):
        clean = self.run_cli("--format", "json", REFERENCE)
        self.assertEqual((clean.returncode, clean.stdout, clean.stderr), (0, "[]\n", ""))
        invalid = self.run_cli("--format", "json")
        self.assertEqual((invalid.returncode, invalid.stdout), (2, ""))
        self.assertIn("usage:", invalid.stderr)

    def test_help_and_missing_arguments(self):
        self.assertEqual(self.run_cli("--help").returncode, 0)
        run = self.run_cli()
        self.assertEqual(run.returncode, 2)
        self.assertIn("usage:", run.stderr)
