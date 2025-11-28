#!/usr/bin/env python3
"""
RBAC Privilege Chain Analyzer
JIRA: RHOAIENG-38196

Builds relationship graph: ClusterRole → RoleBinding → ServiceAccount → Pod
Identifies privilege escalation paths and overly permissive configurations.
"""

import yaml
import sys
from pathlib import Path
from typing import Dict, List, Set
from collections import defaultdict

class RBACAnalyzer:
    def __init__(self):
        self.cluster_roles = {}
        self.roles = {}
        self.cluster_role_bindings = []
        self.role_bindings = []
        self.service_accounts = {}
        self.pods = {}
        self.findings = []

    def load_yaml_files(self, base_path: str):
        """Load all YAML manifests from the repository."""
        for yaml_file in Path(base_path).rglob("*.yaml"):
            if any(x in str(yaml_file) for x in ['.git', 'vendor', 'node_modules']):
                continue

            try:
                with open(yaml_file) as f:
                    docs = yaml.safe_load_all(f)
                    for doc in docs:
                        if not doc or 'kind' not in doc:
                            continue
                        self._categorize_resource(doc, str(yaml_file))
            except Exception as e:
                print(f"Warning: Failed to parse {yaml_file}: {e}", file=sys.stderr)

    def _categorize_resource(self, doc: dict, file_path: str):
        """Categorize Kubernetes resource by kind."""
        kind = doc.get('kind')
        metadata = doc.get('metadata', {})
        name = metadata.get('name', 'unknown')

        if kind == 'ClusterRole':
            self.cluster_roles[name] = {'rules': doc.get('rules', []), 'file': file_path, 'doc': doc}
        elif kind == 'Role':
            namespace = metadata.get('namespace', 'default')
            self.roles[f"{namespace}/{name}"] = {'rules': doc.get('rules', []), 'file': file_path}
        elif kind == 'ClusterRoleBinding':
            self.cluster_role_bindings.append({'doc': doc, 'file': file_path})
        elif kind == 'RoleBinding':
            self.role_bindings.append({'doc': doc, 'file': file_path})
        elif kind == 'ServiceAccount':
            namespace = metadata.get('namespace', 'default')
            self.service_accounts[f"{namespace}/{name}"] = {'file': file_path, 'doc': doc}
        elif kind == 'Pod':
            namespace = metadata.get('namespace', 'default')
            sa_name = doc.get('spec', {}).get('serviceAccountName', 'default')
            self.pods[f"{namespace}/{name}"] = {
                'serviceAccount': sa_name,
                'file': file_path,
                'automountToken': doc.get('spec', {}).get('automountServiceAccountToken', True)
            }

    def analyze_privilege_chains(self):
        """Build ClusterRole → Binding → SA → Pod chains."""
        print("\n=== RBAC Privilege Chain Analysis ===\n")

        # Track which ServiceAccounts have which permissions
        sa_permissions = defaultdict(list)

        # Analyze ClusterRoleBindings
        for binding in self.cluster_role_bindings:
            doc = binding['doc']
            role_ref = doc.get('roleRef', {})
            role_name = role_ref.get('name')
            subjects = doc.get('subjects', [])

            for subject in subjects:
                if subject.get('kind') == 'ServiceAccount':
                    sa_namespace = subject.get('namespace', 'default')
                    sa_name = subject.get('name')
                    sa_key = f"{sa_namespace}/{sa_name}"

                    sa_permissions[sa_key].append({
                        'type': 'ClusterRole',
                        'role': role_name,
                        'binding': doc['metadata']['name'],
                        'file': binding['file']
                    })

        # Analyze RoleBindings
        for binding in self.role_bindings:
            doc = binding['doc']
            role_ref = doc.get('roleRef', {})
            role_kind = role_ref.get('kind')  # Could be ClusterRole!
            role_name = role_ref.get('name')
            subjects = doc.get('subjects', [])

            for subject in subjects:
                if subject.get('kind') == 'ServiceAccount':
                    sa_namespace = subject.get('namespace', doc['metadata'].get('namespace', 'default'))
                    sa_name = subject.get('name')
                    sa_key = f"{sa_namespace}/{sa_name}"

                    sa_permissions[sa_key].append({
                        'type': role_kind,  # Role or ClusterRole
                        'role': role_name,
                        'binding': doc['metadata']['name'],
                        'file': binding['file']
                    })

        # Map ServiceAccounts to Pods
        print("### Service Account → Pod Mapping\n")
        for pod_key, pod_info in self.pods.items():
            namespace = pod_key.split('/')[0]
            sa_name = pod_info['serviceAccount']
            sa_key = f"{namespace}/{sa_name}"

            if sa_key in sa_permissions:
                print(f"**Pod**: `{pod_key}`")
                print(f"  - **ServiceAccount**: `{sa_key}`")
                print(f"  - **Permissions**:")
                for perm in sa_permissions[sa_key]:
                    role_type = perm['type']
                    role_name = perm['role']
                    print(f"    - {role_type}: `{role_name}` (via {perm['binding']})")

                    # Check if this is a high-privilege role
                    if role_name == 'cluster-admin':
                        self._add_finding(
                            severity='CRITICAL',
                            title=f"Pod {pod_key} has cluster-admin access",
                            description=f"Pod uses ServiceAccount {sa_key} bound to cluster-admin",
                            file=pod_info['file'],
                            remediation="Create a custom Role with minimal required permissions"
                        )

                    # Check if RoleBinding references ClusterRole
                    if role_type == 'ClusterRole' and any(b['doc']['metadata']['name'] == perm['binding']
                                                          for b in self.role_bindings):
                        self._add_finding(
                            severity='WARNING',
                            title=f"RoleBinding {perm['binding']} grants cluster-wide permissions",
                            description=f"RoleBinding references ClusterRole {role_name}, granting cluster-scoped permissions in namespace scope",
                            file=perm['file'],
                            remediation="Use a namespace-scoped Role instead of ClusterRole"
                        )
                print()

    def analyze_dangerous_permissions(self):
        """Identify high-risk permissions in ClusterRoles."""
        print("\n=== Dangerous Permission Analysis ===\n")

        dangerous_verbs = {'escalate', 'impersonate', 'bind', '*'}
        dangerous_resources = {'*', 'persistentvolumes', 'nodes', 'clusterroles'}

        for role_name, role_data in self.cluster_roles.items():
            rules = role_data['rules']
            findings_for_role = []

            for rule in rules:
                resources = rule.get('resources', [])
                verbs = rule.get('verbs', [])

                # Check for wildcards
                if '*' in resources:
                    findings_for_role.append("Wildcard resources (*)")
                if '*' in verbs:
                    findings_for_role.append("Wildcard verbs (*)")

                # Check dangerous verbs
                dangerous = set(verbs) & dangerous_verbs
                if dangerous:
                    findings_for_role.append(f"Dangerous verbs: {', '.join(dangerous)}")

                # Check dangerous resources
                dangerous_res = set(resources) & dangerous_resources
                if dangerous_res:
                    findings_for_role.append(f"Dangerous resources: {', '.join(dangerous_res)}")

            if findings_for_role:
                print(f"**ClusterRole**: `{role_name}` ({role_data['file']})")
                for finding in findings_for_role:
                    print(f"  - ⚠️  {finding}")
                print()

                self._add_finding(
                    severity='HIGH',
                    title=f"ClusterRole {role_name} has dangerous permissions",
                    description="; ".join(findings_for_role),
                    file=role_data['file'],
                    remediation="Apply principle of least privilege - specify exact resources and verbs needed"
                )

    def check_aggregated_roles(self):
        """Check for aggregated ClusterRoles."""
        print("\n=== Aggregated ClusterRole Analysis ===\n")

        for role_name, role_data in self.cluster_roles.items():
            doc = role_data['doc']
            if 'aggregationRule' in doc:
                selectors = doc['aggregationRule'].get('clusterRoleSelectors', [])
                print(f"**ClusterRole**: `{role_name}`")
                print(f"  - Aggregates roles matching: `{selectors}`")
                print(f"  - File: {role_data['file']}\n")

                self._add_finding(
                    severity='INFO',
                    title=f"Aggregated ClusterRole detected: {role_name}",
                    description=f"Aggregates permissions from roles matching {selectors}",
                    file=role_data['file'],
                    remediation="Review aggregation selectors to ensure no unintended permissions are granted"
                )

    def _add_finding(self, severity: str, title: str, description: str, file: str, remediation: str):
        """Add a security finding."""
        self.findings.append({
            'severity': severity,
            'title': title,
            'description': description,
            'file': file,
            'remediation': remediation
        })

    def generate_report(self):
        """Generate final security report."""
        print("\n" + "="*80)
        print("RBAC SECURITY FINDINGS SUMMARY")
        print("="*80 + "\n")

        by_severity = defaultdict(list)
        for finding in self.findings:
            by_severity[finding['severity']].append(finding)

        for severity in ['CRITICAL', 'HIGH', 'WARNING', 'INFO']:
            findings = by_severity[severity]
            if findings:
                print(f"\n### {severity} ({len(findings)} findings)\n")
                for i, finding in enumerate(findings, 1):
                    print(f"{i}. **{finding['title']}**")
                    print(f"   - File: `{finding['file']}`")
                    print(f"   - Issue: {finding['description']}")
                    print(f"   - Fix: {finding['remediation']}\n")

        total = len(self.findings)
        print(f"\n**Total Findings**: {total}")

        # Exit code for CI
        critical_count = len(by_severity['CRITICAL'])
        if critical_count > 0:
            print(f"\n❌ {critical_count} CRITICAL issues found - review required")
            return 1
        else:
            print("\n✅ No critical RBAC issues detected")
            return 0

def main():
    if len(sys.argv) < 2:
        print("Usage: rbac-analyzer.py <path-to-repo>")
        sys.exit(1)

    repo_path = sys.argv[1]
    analyzer = RBACAnalyzer()

    print(f"Scanning repository: {repo_path}")
    analyzer.load_yaml_files(repo_path)

    print(f"\nLoaded Resources:")
    print(f"  - ClusterRoles: {len(analyzer.cluster_roles)}")
    print(f"  - Roles: {len(analyzer.roles)}")
    print(f"  - ClusterRoleBindings: {len(analyzer.cluster_role_bindings)}")
    print(f"  - RoleBindings: {len(analyzer.role_bindings)}")
    print(f"  - ServiceAccounts: {len(analyzer.service_accounts)}")
    print(f"  - Pods: {len(analyzer.pods)}")

    analyzer.analyze_dangerous_permissions()
    analyzer.check_aggregated_roles()
    analyzer.analyze_privilege_chains()

    exit_code = analyzer.generate_report()
    sys.exit(exit_code)

if __name__ == '__main__':
    main()
