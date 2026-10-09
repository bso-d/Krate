#!/usr/bin/env python3
"""Validate effective Compose defaults without Docker daemon access or PyYAML."""
import json
import re
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
POLICIES = {
    "zk": {"kafka-ui": {"GITHUB_RELEASE_INFO_ENABLED": "false"}},
    "kraft": {"kafka-ui": {"GITHUB_RELEASE_INFO_ENABLED": "false"}},
    "epc": {"kafka-ui": {"GITHUB_RELEASE_INFO_ENABLED": "false"}},
    "monitoring": {
        "grafana": {
            "GF_ANALYTICS_REPORTING_ENABLED": "false",
            "GF_ANALYTICS_CHECK_FOR_UPDATES": "false",
            "GF_ANALYTICS_CHECK_FOR_PLUGIN_UPDATES": "false",
            "GF_PLUGINS_PREINSTALL_DISABLED": "true",
            "GF_PLUGINS_PUBLIC_KEY_RETRIEVAL_DISABLED": "true",
            "GF_PLUGINS_PLUGIN_ADMIN_ENABLED": "false",
            "GF_SECURITY_DISABLE_GRAVATAR": "true",
            "GF_SNAPSHOTS_EXTERNAL_ENABLED": "false",
        }
    },
}


def violations(variant, config):
    errors = []
    for service, policy in POLICIES[variant].items():
        env = config.get("services", {}).get(service, {}).get("environment", {})
        for key, expected in policy.items():
            actual = env.get(key)
            if actual != expected:
                errors.append(f"{variant}/{service}: {key} must be {expected}; got {actual!r}")
    return errors


INTERNAL_DATASOURCE = re.compile(r"http://(prometheus:9090|victorialogs:9428)")


def perses_violations():
    """Perses must load only its baked plugins and query only internal services."""
    errors = []
    render = (ROOT / "monitoring/render.py").read_text()
    if "'  enable_dev: false'," not in render:
        errors.append("monitoring/render.py: Perses plugin.enable_dev must be false")
    names = set()
    for path in sorted((ROOT / "monitoring/perses/provisioning").glob("*.json")):
        for resource in json.loads(path.read_text()):
            if resource.get("kind") not in ("Datasource", "GlobalDatasource"):
                continue
            names.add((resource["spec"]["plugin"]["kind"], resource["metadata"]["name"]))
            plugin = resource["spec"]["plugin"]["spec"]
            proxy = plugin.get("proxy", {}).get("spec", {})
            if "directUrl" in plugin or not INTERNAL_DATASOURCE.fullmatch(proxy.get("url", "")):
                errors.append(f"{path.name}: datasource {resource['metadata']['name']} must proxy to an internal service without directUrl")
    for path in sorted((ROOT / "monitoring/perses/dashboards").glob("*.json")):
        def walk(node):
            if isinstance(node, dict):
                if "datasource" in node and isinstance(node["datasource"], dict):
                    ref = (node["datasource"].get("kind"), node["datasource"].get("name"))
                    if ref not in names:
                        errors.append(f"{path.name}: datasource {ref} is not a provisioned internal datasource")
                if "directUrl" in node:
                    errors.append(f"{path.name}: dashboards must not set directUrl")
                for value in node.values():
                    walk(value)
            elif isinstance(node, list):
                for value in node:
                    walk(value)
        walk(json.loads(path.read_text()))
    return errors


def main():
    errors = perses_violations()
    for variant in POLICIES:
        result = subprocess.run(
            ["docker", "compose", "--env-file", str(ROOT / variant / ".env.template"),
             "-f", str(ROOT / variant / "docker-compose.yml"), "config", "--format", "json"],
            cwd=ROOT, text=True, capture_output=True,
        )
        if result.returncode:
            # Do not dump rendered configuration, which could contain secrets.
            errors.append(f"{variant}: Compose rendering failed; run make compose-check")
            continue
        errors.extend(violations(variant, json.loads(result.stdout)))
    if errors:
        print("Offline policy check failed:\n" + "\n".join(errors), file=sys.stderr)
        return 1
    print("Offline defaults verified: all Kafbat variants, shared Grafana and Perses.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
